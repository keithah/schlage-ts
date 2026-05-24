import { describe, expect, it, vi } from 'vitest';
import {
  SchlageAuthManager,
  assertValidSessionMaterial,
  createPublicSchlageAuthSnapshot,
  validateSchlageCredentials,
  type SchlageAuthTransport,
  type SchlageAuthTransportResult,
} from '../src/auth.js';
import {
  SchlageError,
  toPublicSchlageError,
  wrapUnknownSchlageError,
} from '../src/errors.js';
import {
  SchlageError as PublicSchlageError,
  createPublicSchlageAuthSnapshot as publicSnapshotFromIndex,
} from '../src/index.js';

const credentials = {
  username: 'operator@example.test',
  password: 'passphrase',
};

function session(
  overrides: Partial<SchlageAuthTransportResult> = {},
): SchlageAuthTransportResult {
  return {
    accessToken: 'mock-access-token-value-00000000000000000000',
    refreshToken: 'mock-refresh-token-value-00000000000000000000',
    expiresAt: new Date('2999-01-01T00:00:00.000Z'),
    ...overrides,
  };
}

describe('auth and error contracts', () => {
  it('validates credentials without exposing password values', () => {
    expect(
      validateSchlageCredentials({
        username: ' operator@example.test ',
        password: ' passphrase ',
      }),
    ).toEqual({
      username: 'operator@example.test',
      password: 'passphrase',
    });

    for (const invalidCredentials of [
      { username: '', password: 'passphrase' },
      { username: 'operator@example.test', password: '' },
      { username: '   ', password: '   ' },
    ]) {
      expect(() => validateSchlageCredentials(invalidCredentials)).toThrow(
        SchlageError,
      );
      try {
        validateSchlageCredentials(invalidCredentials);
      } catch (error) {
        expect(toPublicSchlageError(error)).toEqual({
          name: 'SchlageError',
          code: 'SCHLAGE_CONFIG_MISSING_CREDENTIALS',
          message: 'Schlage username and password are required.',
          retryable: false,
        });
      }
    }
  });

  it('creates redacted public auth snapshots from token-bearing session material', () => {
    const snapshot = createPublicSchlageAuthSnapshot({
      username: 'operator@example.test',
      session: {
        accessToken: 'access.token.value-that-must-not-leak',
        refreshToken: 'refresh.token.value-that-must-not-leak',
        accountId: 'account-12345',
        expiresAt: '2999-01-01T00:00:00.000Z',
        refreshedAt: '2025-01-01T00:00:00.000Z',
      },
    });

    expect(snapshot).toEqual({
      phase: 'authenticated',
      username: '[REDACTED_USERNAME]',
      authenticated: true,
      session: {
        hasSession: true,
        status: 'active',
        expiresAt: '2999-01-01T00:00:00.000Z',
        refreshedAt: '2025-01-01T00:00:00.000Z',
      },
    });

    const rendered = JSON.stringify(snapshot);
    expect(rendered).not.toContain('operator@example.test');
    expect(rendered).not.toContain('access.token.value-that-must-not-leak');
    expect(rendered).not.toContain('refresh.token.value-that-must-not-leak');
    expect(rendered).not.toContain('account-12345');
  });

  it('marks malformed session-like data as a protocol error at the internal seam', async () => {
    const transport: SchlageAuthTransport = {
      async signIn() {
        return session();
      },
      async refresh(activeSession) {
        return activeSession;
      },
    };

    const activeSession = await transport.signIn({
      username: 'operator@example.test',
      password: 'password',
    });
    assertValidSessionMaterial(activeSession);
    await expect(transport.refresh(activeSession)).resolves.toEqual(
      activeSession,
    );

    expect(() =>
      assertValidSessionMaterial({
        accessToken: 'token-shaped-value-without-expiry-00000000000000000000',
      }),
    ).toThrow(SchlageError);

    try {
      assertValidSessionMaterial({
        accessToken: 'token-shaped-value-without-expiry-00000000000000000000',
      });
    } catch (error) {
      const publicError = toPublicSchlageError(error);
      expect(publicError.code).toBe('SCHLAGE_AUTH_PROTOCOL');
      expect(publicError.message).toBe(
        'Schlage auth response did not include a usable session.',
      );
      expect(JSON.stringify(publicError)).not.toContain('token-shaped-value');
    }
  });

  it('wraps unknown causes without leaking unsafe payloads through public errors', () => {
    const wrapped = wrapUnknownSchlageError(
      new Error(
        'password=hunter2 token=mock-token-value-00000000000000000000 operator@example.test',
      ),
      'Auth failed for operator@example.test with token=mock-token-value-00000000000000000000',
    );

    expect(wrapped).toBeInstanceOf(SchlageError);
    expect(wrapped.message).not.toContain('operator@example.test');
    expect(wrapped.message).not.toContain('mock-token-value');
    expect(wrapped.message).toContain('[REDACTED]');

    const publicError = toPublicSchlageError(
      new Error(
        'password=hunter2 token=mock-token-value-00000000000000000000 operator@example.test',
      ),
    );
    expect(publicError).toEqual({
      name: 'SchlageError',
      code: 'SCHLAGE_UNKNOWN_ERROR',
      message:
        'Schlage operation failed. See the error code for a safe diagnostic category.',
      retryable: false,
    });
  });

  it('exports only safe public contracts from the package entrypoint', () => {
    expect(
      publicSnapshotFromIndex({ username: 'operator@example.test' }),
    ).toMatchObject({
      username: '[REDACTED_USERNAME]',
      authenticated: false,
      session: { hasSession: false, status: 'none' },
    });
    expect(
      new PublicSchlageError({
        code: 'SCHLAGE_AUTH_FAILED',
        message: 'token=unsafe-value',
      }).message,
    ).toBe('token=[REDACTED]');
  });
});

describe('SchlageAuthManager', () => {
  it('authenticates once on first use and exposes only a redacted active session snapshot', async () => {
    const calls: string[] = [];
    const transport: SchlageAuthTransport = {
      signIn: vi.fn(async () => {
        calls.push('signIn');
        return session({ accountId: 'account-12345' });
      }),
      refresh: vi.fn(async () => {
        calls.push('refresh');
        return session({ refreshedAt: new Date('2999-01-01T00:00:00.000Z') });
      }),
    };

    const manager = new SchlageAuthManager({ credentials, transport });
    const snapshot = await manager.ensureSession();

    expect(calls).toEqual(['signIn']);
    expect(transport.signIn).toHaveBeenCalledExactlyOnceWith(credentials);
    expect(transport.refresh).not.toHaveBeenCalled();
    expect(snapshot).toMatchObject({
      phase: 'authenticated',
      username: '[REDACTED_USERNAME]',
      authenticated: true,
      session: { hasSession: true, status: 'active' },
    });
    expect(JSON.stringify(snapshot)).not.toContain(credentials.username);
    expect(JSON.stringify(snapshot)).not.toContain('mock-access-token-value');
    expect(JSON.stringify(snapshot)).not.toContain('mock-refresh-token-value');
    expect(JSON.stringify(snapshot)).not.toContain('account-12345');
  });

  it('reuses an unexpired in-memory session without repeated authenticate or refresh calls', async () => {
    const transport: SchlageAuthTransport = {
      signIn: vi.fn(async () => session()),
      refresh: vi.fn(async () =>
        session({ refreshedAt: new Date('2999-01-01T00:00:00.000Z') }),
      ),
    };
    const manager = new SchlageAuthManager({ credentials, transport });

    await manager.ensureSession();
    await manager.ensureSession();

    expect(transport.signIn).toHaveBeenCalledTimes(1);
    expect(transport.refresh).not.toHaveBeenCalled();
  });

  it('refreshes an expired in-memory session without re-authenticating', async () => {
    let now = new Date('2025-01-01T00:00:00.000Z');
    const calls: string[] = [];
    const transport: SchlageAuthTransport = {
      signIn: vi.fn(async () => {
        calls.push('signIn');
        return session({ expiresAt: new Date('2025-01-01T00:00:01.000Z') });
      }),
      refresh: vi.fn(async (activeSession) => {
        calls.push(`refresh:${activeSession.refreshToken}`);
        return session({
          accessToken: 'mock-refreshed-access-token-value-00000000000000000000',
          refreshToken:
            'mock-refreshed-refresh-token-value-00000000000000000000',
          expiresAt: new Date('2025-01-02T00:00:00.000Z'),
        });
      }),
    };
    const manager = new SchlageAuthManager({
      credentials,
      transport,
      now: () => now,
    });

    await manager.ensureSession();
    now = new Date('2025-01-01T00:00:02.000Z');
    const snapshot = await manager.ensureSession();

    expect(calls).toEqual([
      'signIn',
      'refresh:mock-refresh-token-value-00000000000000000000',
    ]);
    expect(transport.signIn).toHaveBeenCalledTimes(1);
    expect(transport.refresh).toHaveBeenCalledTimes(1);
    expect(snapshot).toMatchObject({
      phase: 'authenticated',
      authenticated: true,
      session: {
        hasSession: true,
        status: 'active',
        expiresAt: '2025-01-02T00:00:00.000Z',
        refreshedAt: '2025-01-01T00:00:02.000Z',
      },
    });
    expect(JSON.stringify(snapshot)).not.toContain(
      'mock-refreshed-access-token-value',
    );
    expect(JSON.stringify(snapshot)).not.toContain(
      'mock-refreshed-refresh-token-value',
    );
  });

  it('force-refreshes a valid in-memory session using the refresh token', async () => {
    const transport: SchlageAuthTransport = {
      signIn: vi.fn(async () => session()),
      refresh: vi.fn(async () =>
        session({
          accessToken:
            'mock-force-refreshed-access-token-value-00000000000000000000',
          refreshToken:
            'mock-force-refreshed-refresh-token-value-00000000000000000000',
          refreshedAt: new Date('2999-01-01T00:00:00.000Z'),
        }),
      ),
    };
    const manager = new SchlageAuthManager({ credentials, transport });

    await manager.ensureSession();
    const snapshot = await manager.ensureSession({ forceRefresh: true });

    expect(transport.signIn).toHaveBeenCalledTimes(1);
    expect(transport.refresh).toHaveBeenCalledTimes(1);
    expect(snapshot.session.refreshedAt).toBe('2999-01-01T00:00:00.000Z');
    expect(JSON.stringify(snapshot)).not.toContain(
      'mock-force-refreshed-access-token-value',
    );
    expect(JSON.stringify(snapshot)).not.toContain(
      'mock-force-refreshed-refresh-token-value',
    );
  });

  it('maps rejected authenticate calls to a safe typed auth failure snapshot', async () => {
    const transport: SchlageAuthTransport = {
      signIn: vi.fn(async () => {
        throw new Error(
          'password=hunter2 token=unsafe-auth-token-00000000000000000000 operator@example.test',
        );
      }),
      refresh: vi.fn(async () => session()),
    };
    const manager = new SchlageAuthManager({ credentials, transport });

    await expect(manager.ensureSession()).rejects.toMatchObject({
      code: 'SCHLAGE_AUTH_FAILED',
      message: 'Schlage authenticate operation failed.',
      retryable: true,
    });

    const snapshot = manager.getSnapshot();
    expect(snapshot).toMatchObject({
      phase: 'failed',
      authenticated: false,
      session: { hasSession: false, status: 'none' },
      error: {
        code: 'SCHLAGE_AUTH_FAILED',
        message: 'Schlage authenticate operation failed.',
        retryable: true,
      },
    });
    expect(JSON.stringify(snapshot)).not.toContain('hunter2');
    expect(JSON.stringify(snapshot)).not.toContain('unsafe-auth-token');
    expect(JSON.stringify(snapshot)).not.toContain('operator@example.test');
    expect(transport.refresh).not.toHaveBeenCalled();
  });

  it('maps rejected refresh calls to a safe typed auth/session failure snapshot', async () => {
    const transport: SchlageAuthTransport = {
      signIn: vi.fn(async () => session()),
      refresh: vi.fn(async () => {
        throw new Error(
          'refresh_token=unsafe-refresh-token-00000000000000000000',
        );
      }),
    };
    const manager = new SchlageAuthManager({ credentials, transport });

    await manager.ensureSession();
    await expect(
      manager.ensureSession({ forceRefresh: true }),
    ).rejects.toMatchObject({
      code: 'SCHLAGE_AUTH_FAILED',
      message: 'Schlage refresh operation failed.',
      retryable: true,
    });

    const snapshot = manager.getSnapshot();
    expect(snapshot).toMatchObject({
      phase: 'failed',
      authenticated: false,
      error: {
        code: 'SCHLAGE_AUTH_FAILED',
        message: 'Schlage refresh operation failed.',
        retryable: true,
      },
    });
    expect(JSON.stringify(snapshot)).not.toContain('unsafe-refresh-token');
  });

  it('preserves rate-limit and auth status categories from auth transport failures', async () => {
    const rateLimitedTransport: SchlageAuthTransport = {
      signIn: vi.fn(async () => {
        throw {
          statusCode: 429,
          message: 'token=rate-limited-auth-token-00000000000000000000',
        };
      }),
      refresh: vi.fn(async () => session()),
    };
    const rateLimitedManager = new SchlageAuthManager({
      credentials,
      transport: rateLimitedTransport,
    });

    await expect(rateLimitedManager.ensureSession()).rejects.toMatchObject({
      code: 'SCHLAGE_RATE_LIMITED',
      message: 'Schlage authenticate operation failed.',
      retryable: true,
    });
    expect(rateLimitedManager.getSnapshot()).toMatchObject({
      phase: 'failed',
      error: { code: 'SCHLAGE_RATE_LIMITED', retryable: true },
    });
    expect(JSON.stringify(rateLimitedManager.getSnapshot())).not.toContain(
      'rate-limited-auth-token',
    );

    const unauthorizedTransport: SchlageAuthTransport = {
      signIn: vi.fn(async () => session()),
      refresh: vi.fn(async () => {
        throw { status: 401, message: 'password=hunter2' };
      }),
    };
    const unauthorizedManager = new SchlageAuthManager({
      credentials,
      transport: unauthorizedTransport,
    });

    await unauthorizedManager.ensureSession();
    await expect(
      unauthorizedManager.ensureSession({ forceRefresh: true }),
    ).rejects.toMatchObject({
      code: 'SCHLAGE_AUTH_FAILED',
      retryable: false,
    });
    expect(JSON.stringify(unauthorizedManager.getSnapshot())).not.toContain(
      'hunter2',
    );
  });

  it('maps malformed authenticate payloads to protocol failures without exposing token material', async () => {
    const transport: SchlageAuthTransport = {
      signIn: vi.fn(
        async () =>
          ({
            accessToken: 'malformed-auth-access-token-00000000000000000000',
            refreshToken: 'malformed-auth-refresh-token-00000000000000000000',
            expiresAt: 'not-a-date',
          }) as unknown as SchlageAuthTransportResult,
      ),
      refresh: vi.fn(async () => session()),
    };
    const manager = new SchlageAuthManager({ credentials, transport });

    await expect(manager.ensureSession()).rejects.toMatchObject({
      code: 'SCHLAGE_AUTH_PROTOCOL',
    });
    expect(manager.getSnapshot()).toMatchObject({
      phase: 'failed',
      session: { hasSession: false, status: 'none' },
      error: { code: 'SCHLAGE_AUTH_PROTOCOL' },
    });
    expect(JSON.stringify(manager.getSnapshot())).not.toContain(
      'malformed-auth-access-token',
    );
    expect(JSON.stringify(manager.getSnapshot())).not.toContain(
      'malformed-auth-refresh-token',
    );
  });

  it('maps malformed refresh payloads, including missing refresh tokens and malformed expiry, to protocol failures', async () => {
    const missingRefreshTransport: SchlageAuthTransport = {
      signIn: vi.fn(async () => session()),
      refresh: vi.fn(
        async () =>
          ({
            accessToken: 'missing-refresh-access-token-00000000000000000000',
            expiresAt: new Date('2999-01-01T00:00:00.000Z'),
          }) as unknown as SchlageAuthTransportResult,
      ),
    };
    const malformedExpiryTransport: SchlageAuthTransport = {
      signIn: vi.fn(async () => session()),
      refresh: vi.fn(
        async () =>
          ({
            accessToken: 'malformed-refresh-access-token-00000000000000000000',
            refreshToken: 'malformed-refresh-token-00000000000000000000',
            expiresAt: Number.NaN,
          }) as unknown as SchlageAuthTransportResult,
      ),
    };

    const missingRefreshManager = new SchlageAuthManager({
      credentials,
      transport: missingRefreshTransport,
    });
    await missingRefreshManager.ensureSession();
    await expect(
      missingRefreshManager.ensureSession({ forceRefresh: true }),
    ).rejects.toMatchObject({
      code: 'SCHLAGE_AUTH_PROTOCOL',
    });
    expect(JSON.stringify(missingRefreshManager.getSnapshot())).not.toContain(
      'missing-refresh-access-token',
    );

    const malformedExpiryManager = new SchlageAuthManager({
      credentials,
      transport: malformedExpiryTransport,
    });
    await malformedExpiryManager.ensureSession();
    await expect(
      malformedExpiryManager.ensureSession({ forceRefresh: true }),
    ).rejects.toMatchObject({
      code: 'SCHLAGE_AUTH_PROTOCOL',
    });
    expect(JSON.stringify(malformedExpiryManager.getSnapshot())).not.toContain(
      'malformed-refresh-token',
    );
  });
});
