import { describe, expect, it, vi } from 'vitest';
import {
  SchlageClient,
  toPublicSchlageError,
  type SchlageClientAuthTransport,
  type SchlageClientProtocolTransport,
} from '../src/index.js';

type Session = Awaited<ReturnType<SchlageClientAuthTransport['signIn']>>;

const credentials = {
  username: 'operator@example.test',
  password: 'passphrase',
};

function session(overrides: Partial<Record<string, unknown>> = {}): Session {
  return {
    accessToken: 'client-protocol-access-token-value-00000000000000000000',
    refreshToken: 'client-protocol-refresh-token-value-00000000000000000000',
    expiresAt: new Date('2999-01-01T00:00:00.000Z'),
    refreshedAt: new Date('2025-01-01T00:00:00.000Z'),
    accountId: 'client-protocol-account-secret-12345',
    ...overrides,
  };
}

function authTransport(
  sessionResult: Session = session(),
): SchlageClientAuthTransport {
  return {
    signIn: vi.fn(async () => sessionResult),
    refresh: vi.fn(async () => sessionResult),
  };
}

function protocolTransport(): SchlageClientProtocolTransport {
  return {
    listLocks: vi.fn(async () => ({
      locks: [
        {
          id: ' front-door ',
          name: ' Front Door ',
          subtitle: ' sf front ',
          accessToken: 'raw-list-token-value-00000000000000000000',
          accountId: 'raw-list-account-secret-12345',
        },
      ],
    })),
    getStatus: vi.fn(async () => ({
      state: 'LOCKED',
      battery: 91,
      updatedAt: '2025-01-02T03:04:05.000Z',
      lockStateMetadata: { actionType: 'virtualKey', UUID: 'user-1' },
      users: [
        {
          identityId: 'user-1',
          friendlyName: 'Operator',
          email: 'operator@example.test',
        },
      ],
      refreshToken: 'raw-status-refresh-token-00000000000000000000',
    })),
    lock: vi.fn(async () => ({
      accepted: true,
      observedState: 'LOCKED',
      commandToken: 'raw-lock-command-token-00000000000000000000',
    })),
    unlock: vi.fn(async () => ({
      accepted: true,
      observedState: 'UNLOCKED',
      commandToken: 'raw-unlock-command-token-00000000000000000000',
    })),
    listUsers: vi.fn(async () => ({
      users: [
        {
          identityId: 'user-1',
          friendlyName: 'Operator',
          email: 'operator@example.test',
          accessToken: 'raw-user-token-value-00000000000000000000',
        },
      ],
    })),
    listAccessCodes: vi.fn(async () => [
      {
        accesscodeId: 'code-1',
        friendlyName: 'Cleaner',
        accessCode: 42,
        accessCodeLength: 4,
        disabled: 0,
        activationSecs: 1735689600,
        expirationSecs: 1735776000,
        rawToken: 'raw-code-token-value-00000000000000000000',
      },
    ]),
    listLogs: vi.fn(async () => [
      {
        createdAt: '2025-01-02T03:04:05.000Z',
        message: { eventCode: 2, accessorUuid: 'user-1', keypadUuid: 'code-1' },
        rawToken: 'raw-log-token-value-00000000000000000000',
      },
    ]),
    getDiagnostics: vi.fn(async () => ({
      deviceId: 'front-door-secret-id',
      name: 'Front Door',
      attributes: {
        batteryLevel: 91,
        accessToken: 'raw-diagnostic-token-value-00000000000000000000',
      },
      users: [{ email: 'operator@example.test' }],
    })),
    addAccessCode: vi.fn(async () => ({
      accepted: true,
      accesscodeId: 'code-2',
      rawToken: 'raw-add-code-token-value-00000000000000000000',
    })),
    updateAccessCode: vi.fn(async () => ({
      accepted: true,
      accesscodeId: 'code-1',
      rawToken: 'raw-update-code-token-value-00000000000000000000',
    })),
    deleteAccessCode: vi.fn(async () => ({
      accepted: true,
      accesscodeId: 'code-1',
      rawToken: 'raw-delete-code-token-value-00000000000000000000',
    })),
    setLockSetting: vi.fn(async () => ({
      accepted: true,
      rawToken: 'raw-setting-token-value-00000000000000000000',
    })),
  };
}

describe('SchlageClient authenticated protocol operations', () => {
  it('authenticates once, passes private session material to list-locks transport, and returns redacted public locks', async () => {
    const auth = authTransport();
    const protocol = protocolTransport();
    const client = new SchlageClient({
      ...credentials,
      authTransport: auth,
      protocolTransport: protocol,
    });

    const locks = await client.listLocks();

    expect(auth.signIn).toHaveBeenCalledExactlyOnceWith(credentials);
    expect(auth.refresh).not.toHaveBeenCalled();
    expect(protocol.listLocks).toHaveBeenCalledTimes(1);
    expect(protocol.listLocks).toHaveBeenCalledWith(
      expect.objectContaining({
        accessToken: 'client-protocol-access-token-value-00000000000000000000',
        refreshToken:
          'client-protocol-refresh-token-value-00000000000000000000',
        accountId: 'client-protocol-account-secret-12345',
      }),
    );
    expect(locks).toEqual([
      { id: 'front-door', name: 'Front Door', subtitle: 'sf front' },
    ]);
    expect(JSON.stringify(locks)).not.toContain('token');
    expect(JSON.stringify(locks)).not.toContain('account');
    expect(JSON.stringify(client.getAuthSnapshot())).not.toContain(
      'client-protocol-access-token-value',
    );
    expect(JSON.stringify(client.getAuthSnapshot())).not.toContain(
      'client-protocol-account-secret',
    );
  });

  it('reuses a live authenticated session for status without reauthenticating', async () => {
    const auth = authTransport();
    const protocol = protocolTransport();
    const client = new SchlageClient({
      ...credentials,
      authTransport: auth,
      protocolTransport: protocol,
    });

    await client.listLocks();
    const status = await client.getStatus('front-door');

    expect(auth.signIn).toHaveBeenCalledTimes(1);
    expect(auth.refresh).not.toHaveBeenCalled();
    expect(protocol.getStatus).toHaveBeenCalledExactlyOnceWith(
      expect.objectContaining({
        accessToken: 'client-protocol-access-token-value-00000000000000000000',
      }),
      'front-door',
    );
    expect(status).toEqual({
      id: 'front-door',
      state: 'locked',
      batteryLevel: 91,
      updatedAt: new Date('2025-01-02T03:04:05.000Z'),
      lockStateMetadata: { actionType: 'virtualKey', uuid: 'user-1' },
      users: [
        { id: 'user-1', name: 'Operator', email: 'operator@example.test' },
      ],
    });
    expect(JSON.stringify(status)).not.toContain('raw-status-refresh-token');
  });

  it('locks then unlocks the same mocked lock through the authenticated protocol seam', async () => {
    const auth = authTransport();
    const protocol = protocolTransport();
    const client = new SchlageClient({
      ...credentials,
      authTransport: auth,
      protocolTransport: protocol,
    });

    const lockResult = await client.lock(' front-door ');
    const unlockResult = await client.unlock('front-door');

    expect(auth.signIn).toHaveBeenCalledTimes(1);
    expect(auth.refresh).not.toHaveBeenCalled();
    expect(protocol.lock).toHaveBeenCalledExactlyOnceWith(
      expect.objectContaining({
        accessToken: 'client-protocol-access-token-value-00000000000000000000',
      }),
      'front-door',
    );
    expect(protocol.unlock).toHaveBeenCalledExactlyOnceWith(
      expect.objectContaining({
        accessToken: 'client-protocol-access-token-value-00000000000000000000',
      }),
      'front-door',
    );
    expect(lockResult).toEqual({
      id: 'front-door',
      accepted: true,
      observedState: 'locked',
    });
    expect(unlockResult).toEqual({
      id: 'front-door',
      accepted: true,
      observedState: 'unlocked',
    });
    expect(JSON.stringify([lockResult, unlockResult])).not.toContain(
      'command-token',
    );
  });

  it('reads users, access codes, and lock logs through the authenticated protocol seam', async () => {
    const auth = authTransport();
    const protocol = protocolTransport();
    const client = new SchlageClient({
      ...credentials,
      authTransport: auth,
      protocolTransport: protocol,
    });

    const users = await client.listUsers();
    const codes = await client.listAccessCodes(' front-door ');
    const logs = await client.listLogs('front-door', {
      limit: 10,
      sortDesc: true,
    });

    expect(auth.signIn).toHaveBeenCalledTimes(1);
    expect(protocol.listUsers).toHaveBeenCalledExactlyOnceWith(
      expect.objectContaining({
        accessToken: 'client-protocol-access-token-value-00000000000000000000',
      }),
    );
    expect(protocol.listAccessCodes).toHaveBeenCalledExactlyOnceWith(
      expect.objectContaining({
        accessToken: 'client-protocol-access-token-value-00000000000000000000',
      }),
      'front-door',
    );
    expect(protocol.listLogs).toHaveBeenCalledExactlyOnceWith(
      expect.objectContaining({
        accessToken: 'client-protocol-access-token-value-00000000000000000000',
      }),
      'front-door',
      { limit: 10, sortDesc: true },
    );
    expect(users).toEqual([
      { id: 'user-1', name: 'Operator', email: 'operator@example.test' },
    ]);
    expect(codes).toEqual([
      {
        id: 'code-1',
        lockId: 'front-door',
        name: 'Cleaner',
        code: '0042',
        disabled: false,
        schedule: {
          type: 'temporary',
          startsAt: new Date('2025-01-01T00:00:00.000Z'),
          endsAt: new Date('2025-01-02T00:00:00.000Z'),
        },
      },
    ]);
    expect(logs).toEqual([
      {
        lockId: 'front-door',
        createdAt: new Date('2025-01-02T03:04:05.000Z'),
        message: 'Unlocked by keypad',
        eventCode: 2,
        accessorId: 'user-1',
        accessCodeId: 'code-1',
      },
    ]);
    expect(JSON.stringify([users, codes, logs])).not.toContain(
      'raw-user-token-value',
    );
    expect(JSON.stringify([users, codes, logs])).not.toContain(
      'raw-code-token-value',
    );
    expect(JSON.stringify([users, codes, logs])).not.toContain(
      'raw-log-token-value',
    );
  });

  it('reads diagnostics and pyschlage helper values through the authenticated protocol seam', async () => {
    const auth = authTransport();
    const protocol = protocolTransport();
    const client = new SchlageClient({
      ...credentials,
      authTransport: auth,
      protocolTransport: protocol,
    });

    const diagnostics = await client.getDiagnostics(' front-door ');
    const keypadDisabled = await client.keypadDisabled('front-door', [
      {
        lockId: 'front-door',
        createdAt: new Date('2025-01-02T03:04:05.000Z'),
        message: 'Unlocked by keypad',
        eventCode: 2,
      },
      {
        lockId: 'front-door',
        createdAt: new Date('2025-01-02T03:05:05.000Z'),
        message: 'Keypad disabled invalid code',
        eventCode: 11,
      },
    ]);
    const lastChangedBy = await client.lastChangedBy('front-door');

    expect(protocol.getDiagnostics).toHaveBeenCalledExactlyOnceWith(
      expect.objectContaining({
        accessToken: 'client-protocol-access-token-value-00000000000000000000',
      }),
      'front-door',
    );
    expect(protocol.getStatus).toHaveBeenCalledExactlyOnceWith(
      expect.any(Object),
      'front-door',
    );
    expect(protocol.listLogs).not.toHaveBeenCalled();
    expect(diagnostics).toMatchObject({
      deviceId: '<REDACTED>',
      name: 'Front Door',
      attributes: {
        batteryLevel: 91,
        accessToken: '<REDACTED>',
      },
      users: ['<REDACTED>'],
    });
    expect(keypadDisabled).toBe(true);
    expect(lastChangedBy).toBe('mobile device - Operator');
    expect(JSON.stringify(diagnostics)).not.toContain('raw-diagnostic-token');
  });

  it('writes access codes and lock settings through the authenticated protocol seam', async () => {
    const auth = authTransport();
    const protocol = protocolTransport();
    const client = new SchlageClient({
      ...credentials,
      authTransport: auth,
      protocolTransport: protocol,
    });

    const added = await client.addAccessCode(' front-door ', {
      name: 'Cleaner',
      code: '0042',
      disabled: false,
    });
    const updated = await client.updateAccessCode('front-door', ' code-1 ', {
      name: 'Cleaner Updated',
      code: '0043',
      disabled: true,
    });
    const deleted = await client.deleteAccessCode('front-door', 'code-1');
    const beeper = await client.setBeeper('front-door', true);
    const lockAndLeave = await client.setLockAndLeave('front-door', false);
    const autoLock = await client.setAutoLockTime('front-door', 60);

    expect(auth.signIn).toHaveBeenCalledTimes(1);
    expect(protocol.addAccessCode).toHaveBeenCalledExactlyOnceWith(
      expect.objectContaining({
        accessToken: 'client-protocol-access-token-value-00000000000000000000',
      }),
      'front-door',
      { name: 'Cleaner', code: '0042', disabled: false },
    );
    expect(protocol.updateAccessCode).toHaveBeenCalledExactlyOnceWith(
      expect.objectContaining({
        accessToken: 'client-protocol-access-token-value-00000000000000000000',
      }),
      'front-door',
      'code-1',
      { name: 'Cleaner Updated', code: '0043', disabled: true },
    );
    expect(protocol.deleteAccessCode).toHaveBeenCalledExactlyOnceWith(
      expect.objectContaining({
        accessToken: 'client-protocol-access-token-value-00000000000000000000',
      }),
      'front-door',
      'code-1',
    );
    expect(protocol.setLockSetting).toHaveBeenNthCalledWith(
      1,
      expect.objectContaining({
        accessToken: 'client-protocol-access-token-value-00000000000000000000',
      }),
      'front-door',
      'beeperEnabled',
      true,
    );
    expect(protocol.setLockSetting).toHaveBeenNthCalledWith(
      2,
      expect.any(Object),
      'front-door',
      'lockAndLeaveEnabled',
      false,
    );
    expect(protocol.setLockSetting).toHaveBeenNthCalledWith(
      3,
      expect.any(Object),
      'front-door',
      'autoLockTime',
      60,
    );
    expect(added).toEqual({
      lockId: 'front-door',
      accepted: true,
      accessCodeId: 'code-2',
    });
    expect(updated).toEqual({
      lockId: 'front-door',
      accepted: true,
      accessCodeId: 'code-1',
    });
    expect(deleted).toEqual({
      lockId: 'front-door',
      accepted: true,
      accessCodeId: 'code-1',
    });
    expect(beeper).toEqual({ lockId: 'front-door', accepted: true });
    expect(lockAndLeave).toEqual({ lockId: 'front-door', accepted: true });
    expect(autoLock).toEqual({ lockId: 'front-door', accepted: true });
    expect(
      JSON.stringify([added, updated, deleted, beeper, lockAndLeave, autoLock]),
    ).not.toContain('raw-');
  });

  it('rejects invalid write inputs before auth or protocol use', async () => {
    const auth = authTransport();
    const protocol = protocolTransport();
    const client = new SchlageClient({
      ...credentials,
      authTransport: auth,
      protocolTransport: protocol,
    });

    await expect(
      client.addAccessCode('   ', { name: 'Cleaner', code: '0042' }),
    ).rejects.toMatchObject({
      code: 'SCHLAGE_LOCK_ID_INVALID',
      retryable: false,
    });
    await expect(
      client.updateAccessCode('front-door', '   ', {
        name: 'Cleaner',
        code: '0042',
      }),
    ).rejects.toMatchObject({
      code: 'SCHLAGE_LOCK_ID_INVALID',
      retryable: false,
    });
    await expect(client.setAutoLockTime('front-door', 7)).rejects.toMatchObject(
      {
        code: 'SCHLAGE_LOCK_ID_INVALID',
        retryable: false,
      },
    );
    await expect(client.keypadDisabled('   ', [])).rejects.toMatchObject({
      code: 'SCHLAGE_LOCK_ID_INVALID',
      retryable: false,
    });

    expect(auth.signIn).not.toHaveBeenCalled();
    expect(protocol.addAccessCode).not.toHaveBeenCalled();
    expect(protocol.updateAccessCode).not.toHaveBeenCalled();
    expect(protocol.setLockSetting).not.toHaveBeenCalled();
  });

  it('returns structured command rejection and failed-state outcomes without leaking raw protocol fields', async () => {
    const auth = authTransport();
    const protocol = protocolTransport();
    vi.mocked(protocol.lock).mockResolvedValueOnce({
      accepted: false,
      observedState: 'locked',
      reason: 'policy-rejected-secret-token-00000000000000000000',
    });
    vi.mocked(protocol.unlock).mockResolvedValueOnce({
      accepted: false,
      observedState: 'jammed-protocol-value',
      failureCode: 'transport-specific-failure',
    });
    const client = new SchlageClient({
      ...credentials,
      authTransport: auth,
      protocolTransport: protocol,
    });

    const rejected = await client.lock('front-door');
    const failed = await client.unlock('front-door');

    expect(rejected).toEqual({
      id: 'front-door',
      accepted: false,
      observedState: 'locked',
    });
    expect(failed).toEqual({
      id: 'front-door',
      accepted: false,
      observedState: 'unknown',
    });
    expect(JSON.stringify([rejected, failed])).not.toContain(
      'policy-rejected-secret-token',
    );
    expect(JSON.stringify([rejected, failed])).not.toContain(
      'transport-specific-failure',
    );
  });

  it('rejects blank command lock IDs before auth or protocol use', async () => {
    const auth = authTransport();
    const protocol = protocolTransport();
    const client = new SchlageClient({
      ...credentials,
      authTransport: auth,
      protocolTransport: protocol,
    });

    await expect(client.lock('   ')).rejects.toMatchObject({
      code: 'SCHLAGE_LOCK_ID_INVALID',
      retryable: false,
    });
    await expect(client.unlock('')).rejects.toMatchObject({
      code: 'SCHLAGE_LOCK_ID_INVALID',
      retryable: false,
    });

    expect(auth.signIn).not.toHaveBeenCalled();
    expect(protocol.lock).not.toHaveBeenCalled();
    expect(protocol.unlock).not.toHaveBeenCalled();
  });

  it('does not call protocol transport when authentication fails', async () => {
    const auth = authTransport();
    vi.mocked(auth.signIn).mockRejectedValueOnce(
      new Error('access_token=auth-failed-token-00000000000000000000'),
    );
    const protocol = protocolTransport();
    const client = new SchlageClient({
      ...credentials,
      authTransport: auth,
      protocolTransport: protocol,
    });

    await expect(client.listLocks()).rejects.toMatchObject({
      code: 'SCHLAGE_AUTH_FAILED',
      retryable: true,
    });

    expect(protocol.listLocks).not.toHaveBeenCalled();
    expect(protocol.getStatus).not.toHaveBeenCalled();
    expect(JSON.stringify(client.getAuthSnapshot())).not.toContain(
      'auth-failed-token',
    );
  });

  it('reports missing protocol transport as not implemented after session authentication succeeds', async () => {
    const auth = authTransport();
    const client = new SchlageClient({ ...credentials, authTransport: auth });

    await expect(client.listLocks()).rejects.toMatchObject({
      code: 'SCHLAGE_NOT_IMPLEMENTED',
      message:
        'SchlageClient.listLocks is not implemented until the Schlage protocol port lands.',
    });

    expect(auth.signIn).toHaveBeenCalledTimes(1);
  });

  it('maps malformed list/status/command payloads to safe protocol errors', async () => {
    const auth = authTransport();
    const protocol = protocolTransport();
    vi.mocked(protocol.listLocks).mockResolvedValueOnce({
      locks: [{ id: 'front-door' }],
    });
    vi.mocked(protocol.getStatus).mockResolvedValueOnce({ state: null });
    vi.mocked(protocol.lock).mockResolvedValueOnce({ accepted: 'true' });
    vi.mocked(protocol.unlock).mockResolvedValueOnce({
      accepted: true,
      observedState: 1,
    });
    const client = new SchlageClient({
      ...credentials,
      authTransport: auth,
      protocolTransport: protocol,
    });

    await expect(client.listLocks()).rejects.toMatchObject({
      code: 'SCHLAGE_PROTOCOL_MALFORMED',
      retryable: true,
    });
    await expect(client.getStatus('front-door')).rejects.toMatchObject({
      code: 'SCHLAGE_PROTOCOL_MALFORMED',
      retryable: true,
    });
    await expect(client.lock('front-door')).rejects.toMatchObject({
      code: 'SCHLAGE_PROTOCOL_MALFORMED',
      retryable: true,
    });
    await expect(client.unlock('front-door')).rejects.toMatchObject({
      code: 'SCHLAGE_PROTOCOL_MALFORMED',
      retryable: true,
    });
  });

  it('wraps token-shaped transport failures in redacted protocol errors', async () => {
    const auth = authTransport();
    const protocol = protocolTransport();
    vi.mocked(protocol.getStatus).mockRejectedValueOnce(
      new Error(
        'authorization=Bearer protocol-failure-token-00000000000000000000 operator@example.test',
      ),
    );
    vi.mocked(protocol.lock).mockRejectedValueOnce(
      new Error(
        'access_token=command-failure-token-00000000000000000000 operator@example.test',
      ),
    );
    const client = new SchlageClient({
      ...credentials,
      authTransport: auth,
      protocolTransport: protocol,
    });

    try {
      await client.getStatus('front-door');
      throw new Error('expected protocol failure');
    } catch (error) {
      const publicError = toPublicSchlageError(error);
      expect(publicError).toEqual({
        name: 'SchlageError',
        code: 'SCHLAGE_PROTOCOL_TRANSPORT',
        message: 'Schlage getStatus operation failed.',
        retryable: true,
      });
      expect(JSON.stringify(publicError)).not.toContain(
        'protocol-failure-token',
      );
      expect(JSON.stringify(publicError)).not.toContain(
        'operator@example.test',
      );
    }

    try {
      await client.lock('front-door');
      throw new Error('expected command protocol failure');
    } catch (error) {
      const publicError = toPublicSchlageError(error);
      expect(publicError).toEqual({
        name: 'SchlageError',
        code: 'SCHLAGE_PROTOCOL_TRANSPORT',
        message: 'Schlage lock operation failed.',
        retryable: true,
      });
      expect(JSON.stringify(publicError)).not.toContain(
        'command-failure-token',
      );
      expect(JSON.stringify(publicError)).not.toContain(
        'operator@example.test',
      );
    }
  });

  it('preserves rate-limit-like protocol failures as retryable public error codes', async () => {
    const auth = authTransport();
    const protocol = protocolTransport();
    vi.mocked(protocol.listLocks).mockRejectedValueOnce({
      status: 429,
      message:
        'rate limited for access_token=rate-limit-protocol-token-00000000000000000000',
    });
    const client = new SchlageClient({
      ...credentials,
      authTransport: auth,
      protocolTransport: protocol,
    });

    try {
      await client.listLocks();
      throw new Error('expected rate limit failure');
    } catch (error) {
      const publicError = toPublicSchlageError(error);
      expect(publicError).toEqual({
        name: 'SchlageError',
        code: 'SCHLAGE_RATE_LIMITED',
        message: 'Schlage listLocks operation failed.',
        retryable: true,
      });
      expect(JSON.stringify(publicError)).not.toContain(
        'rate-limit-protocol-token',
      );
    }
  });
});
