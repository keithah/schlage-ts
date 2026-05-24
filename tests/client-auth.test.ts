import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  SchlageClient,
  SchlageError,
  type SchlageClientAuthTransport,
  type SchlageLockId,
} from '../src/index.js';

const credentials = {
  username: 'operator@example.test',
  password: 'passphrase',
};
const cacheRoots: string[] = [];

async function tempCacheDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'schlage-client-auth-test-'));
  cacheRoots.push(dir);
  return dir;
}

afterEach(async () => {
  await Promise.all(
    cacheRoots
      .splice(0)
      .map((dir) => rm(dir, { force: true, recursive: true })),
  );
});

function session(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    accessToken: 'client-access-token-value-00000000000000000000',
    refreshToken: 'client-refresh-token-value-00000000000000000000',
    expiresAt: new Date('2999-01-01T00:00:00.000Z'),
    accountId: 'account-12345',
    ...overrides,
  };
}

function mockedTransport(): SchlageClientAuthTransport {
  return {
    signIn: vi.fn(async () => session()),
    refresh: vi.fn(async () =>
      session({
        accessToken: 'client-refreshed-access-token-value-00000000000000000000',
        refreshToken:
          'client-refreshed-refresh-token-value-00000000000000000000',
        refreshedAt: new Date('2999-01-01T00:00:00.000Z'),
      }),
    ),
  };
}

describe('SchlageClient auth surface', () => {
  it('authenticates through an injected transport and exposes only a redacted status', async () => {
    const authTransport = mockedTransport();
    const client = new SchlageClient({ ...credentials, authTransport });

    const snapshot = await client.authCheck();

    expect(authTransport.signIn).toHaveBeenCalledExactlyOnceWith(credentials);
    expect(authTransport.refresh).not.toHaveBeenCalled();
    expect(snapshot).toMatchObject({
      phase: 'authenticated',
      username: '[REDACTED_USERNAME]',
      authenticated: true,
      session: { hasSession: true, status: 'active' },
    });
    expect(JSON.stringify(snapshot)).not.toContain(credentials.username);
    expect(JSON.stringify(snapshot)).not.toContain(credentials.password);
    expect(JSON.stringify(snapshot)).not.toContain('client-access-token-value');
    expect(JSON.stringify(snapshot)).not.toContain(
      'client-refresh-token-value',
    );
    expect(JSON.stringify(snapshot)).not.toContain('account-12345');
  });

  it('force-refreshes an existing client session without re-authenticating', async () => {
    const authTransport = mockedTransport();
    const client = new SchlageClient({ ...credentials, authTransport });

    await client.authCheck();
    const snapshot = await client.refreshSession();

    expect(authTransport.signIn).toHaveBeenCalledTimes(1);
    expect(authTransport.refresh).toHaveBeenCalledTimes(1);
    expect(snapshot).toMatchObject({
      phase: 'authenticated',
      authenticated: true,
      session: {
        hasSession: true,
        status: 'active',
        refreshedAt: '2999-01-01T00:00:00.000Z',
      },
    });
    expect(JSON.stringify(snapshot)).not.toContain(
      'client-refreshed-access-token-value',
    );
    expect(JSON.stringify(snapshot)).not.toContain(
      'client-refreshed-refresh-token-value',
    );
  });

  it('reports missing credentials through safe typed errors only when auth is requested', async () => {
    const client = new SchlageClient({ cacheDir: './.schlage-cache' });

    expect(client.options.cacheDir).toBe('./.schlage-cache');
    await expect(client.authCheck()).rejects.toMatchObject({
      code: 'SCHLAGE_CONFIG_MISSING_CREDENTIALS',
      message: 'Schlage username and password are required.',
      retryable: false,
    });
    await expect(client.listLocks()).rejects.toMatchObject({
      code: 'SCHLAGE_CONFIG_MISSING_CREDENTIALS',
      message: 'Schlage username and password are required.',
      retryable: false,
    });
  });

  it('clones options at construction and when read back', async () => {
    const authTransport = mockedTransport();
    const cacheDir = await tempCacheDir();
    const options = { ...credentials, cacheDir, authTransport };
    const client = new SchlageClient(options);

    options.username = 'mutated@example.test';
    options.password = 'mutated-password';
    options.cacheDir = './after';
    const readOptions = client.options;
    readOptions.cacheDir = './read-mutated';

    expect(client.options).toMatchObject({
      username: credentials.username,
      password: credentials.password,
      cacheDir,
    });

    await client.authCheck();
    expect(authTransport.signIn).toHaveBeenCalledExactlyOnceWith(credentials);
  });

  it('authenticates before reporting missing protocol transport for protocol operations', async () => {
    const authTransport = mockedTransport();
    const client = new SchlageClient({ ...credentials, authTransport });
    const lockId: SchlageLockId = 'front-door';

    await expect(client.listLocks()).rejects.toMatchObject({
      code: 'SCHLAGE_NOT_IMPLEMENTED',
    });
    await expect(client.getStatus(lockId)).rejects.toMatchObject({
      code: 'SCHLAGE_NOT_IMPLEMENTED',
    });
    await expect(client.lock(lockId)).rejects.toMatchObject({
      code: 'SCHLAGE_NOT_IMPLEMENTED',
    });
    await expect(client.unlock(lockId)).rejects.toMatchObject({
      code: 'SCHLAGE_NOT_IMPLEMENTED',
    });
    expect(authTransport.signIn).toHaveBeenCalledTimes(1);
  });

  it('does not leak token-shaped transport failure payloads through public errors or snapshots', async () => {
    const authTransport: SchlageClientAuthTransport = {
      signIn: vi.fn(async () => {
        throw new Error(
          'password=hunter2 token=unsafe-client-auth-token-00000000000000000000 operator@example.test',
        );
      }),
      refresh: vi.fn(async () => session()),
    };
    const client = new SchlageClient({ ...credentials, authTransport });

    await expect(client.authCheck()).rejects.toBeInstanceOf(SchlageError);
    await expect(client.authCheck()).rejects.toMatchObject({
      code: 'SCHLAGE_AUTH_FAILED',
      message: 'Schlage authenticate operation failed.',
      retryable: true,
    });

    const snapshot = client.getAuthSnapshot();
    const renderedSnapshot = JSON.stringify(snapshot);
    const renderedOptions = JSON.stringify(client.options);
    expect(renderedSnapshot).not.toContain('hunter2');
    expect(renderedSnapshot).not.toContain('unsafe-client-auth-token');
    expect(renderedSnapshot).not.toContain(credentials.username);
    expect(renderedOptions).not.toContain('hunter2');
    expect(renderedOptions).not.toContain('unsafe-client-auth-token');
  });
});
