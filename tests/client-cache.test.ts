import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  SCHLAGE_TOKEN_CACHE_FILENAME,
  SchlageClient,
  type SchlageClientAuthTransport,
  type SchlageClientProtocolTransport,
} from '../src/index.js';
import {
  type SchlageTokenCacheSession,
  writeSchlageTokenCache,
} from '../src/token-cache.js';

const cacheRoots: string[] = [];
const credentials = {
  username: 'operator@example.test',
  password: 'passphrase',
};

function session(
  overrides: Partial<SchlageTokenCacheSession> = {},
): SchlageTokenCacheSession {
  return {
    accessToken: 'client-cache-access-token-value-00000000000000000000',
    refreshToken: 'client-cache-refresh-token-value-00000000000000000000',
    expiresAt: new Date('2999-01-01T00:00:00.000Z'),
    refreshedAt: new Date('2025-01-01T00:00:00.000Z'),
    accountId: 'client-cache-account-secret-12345',
    ...overrides,
  };
}

function mockedTransport(): SchlageClientAuthTransport {
  return {
    signIn: vi.fn(async () =>
      session({
        accessToken:
          'client-cache-signin-access-token-value-00000000000000000000',
        refreshToken:
          'client-cache-signin-refresh-token-value-00000000000000000000',
      }),
    ),
    refresh: vi.fn(async () =>
      session({
        accessToken:
          'client-cache-refreshed-access-token-value-00000000000000000000',
        refreshToken:
          'client-cache-refreshed-refresh-token-value-00000000000000000000',
        expiresAt: new Date('2999-02-01T00:00:00.000Z'),
        refreshedAt: new Date('2025-02-01T00:00:00.000Z'),
      }),
    ),
  };
}

function protocolTransport(): SchlageClientProtocolTransport {
  return {
    listLocks: vi.fn(async () => ({ locks: [] })),
    getStatus: vi.fn(async () => ({ state: 'LOCKED', battery: 91 })),
    lock: vi.fn(async () => ({ accepted: true, observedState: 'LOCKED' })),
    unlock: vi.fn(async () => ({ accepted: true, observedState: 'UNLOCKED' })),
  };
}

async function tempCacheDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'schlage-client-cache-test-'));
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

describe('SchlageClient token cache integration', () => {
  it('reuses an active local cache without signing in or exposing cache payloads', async () => {
    const cacheDir = await tempCacheDir();
    await writeSchlageTokenCache({ cacheDir, session: session() });
    const authTransport = mockedTransport();
    const client = new SchlageClient({
      ...credentials,
      cacheDir,
      authTransport,
    });

    const snapshot = await client.authCheck();

    expect(authTransport.signIn).not.toHaveBeenCalled();
    expect(authTransport.refresh).not.toHaveBeenCalled();
    expect(snapshot).toMatchObject({
      phase: 'authenticated',
      authenticated: true,
      session: { hasSession: true, status: 'active' },
      cache: { enabled: true, status: 'hit', hasSession: true },
    });
    expect(JSON.stringify(snapshot)).not.toContain(
      'client-cache-access-token-value',
    );
    expect(JSON.stringify(snapshot)).not.toContain(
      'client-cache-refresh-token-value',
    );
    expect(JSON.stringify(snapshot)).not.toContain(
      'client-cache-account-secret',
    );
    expect(client.getAuthSnapshot()).toMatchObject({
      cache: { status: 'hit' },
    });
  });

  it('refreshes an expired local cache and persists the refreshed session', async () => {
    const cacheDir = await tempCacheDir();
    await writeSchlageTokenCache({
      cacheDir,
      session: session({ expiresAt: new Date('2000-01-01T00:00:00.000Z') }),
    });
    const authTransport = mockedTransport();
    const client = new SchlageClient({
      ...credentials,
      cacheDir,
      authTransport,
    });

    const snapshot = await client.authCheck();

    expect(authTransport.signIn).not.toHaveBeenCalled();
    expect(authTransport.refresh).toHaveBeenCalledTimes(1);
    expect(snapshot).toMatchObject({
      phase: 'authenticated',
      authenticated: true,
      session: {
        hasSession: true,
        status: 'active',
        expiresAt: '2999-02-01T00:00:00.000Z',
      },
      cache: {
        enabled: true,
        status: 'hit',
        hasSession: true,
        expiresAt: '2999-02-01T00:00:00.000Z',
      },
    });

    const rawCache = await readFile(
      join(cacheDir, SCHLAGE_TOKEN_CACHE_FILENAME),
      'utf8',
    );
    expect(rawCache).toContain('client-cache-refreshed-access-token-value');
    expect(JSON.stringify(snapshot)).not.toContain(
      'client-cache-refreshed-access-token-value',
    );
  });

  it('falls back to sign-in for malformed cache data and overwrites it safely', async () => {
    const cacheDir = await tempCacheDir();
    await writeFile(
      join(cacheDir, SCHLAGE_TOKEN_CACHE_FILENAME),
      '{"accessToken":"client-cache-corrupt-token-value-00000000000000000000"',
      'utf8',
    );
    const authTransport = mockedTransport();
    const client = new SchlageClient({
      ...credentials,
      cacheDir,
      authTransport,
    });

    const snapshot = await client.authCheck();

    expect(authTransport.signIn).toHaveBeenCalledExactlyOnceWith(credentials);
    expect(authTransport.refresh).not.toHaveBeenCalled();
    expect(snapshot).toMatchObject({
      phase: 'authenticated',
      authenticated: true,
      cache: { enabled: true, status: 'hit', hasSession: true },
    });
    const rawCache = await readFile(
      join(cacheDir, SCHLAGE_TOKEN_CACHE_FILENAME),
      'utf8',
    );
    expect(rawCache).toContain('client-cache-signin-access-token-value');
    expect(JSON.stringify(snapshot)).not.toContain(
      'client-cache-corrupt-token-value',
    );
    expect(JSON.stringify(client.getAuthSnapshot())).not.toContain(
      'client-cache-signin-refresh-token-value',
    );
  });

  it('falls back to sign-in when an expired cached refresh is rejected', async () => {
    const cacheDir = await tempCacheDir();
    await writeSchlageTokenCache({
      cacheDir,
      session: session({ expiresAt: new Date('2000-01-01T00:00:00.000Z') }),
    });
    const authTransport = mockedTransport();
    vi.mocked(authTransport.refresh).mockRejectedValueOnce(
      new Error(
        'refresh_token=client-cache-rejected-refresh-token-00000000000000000000',
      ),
    );
    const client = new SchlageClient({
      ...credentials,
      cacheDir,
      authTransport,
    });

    const snapshot = await client.authCheck();

    expect(authTransport.refresh).toHaveBeenCalledTimes(1);
    expect(authTransport.signIn).toHaveBeenCalledExactlyOnceWith(credentials);
    expect(snapshot).toMatchObject({
      phase: 'authenticated',
      authenticated: true,
      cache: { enabled: true, status: 'hit', hasSession: true },
    });
    expect(JSON.stringify(snapshot)).not.toContain(
      'client-cache-rejected-refresh-token',
    );
  });

  it('keeps auth usable and reports a safe cache write failure when persistence fails', async () => {
    const cacheRoot = await tempCacheDir();
    const cacheDir = join(cacheRoot, 'not-a-directory');
    await writeFile(cacheDir, 'blocking-file', 'utf8');
    const authTransport = mockedTransport();
    const client = new SchlageClient({
      ...credentials,
      cacheDir,
      authTransport,
    });

    const snapshot = await client.authCheck();

    expect(authTransport.signIn).toHaveBeenCalledExactlyOnceWith(credentials);
    expect(snapshot).toMatchObject({
      phase: 'authenticated',
      authenticated: true,
      session: { hasSession: true, status: 'active' },
      cache: {
        enabled: true,
        status: 'write-failed',
        hasSession: false,
        error: { code: 'SCHLAGE_CACHE_WRITE_FAILED', retryable: true },
      },
    });
    expect(JSON.stringify(snapshot)).not.toContain(
      'client-cache-signin-access-token-value',
    );
    expect(JSON.stringify(snapshot)).not.toContain(cacheDir);
  });

  it('still clones options while cache-enabled auth uses the original values', async () => {
    const cacheDir = await tempCacheDir();
    const authTransport = mockedTransport();
    const options = { ...credentials, cacheDir, authTransport };
    const client = new SchlageClient(options);

    options.username = 'mutated@example.test';
    options.password = 'mutated-password';
    options.cacheDir = './mutated-cache-dir';
    const readOptions = client.options;
    readOptions.cacheDir = './read-mutated-cache-dir';

    await client.authCheck();

    expect(authTransport.signIn).toHaveBeenCalledExactlyOnceWith(credentials);
    expect(client.options).toMatchObject({ ...credentials, cacheDir });
  });

  it('reconciles stale status across cache-backed client instances after accepted commands', async () => {
    const cacheDir = await tempCacheDir();
    const writerProtocol = protocolTransport();
    const readerProtocol = protocolTransport();
    const writer = new SchlageClient({
      ...credentials,
      cacheDir,
      authTransport: mockedTransport(),
      protocolTransport: writerProtocol,
    });
    const reader = new SchlageClient({
      ...credentials,
      cacheDir,
      authTransport: mockedTransport(),
      protocolTransport: readerProtocol,
    });

    await writer.unlock('front-door');
    const status = await reader.getStatus('front-door');

    expect(status).toEqual({
      id: 'front-door',
      state: 'unlocked',
      batteryLevel: 91,
    });
  });
});
