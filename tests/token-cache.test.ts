import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { afterEach, describe, expect, it } from 'vitest';
import {
  SCHLAGE_TOKEN_CACHE_FILENAME,
  createPublicSchlageTokenCacheSnapshot,
  readSchlageTokenCache,
  rejectSchlageTokenCache,
  writeSchlageTokenCache,
  type SchlageTokenCacheSession,
} from '../src/token-cache.js';
import { toPublicSchlageError } from '../src/errors.js';

const cacheRoots: string[] = [];
const now = new Date('2025-01-01T00:00:00.000Z');

function session(
  overrides: Partial<SchlageTokenCacheSession> = {},
): SchlageTokenCacheSession {
  return {
    accessToken: 'cache-access-token-value-00000000000000000000',
    refreshToken: 'cache-refresh-token-value-00000000000000000000',
    expiresAt: new Date('2999-01-01T00:00:00.000Z'),
    refreshedAt: new Date('2025-01-01T00:00:00.000Z'),
    accountId: 'account-secret-12345',
    ...overrides,
  };
}

async function tempCacheDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'schlage-token-cache-test-'));
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

describe('local Schlage token cache', () => {
  it('classifies a missing deterministic cache file as a redacted miss', async () => {
    const cacheDir = await tempCacheDir();
    const result = await readSchlageTokenCache({ cacheDir, now });

    expect(result).toEqual({
      status: 'missing',
      snapshot: { enabled: true, status: 'missing', hasSession: false },
    });
  });

  it('writes a deterministic cache file atomically enough for local CLI use and reads a redacted hit', async () => {
    const cacheDir = await tempCacheDir();

    const writeResult = await writeSchlageTokenCache({
      cacheDir,
      session: session(),
      now,
    });
    expect(writeResult.snapshot).toEqual({
      enabled: true,
      status: 'hit',
      hasSession: true,
      expiresAt: '2999-01-01T00:00:00.000Z',
      refreshedAt: '2025-01-01T00:00:00.000Z',
    });

    const cacheFile = join(cacheDir, SCHLAGE_TOKEN_CACHE_FILENAME);
    const rawFile = await readFile(cacheFile, 'utf8');
    expect(rawFile).toContain('cache-access-token-value');
    expect(rawFile).toContain('cache-refresh-token-value');

    const readResult = await readSchlageTokenCache({ cacheDir, now });
    expect(readResult.status).toBe('hit');
    expect(readResult.snapshot).toEqual({
      enabled: true,
      status: 'hit',
      hasSession: true,
      expiresAt: '2999-01-01T00:00:00.000Z',
      refreshedAt: '2025-01-01T00:00:00.000Z',
    });
    expect(JSON.stringify(readResult.snapshot)).not.toContain(
      'cache-access-token-value',
    );
    expect(JSON.stringify(readResult.snapshot)).not.toContain(
      'cache-refresh-token-value',
    );
    expect(JSON.stringify(readResult.snapshot)).not.toContain(
      'account-secret-12345',
    );

    if (readResult.status === 'hit') {
      expect(readResult.session.refreshToken).toBe(
        'cache-refresh-token-value-00000000000000000000',
      );
      expect(readResult.session.expiresAt).toEqual(
        new Date('2999-01-01T00:00:00.000Z'),
      );
    }
  });

  it('classifies expired cached sessions without leaking token material', async () => {
    const cacheDir = await tempCacheDir();
    await writeSchlageTokenCache({
      cacheDir,
      session: session({ expiresAt: new Date('2024-12-31T23:59:59.000Z') }),
      now,
    });

    const readResult = await readSchlageTokenCache({ cacheDir, now });

    expect(readResult.status).toBe('expired');
    expect(readResult.snapshot).toMatchObject({
      enabled: true,
      status: 'expired',
      hasSession: true,
    });
    expect(JSON.stringify(readResult.snapshot)).not.toContain(
      'cache-refresh-token-value',
    );
  });

  it('rejects invalid JSON and malformed session material as safe cache diagnostics', async () => {
    const malformedDir = await tempCacheDir();
    await writeFile(
      join(malformedDir, SCHLAGE_TOKEN_CACHE_FILENAME),
      '{"accessToken":"token-shaped-corrupt-value-00000000000000000000"',
      'utf8',
    );

    const malformed = await readSchlageTokenCache({
      cacheDir: malformedDir,
      now,
    });
    expect(malformed.status).toBe('malformed');
    expect(malformed.snapshot.error).toMatchObject({
      code: 'SCHLAGE_CACHE_MALFORMED',
    });
    expect(JSON.stringify(malformed.snapshot)).not.toContain(
      'token-shaped-corrupt-value',
    );

    const rejectedDir = await tempCacheDir();
    await writeFile(
      join(rejectedDir, SCHLAGE_TOKEN_CACHE_FILENAME),
      JSON.stringify({
        accessToken: 'token-shaped-rejected-access-value-00000000000000000000',
        expiresAt: '2999-01-01T00:00:00.000Z',
      }),
      'utf8',
    );

    const rejected = await readSchlageTokenCache({
      cacheDir: rejectedDir,
      now,
    });
    expect(rejected.status).toBe('rejected');
    expect(rejected.snapshot.error).toMatchObject({
      code: 'SCHLAGE_CACHE_REJECTED',
    });
    expect(JSON.stringify(rejected.snapshot)).not.toContain(
      'token-shaped-rejected-access-value',
    );
  });

  it('returns typed read and write failures without exposing file contents or raw paths', async () => {
    const cacheDir = await tempCacheDir();
    const blockingFile = join(cacheDir, SCHLAGE_TOKEN_CACHE_FILENAME);
    await writeFile(
      blockingFile,
      'token=read-failed-token-value-00000000000000000000',
      'utf8',
    );
    await chmod(blockingFile, 0o000);

    try {
      const readFailed = await readSchlageTokenCache({ cacheDir, now });
      if (process.getuid?.() !== 0) {
        expect(readFailed.status).toBe('read-failed');
        expect(readFailed.snapshot.error).toMatchObject({
          code: 'SCHLAGE_CACHE_READ_FAILED',
        });
        expect(JSON.stringify(readFailed.snapshot)).not.toContain(
          'read-failed-token-value',
        );
        expect(JSON.stringify(readFailed.snapshot)).not.toContain(blockingFile);
      }
    } finally {
      await chmod(blockingFile, 0o600);
    }

    const notADirectory = join(cacheDir, 'not-a-directory');
    await writeFile(notADirectory, 'blocking-file', 'utf8');

    const deterministicReadFailed = await readSchlageTokenCache({
      cacheDir: notADirectory,
      now,
    });
    expect(deterministicReadFailed.status).toBe('read-failed');
    expect(deterministicReadFailed.snapshot.error).toMatchObject({
      code: 'SCHLAGE_CACHE_READ_FAILED',
    });
    expect(JSON.stringify(deterministicReadFailed.snapshot)).not.toContain(
      notADirectory,
    );

    const writeFailed = await writeSchlageTokenCache({
      cacheDir: notADirectory,
      session: session(),
      now,
    });

    expect(writeFailed.status).toBe('write-failed');
    expect(writeFailed.snapshot.error).toMatchObject({
      code: 'SCHLAGE_CACHE_WRITE_FAILED',
    });
    expect(JSON.stringify(writeFailed.snapshot)).not.toContain(
      'cache-refresh-token-value',
    );
    expect(JSON.stringify(writeFailed.snapshot)).not.toContain(notADirectory);
  });

  it('creates explicit redacted rejection snapshots and safe public errors', async () => {
    const error = rejectSchlageTokenCache(
      'rejected',
      new Error('refresh_token=unsafe-cache-token-00000000000000000000'),
    );
    const snapshot = createPublicSchlageTokenCacheSnapshot({
      status: 'rejected',
      error,
    });
    const publicError = toPublicSchlageError(error);

    expect(error.code).toBe('SCHLAGE_CACHE_REJECTED');
    expect(snapshot).toMatchObject({
      enabled: true,
      status: 'rejected',
      hasSession: false,
      error: { code: 'SCHLAGE_CACHE_REJECTED' },
    });
    expect(publicError.message).toBe(
      'Schlage token cache record was rejected.',
    );
    expect(JSON.stringify(snapshot)).not.toContain('unsafe-cache-token');
    expect(JSON.stringify(publicError)).not.toContain('unsafe-cache-token');
  });
});
