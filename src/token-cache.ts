import { mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import {
  assertValidSessionMaterial,
  createPublicSchlageAuthSnapshot,
  type PublicSchlageSessionSnapshot,
  type SchlageAuthTransportSession,
} from './auth.js';
import {
  SchlageError,
  toPublicSchlageError,
  type PublicSchlageErrorSnapshot,
} from './errors.js';

export const SCHLAGE_TOKEN_CACHE_FILENAME = 'schlage-session-cache.json';

export type SchlageTokenCacheStatus =
  | 'missing'
  | 'hit'
  | 'expired'
  | 'malformed'
  | 'rejected'
  | 'read-failed'
  | 'write-failed';

export type SchlageTokenCacheSession = SchlageAuthTransportSession;

export interface PublicSchlageTokenCacheSnapshot {
  readonly enabled: boolean;
  readonly status: SchlageTokenCacheStatus;
  readonly hasSession: boolean;
  readonly expiresAt?: string;
  readonly refreshedAt?: string;
  readonly error?: PublicSchlageErrorSnapshot;
}

export interface SchlageTokenCacheOptions {
  readonly cacheDir: string;
  readonly now?: Date;
}

export interface WriteSchlageTokenCacheOptions extends SchlageTokenCacheOptions {
  readonly session: SchlageTokenCacheSession;
}

export type SchlageTokenCacheReadResult =
  | {
      readonly status: 'hit' | 'expired';
      readonly session: SchlageTokenCacheSession;
      readonly snapshot: PublicSchlageTokenCacheSnapshot;
    }
  | {
      readonly status: 'missing' | 'malformed' | 'rejected' | 'read-failed';
      readonly snapshot: PublicSchlageTokenCacheSnapshot;
      readonly error?: SchlageError;
    };

export type SchlageTokenCacheWriteResult =
  | {
      readonly status: 'hit';
      readonly snapshot: PublicSchlageTokenCacheSnapshot;
    }
  | {
      readonly status: 'write-failed';
      readonly snapshot: PublicSchlageTokenCacheSnapshot;
      readonly error: SchlageError;
    };

export async function readSchlageTokenCache(
  options: SchlageTokenCacheOptions,
): Promise<SchlageTokenCacheReadResult> {
  const cachePath = tokenCachePath(options.cacheDir);
  const now = options.now ?? new Date();
  let raw: string;

  try {
    raw = await readFile(cachePath, 'utf8');
  } catch (error) {
    if (isNodeError(error) && error.code === 'ENOENT') {
      return {
        status: 'missing',
        snapshot: createPublicSchlageTokenCacheSnapshot({ status: 'missing' }),
      };
    }

    const cacheError = cacheFailure('read-failed', error);
    return {
      status: 'read-failed',
      error: cacheError,
      snapshot: createPublicSchlageTokenCacheSnapshot({
        status: 'read-failed',
        error: cacheError,
      }),
    };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    const cacheError = cacheFailure('malformed', error);
    return {
      status: 'malformed',
      error: cacheError,
      snapshot: createPublicSchlageTokenCacheSnapshot({
        status: 'malformed',
        error: cacheError,
      }),
    };
  }

  try {
    assertValidSessionMaterial(parsed);
    const session = normalizeCacheSession(parsed);
    const status = isExpired(session, now) ? 'expired' : 'hit';
    return {
      status,
      session,
      snapshot: createPublicSchlageTokenCacheSnapshot({ status, session, now }),
    };
  } catch (error) {
    const cacheError = cacheFailure('rejected', error);
    return {
      status: 'rejected',
      error: cacheError,
      snapshot: createPublicSchlageTokenCacheSnapshot({
        status: 'rejected',
        error: cacheError,
      }),
    };
  }
}

export async function writeSchlageTokenCache(
  options: WriteSchlageTokenCacheOptions,
): Promise<SchlageTokenCacheWriteResult> {
  const cachePath = tokenCachePath(options.cacheDir);
  const tempPath = `${cachePath}.${process.pid}.${Date.now()}.tmp`;

  try {
    assertValidSessionMaterial(options.session);
    const session = normalizeCacheSession(options.session);
    const payload = `${JSON.stringify(serializeCacheSession(session), null, 2)}\n`;

    await mkdir(dirname(cachePath), { recursive: true, mode: 0o700 });
    await writeFile(tempPath, payload, { encoding: 'utf8', mode: 0o600 });
    await rename(tempPath, cachePath);

    return {
      status: 'hit',
      snapshot: createPublicSchlageTokenCacheSnapshot({
        status: 'hit',
        session,
        now: options.now,
      }),
    };
  } catch (error) {
    await rm(tempPath, { force: true }).catch(() => undefined);
    const cacheError = cacheFailure('write-failed', error);
    return {
      status: 'write-failed',
      error: cacheError,
      snapshot: createPublicSchlageTokenCacheSnapshot({
        status: 'write-failed',
        error: cacheError,
      }),
    };
  }
}

export function rejectSchlageTokenCache(
  status: Extract<
    SchlageTokenCacheStatus,
    'malformed' | 'rejected' | 'read-failed' | 'write-failed'
  >,
  cause?: unknown,
): SchlageError {
  return cacheFailure(status, cause);
}

export function createPublicSchlageTokenCacheSnapshot(input: {
  readonly status: SchlageTokenCacheStatus;
  readonly session?: unknown;
  readonly error?: unknown;
  readonly now?: Date;
}): PublicSchlageTokenCacheSnapshot {
  const sessionSnapshot = createPublicSchlageAuthSnapshot({
    session: input.session,
    now: input.now,
  }).session;
  const safeSession = pickSafeSessionFields(input.status, sessionSnapshot);

  return {
    enabled: true,
    status: input.status,
    ...safeSession,
    ...(input.error === undefined
      ? {}
      : { error: toPublicSchlageError(input.error) }),
  };
}

export function tokenCachePath(cacheDir: string): string {
  return join(cacheDir, SCHLAGE_TOKEN_CACHE_FILENAME);
}

function pickSafeSessionFields(
  status: SchlageTokenCacheStatus,
  session: PublicSchlageSessionSnapshot,
): Pick<
  PublicSchlageTokenCacheSnapshot,
  'hasSession' | 'expiresAt' | 'refreshedAt'
> {
  if ((status === 'hit' || status === 'expired') && session.hasSession) {
    return {
      hasSession: true,
      ...(session.expiresAt === undefined
        ? {}
        : { expiresAt: session.expiresAt }),
      ...(session.refreshedAt === undefined
        ? {}
        : { refreshedAt: session.refreshedAt }),
    };
  }

  return { hasSession: false };
}

function normalizeCacheSession(
  session: SchlageAuthTransportSession,
): SchlageTokenCacheSession {
  return {
    accessToken: session.accessToken,
    refreshToken: session.refreshToken,
    expiresAt: coerceDate(session.expiresAt),
    ...(coerceOptionalDate(session.refreshedAt) === undefined
      ? {}
      : { refreshedAt: coerceOptionalDate(session.refreshedAt) }),
    ...(session.accountId === undefined
      ? {}
      : { accountId: session.accountId }),
  };
}

function serializeCacheSession(
  session: SchlageTokenCacheSession,
): Record<string, string> {
  return {
    accessToken: session.accessToken,
    refreshToken: session.refreshToken,
    expiresAt: session.expiresAt.toISOString(),
    ...(session.refreshedAt === undefined
      ? {}
      : { refreshedAt: session.refreshedAt.toISOString() }),
    ...(session.accountId === undefined
      ? {}
      : { accountId: session.accountId }),
  };
}

function isExpired(session: SchlageTokenCacheSession, now: Date): boolean {
  return session.expiresAt.getTime() <= now.getTime();
}

function coerceDate(value: Date | string | number): Date {
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) {
    throw new SchlageError({
      code: 'SCHLAGE_CACHE_REJECTED',
      message: 'Schlage token cache record was rejected.',
    });
  }
  return date;
}

function coerceOptionalDate(
  value: Date | string | number | undefined,
): Date | undefined {
  return value === undefined ? undefined : coerceDate(value);
}

function cacheFailure(
  status: Extract<
    SchlageTokenCacheStatus,
    'malformed' | 'rejected' | 'read-failed' | 'write-failed'
  >,
  cause?: unknown,
): SchlageError {
  switch (status) {
    case 'malformed':
      return new SchlageError({
        code: 'SCHLAGE_CACHE_MALFORMED',
        message: 'Schlage token cache record could not be parsed.',
        cause,
      });
    case 'rejected':
      return new SchlageError({
        code: 'SCHLAGE_CACHE_REJECTED',
        message: 'Schlage token cache record was rejected.',
        cause,
      });
    case 'read-failed':
      return new SchlageError({
        code: 'SCHLAGE_CACHE_READ_FAILED',
        message: 'Schlage token cache file could not be read.',
        cause,
        retryable: true,
      });
    case 'write-failed':
      return new SchlageError({
        code: 'SCHLAGE_CACHE_WRITE_FAILED',
        message: 'Schlage token cache file could not be written.',
        cause,
        retryable: true,
      });
  }
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return typeof error === 'object' && error !== null && 'code' in error;
}
