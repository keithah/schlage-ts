import { mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';

export const SCHLAGE_COMMAND_STATE_CACHE_FILENAME =
  'schlage-command-state-cache.json';

export interface SchlageCachedCommandState {
  readonly state: 'locked' | 'unlocked';
  readonly expiresAt: Date;
}

export interface SchlageCommandStateCacheOptions {
  readonly cacheDir: string;
  readonly lockId: string;
  readonly now?: Date;
}

export interface WriteSchlageCommandStateCacheOptions
  extends SchlageCommandStateCacheOptions {
  readonly state: SchlageCachedCommandState;
}

interface SerializedCommandStateCache {
  readonly locks: Record<
    string,
    {
      readonly state: 'locked' | 'unlocked';
      readonly expiresAt: string;
    }
  >;
}

export async function readSchlageCommandStateCache(
  options: SchlageCommandStateCacheOptions,
): Promise<SchlageCachedCommandState | undefined> {
  const cache = await readCache(options.cacheDir);
  const cached = cache.locks[options.lockId];
  if (cached === undefined) {
    return undefined;
  }

  const state = normalizeCachedCommandState(cached);
  if (state === undefined) {
    return undefined;
  }

  if (state.expiresAt.getTime() <= (options.now ?? new Date()).getTime()) {
    return undefined;
  }

  return state;
}

export async function writeSchlageCommandStateCache(
  options: WriteSchlageCommandStateCacheOptions,
): Promise<void> {
  const cache = await readCache(options.cacheDir);
  await writeCache(options.cacheDir, {
    locks: {
      ...cache.locks,
      [options.lockId]: {
        state: options.state.state,
        expiresAt: options.state.expiresAt.toISOString(),
      },
    },
  });
}

export async function clearSchlageCommandStateCache(
  options: SchlageCommandStateCacheOptions,
): Promise<void> {
  const cache = await readCache(options.cacheDir);
  const locks = { ...cache.locks };
  delete locks[options.lockId];
  await writeCache(options.cacheDir, { locks });
}

function commandStateCachePath(cacheDir: string): string {
  return join(cacheDir, SCHLAGE_COMMAND_STATE_CACHE_FILENAME);
}

async function readCache(
  cacheDir: string,
): Promise<SerializedCommandStateCache> {
  try {
    const parsed = JSON.parse(
      await readFile(commandStateCachePath(cacheDir), 'utf8'),
    );
    if (!isRecord(parsed) || !isRecord(parsed.locks)) {
      return { locks: {} };
    }

    const locks: SerializedCommandStateCache['locks'] = {};
    for (const [lockId, value] of Object.entries(parsed.locks)) {
      const state = normalizeCachedCommandState(value);
      if (state !== undefined) {
        locks[lockId] = {
          state: state.state,
          expiresAt: state.expiresAt.toISOString(),
        };
      }
    }
    return { locks };
  } catch {
    return { locks: {} };
  }
}

async function writeCache(
  cacheDir: string,
  cache: SerializedCommandStateCache,
): Promise<void> {
  const cachePath = commandStateCachePath(cacheDir);
  const tempPath = `${cachePath}.${process.pid}.${Date.now()}.tmp`;

  try {
    await mkdir(dirname(cachePath), { recursive: true, mode: 0o700 });
    await writeFile(tempPath, `${JSON.stringify(cache, null, 2)}\n`, {
      encoding: 'utf8',
      mode: 0o600,
    });
    await rename(tempPath, cachePath);
  } catch (error) {
    await rm(tempPath, { force: true }).catch(() => undefined);
    throw error;
  }
}

function normalizeCachedCommandState(
  value: unknown,
): SchlageCachedCommandState | undefined {
  if (!isRecord(value)) {
    return undefined;
  }

  if (value.state !== 'locked' && value.state !== 'unlocked') {
    return undefined;
  }

  if (typeof value.expiresAt !== 'string') {
    return undefined;
  }

  const expiresAt = new Date(value.expiresAt);
  if (Number.isNaN(expiresAt.getTime())) {
    return undefined;
  }

  return { state: value.state, expiresAt };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
