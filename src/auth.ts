import {
  SchlageError,
  classifySchlageFailure,
  toPublicSchlageError,
  type PublicSchlageErrorSnapshot,
} from './errors.js';
import type { PublicSchlageTokenCacheSnapshot } from './token-cache.js';

export type SchlageAuthPhase =
  | 'missing-credentials'
  | 'signed-out'
  | 'authenticating'
  | 'authenticated'
  | 'refreshing'
  | 'expired'
  | 'failed';

export interface SchlageCredentials {
  readonly username: string;
  readonly password: string;
}

export interface PublicSchlageSessionSnapshot {
  readonly hasSession: boolean;
  readonly status: 'none' | 'active' | 'expired' | 'malformed';
  readonly expiresAt?: string;
  readonly refreshedAt?: string;
}

export interface PublicSchlageAuthSnapshot {
  readonly phase: SchlageAuthPhase;
  readonly username: string | null;
  readonly authenticated: boolean;
  readonly session: PublicSchlageSessionSnapshot;
  readonly cache?: PublicSchlageTokenCacheSnapshot;
  readonly error?: PublicSchlageErrorSnapshot;
}

export interface SchlageAuthTransport {
  readonly signIn: (
    credentials: SchlageCredentials,
  ) => Promise<SchlageAuthTransportResult>;
  readonly refresh: (
    session: SchlageAuthTransportSession,
  ) => Promise<SchlageAuthTransportResult>;
}

export interface SchlageAuthManagerOptions {
  readonly credentials: SchlageCredentials;
  readonly transport: SchlageAuthTransport;
  readonly now?: () => Date;
  readonly initialSession?: SchlageAuthTransportSession;
  readonly onSessionUpdated?: (
    session: SchlageAuthTransportSession,
  ) => Promise<void> | void;
}

export interface EnsureSchlageSessionOptions {
  readonly forceRefresh?: boolean;
}

interface SchlageSessionMaterial {
  readonly accessToken: string;
  readonly refreshToken: string;
  readonly expiresAt: Date;
  readonly refreshedAt?: Date;
  readonly accountId?: string;
}

export type SchlageAuthTransportSession = Readonly<SchlageSessionMaterial>;
export type SchlageAuthTransportResult = Readonly<SchlageSessionMaterial>;

export interface CreateAuthSnapshotInput {
  readonly phase?: SchlageAuthPhase;
  readonly username?: string | null;
  readonly session?: unknown;
  readonly cache?: PublicSchlageTokenCacheSnapshot;
  readonly error?: unknown;
  readonly now?: Date;
}

export function validateSchlageCredentials(input: {
  readonly username?: string | null;
  readonly password?: string | null;
}): SchlageCredentials {
  const username = input.username?.trim() ?? '';
  const password = input.password?.trim() ?? '';

  if (username.length === 0 || password.length === 0) {
    throw new SchlageError({
      code: 'SCHLAGE_CONFIG_MISSING_CREDENTIALS',
      message: 'Schlage username and password are required.',
    });
  }

  return { username, password };
}

export class SchlageAuthManager {
  readonly #credentials: SchlageCredentials;
  readonly #transport: SchlageAuthTransport;
  readonly #now: () => Date;
  readonly #onSessionUpdated:
    | ((session: SchlageAuthTransportSession) => Promise<void> | void)
    | undefined;
  #session: SchlageAuthTransportSession | undefined;
  #sessionSource: 'none' | 'cache' | 'auth' = 'none';
  #phase: SchlageAuthPhase = 'signed-out';
  #error: SchlageError | undefined;

  constructor(options: SchlageAuthManagerOptions) {
    this.#credentials = validateSchlageCredentials(options.credentials);
    this.#transport = options.transport;
    this.#now = options.now ?? (() => new Date());
    this.#onSessionUpdated = options.onSessionUpdated;

    if (options.initialSession !== undefined) {
      this.#session = normalizeSessionMaterial(options.initialSession);
      this.#sessionSource = 'cache';
      this.#phase = isExpired(this.#session, this.#now())
        ? 'expired'
        : 'authenticated';
    }
  }

  getSnapshot(): PublicSchlageAuthSnapshot {
    return createPublicSchlageAuthSnapshot({
      phase: this.#phase,
      username: this.#credentials.username,
      session: this.#session,
      error: this.#error,
      now: this.#now(),
    });
  }

  async ensureSession(
    options: EnsureSchlageSessionOptions = {},
  ): Promise<PublicSchlageAuthSnapshot> {
    if (
      this.#session !== undefined &&
      !options.forceRefresh &&
      !isExpired(this.#session, this.#now())
    ) {
      this.#phase = 'authenticated';
      this.#error = undefined;
      return this.getSnapshot();
    }

    if (this.#session === undefined) {
      return this.#authenticate();
    }

    return this.#refresh();
  }

  async ensureSessionMaterial(
    options: EnsureSchlageSessionOptions = {},
  ): Promise<SchlageAuthTransportSession> {
    await this.ensureSession(options);
    assertValidSessionMaterial(this.#session);
    return this.#session;
  }

  async #authenticate(): Promise<PublicSchlageAuthSnapshot> {
    this.#phase = 'authenticating';
    this.#error = undefined;

    try {
      const session = await this.#transport.signIn(this.#credentials);
      assertValidSessionMaterial(session);
      this.#session = normalizeSessionMaterial(session);
      this.#sessionSource = 'auth';
      await this.#persistSession();
      this.#phase = 'authenticated';
      return this.getSnapshot();
    } catch (error) {
      throw this.#fail(mapAuthOperationError(error, 'authenticate'));
    }
  }

  async #refresh(): Promise<PublicSchlageAuthSnapshot> {
    this.#phase = 'refreshing';
    this.#error = undefined;

    try {
      assertValidSessionMaterial(this.#session);
      const session = await this.#transport.refresh(this.#session);
      assertValidSessionMaterial(session);
      this.#session = normalizeSessionMaterial(session, this.#now());
      this.#sessionSource = 'auth';
      await this.#persistSession();
      this.#phase = 'authenticated';
      return this.getSnapshot();
    } catch (error) {
      if (this.#sessionSource === 'cache') {
        this.#session = undefined;
        this.#sessionSource = 'none';
        return this.#authenticate();
      }
      throw this.#fail(mapAuthOperationError(error, 'refresh'));
    }
  }

  async #persistSession(): Promise<void> {
    if (this.#session !== undefined) {
      await this.#onSessionUpdated?.(this.#session);
    }
  }

  #fail(error: SchlageError): SchlageError {
    this.#phase = 'failed';
    this.#error = error;
    return error;
  }
}

export function createPublicSchlageAuthSnapshot(
  input: CreateAuthSnapshotInput = {},
): PublicSchlageAuthSnapshot {
  const session = createPublicSessionSnapshot(
    input.session,
    input.now ?? new Date(),
  );
  const phase = input.phase ?? derivePhase(session, input.error);

  return {
    phase,
    username: redactPrincipal(input.username),
    authenticated: phase === 'authenticated' && session.status === 'active',
    session,
    ...(input.cache === undefined ? {} : { cache: input.cache }),
    ...(input.error === undefined
      ? {}
      : { error: toPublicSchlageError(input.error) }),
  };
}

export function assertValidSessionMaterial(
  session: unknown,
): asserts session is SchlageAuthTransportSession {
  if (!isSessionMaterial(session)) {
    throw new SchlageError({
      code: 'SCHLAGE_AUTH_PROTOCOL',
      message: 'Schlage auth response did not include a usable session.',
      retryable: true,
    });
  }
}

function mapAuthOperationError(
  error: unknown,
  operation: 'authenticate' | 'refresh',
): SchlageError {
  if (error instanceof SchlageError) {
    return error;
  }

  const classification = classifySchlageFailure(error);

  return new SchlageError({
    code:
      classification.code === 'SCHLAGE_UNKNOWN_ERROR'
        ? 'SCHLAGE_AUTH_FAILED'
        : classification.code,
    message: `Schlage ${operation} operation failed.`,
    cause: error,
    retryable:
      classification.code === 'SCHLAGE_UNKNOWN_ERROR'
        ? true
        : classification.retryable,
  });
}

function normalizeSessionMaterial(
  session: SchlageAuthTransportSession,
  refreshedAt?: Date,
): SchlageAuthTransportSession {
  const expiresAt = coerceDate(session.expiresAt);
  const existingRefreshedAt = coerceDate(session.refreshedAt);

  if (expiresAt === undefined) {
    throw new SchlageError({
      code: 'SCHLAGE_AUTH_PROTOCOL',
      message: 'Schlage auth response did not include a usable session.',
      retryable: true,
    });
  }

  return {
    accessToken: session.accessToken,
    refreshToken: session.refreshToken,
    expiresAt,
    ...(existingRefreshedAt === undefined && refreshedAt === undefined
      ? {}
      : { refreshedAt: existingRefreshedAt ?? refreshedAt }),
    ...(session.accountId === undefined
      ? {}
      : { accountId: session.accountId }),
  };
}

function createPublicSessionSnapshot(
  session: unknown,
  now: Date,
): PublicSchlageSessionSnapshot {
  if (session === undefined || session === null) {
    return { hasSession: false, status: 'none' };
  }

  if (!isSessionLike(session)) {
    return { hasSession: false, status: 'malformed' };
  }

  const expiresAt = coerceDate(session.expiresAt);
  const refreshedAt = coerceDate(session.refreshedAt);

  if (expiresAt === undefined) {
    return { hasSession: false, status: 'malformed' };
  }

  return {
    hasSession: true,
    status: expiresAt.getTime() <= now.getTime() ? 'expired' : 'active',
    expiresAt: expiresAt.toISOString(),
    ...(refreshedAt === undefined
      ? {}
      : { refreshedAt: refreshedAt.toISOString() }),
  };
}

function derivePhase(
  session: PublicSchlageSessionSnapshot,
  error: unknown,
): SchlageAuthPhase {
  if (error !== undefined) {
    return 'failed';
  }

  if (session.status === 'active') {
    return 'authenticated';
  }

  if (session.status === 'expired') {
    return 'expired';
  }

  return 'signed-out';
}

function redactPrincipal(username: string | null | undefined): string | null {
  if (
    username === undefined ||
    username === null ||
    username.trim().length === 0
  ) {
    return null;
  }

  return '[REDACTED_USERNAME]';
}

function isSessionMaterial(
  session: unknown,
): session is SchlageSessionMaterial {
  if (!isSessionLike(session)) {
    return false;
  }

  return (
    typeof session.accessToken === 'string' &&
    session.accessToken.length > 0 &&
    typeof session.refreshToken === 'string' &&
    session.refreshToken.length > 0 &&
    coerceDate(session.expiresAt) !== undefined
  );
}

function isSessionLike(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function isExpired(session: SchlageAuthTransportSession, now: Date): boolean {
  return session.expiresAt.getTime() <= now.getTime();
}

function coerceDate(value: unknown): Date | undefined {
  if (value instanceof Date && !Number.isNaN(value.getTime())) {
    return value;
  }

  if (typeof value === 'string' || typeof value === 'number') {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? undefined : date;
  }

  return undefined;
}
