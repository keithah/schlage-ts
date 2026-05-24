export {
  createPublicSchlageAuthSnapshot,
  validateSchlageCredentials,
  type PublicSchlageAuthSnapshot,
  type PublicSchlageSessionSnapshot,
  type SchlageAuthPhase,
  type SchlageCredentials,
} from './auth.js';
export {
  createPublicSchlageConfigSnapshot,
  parseSchlageConfigYaml,
  resolveSchlageConfig,
  type PublicSchlageConfigSnapshot,
  type ResolvedSchlageConfig,
  type SchlageConfigEnvironment,
  type SchlageConfigOptions,
  type SchlageConfigValueSource,
  type SchlageDiagnosticsConfig,
  type SchlageYamlConfig,
} from './config.js';
export {
  SCHLAGE_TOKEN_CACHE_FILENAME,
  createPublicSchlageTokenCacheSnapshot,
  type PublicSchlageTokenCacheSnapshot,
  type SchlageTokenCacheStatus,
} from './token-cache.js';
export {
  SchlageError,
  classifySchlageFailure,
  isSchlageError,
  toPublicSchlageError,
  wrapUnknownSchlageError,
  type PublicSchlageErrorSnapshot,
  type SchlageErrorCode,
  type SchlageFailureClassification,
} from './errors.js';
export {
  createLiveSchlageTransports,
  type LiveSchlageTransportOptions,
  type LiveSchlageTransports,
} from './live-transport.js';
import {
  SchlageAuthManager,
  assertValidSessionMaterial,
  createPublicSchlageAuthSnapshot,
  type EnsureSchlageSessionOptions,
  type PublicSchlageAuthSnapshot,
  type SchlageAuthTransport,
  type SchlageAuthTransportSession,
  type SchlageCredentials,
} from './auth.js';
import { SchlageError } from './errors.js';
import {
  createLiveSchlageTransports,
  type LiveSchlageTransports,
} from './live-transport.js';
import {
  assertValidLockId,
  createAccessCodeProtocolPayload,
  createLockSettingProtocolPayload,
  isKeypadDisabledFromLogs,
  mapProtocolOperationError,
  normalizeAccessCodeListPayload,
  normalizeCommandPayload,
  normalizeLockDiagnosticsPayload,
  normalizeLockLogListPayload,
  normalizeLockListPayload,
  normalizeLockStatusPayload,
  normalizeUserListPayload,
  normalizeWriteResultPayload,
  resolveLastChangedBy,
  type SchlageProtocolCommand,
  type SchlageProtocolOperation,
} from './protocol.js';
import {
  readSchlageTokenCache,
  writeSchlageTokenCache,
  type PublicSchlageTokenCacheSnapshot,
} from './token-cache.js';

export type SchlageLockId = string;

export interface SchlageClientAuthTransport {
  readonly signIn: (credentials: SchlageCredentials) => Promise<unknown>;
  readonly refresh: (session: unknown) => Promise<unknown>;
}

export interface SchlageClientProtocolTransport {
  readonly listLocks: (session: unknown) => Promise<unknown>;
  readonly getStatus: (
    session: unknown,
    lockId: SchlageLockId,
  ) => Promise<unknown>;
  readonly lock?: (session: unknown, lockId: SchlageLockId) => Promise<unknown>;
  readonly unlock?: (
    session: unknown,
    lockId: SchlageLockId,
  ) => Promise<unknown>;
  readonly listUsers?: (session: unknown) => Promise<unknown>;
  readonly listAccessCodes?: (
    session: unknown,
    lockId: SchlageLockId,
  ) => Promise<unknown>;
  readonly listLogs?: (
    session: unknown,
    lockId: SchlageLockId,
    options?: SchlageListLogsOptions,
  ) => Promise<unknown>;
  readonly getDiagnostics?: (
    session: unknown,
    lockId: SchlageLockId,
  ) => Promise<unknown>;
  readonly addAccessCode?: (
    session: unknown,
    lockId: SchlageLockId,
    input: SchlageAccessCodeInput,
  ) => Promise<unknown>;
  readonly updateAccessCode?: (
    session: unknown,
    lockId: SchlageLockId,
    accessCodeId: string,
    input: SchlageAccessCodeInput,
  ) => Promise<unknown>;
  readonly deleteAccessCode?: (
    session: unknown,
    lockId: SchlageLockId,
    accessCodeId: string,
  ) => Promise<unknown>;
  readonly setLockSetting?: (
    session: unknown,
    lockId: SchlageLockId,
    setting: SchlageLockSetting,
    value: boolean | number,
  ) => Promise<unknown>;
}

export interface SchlageClientOptions {
  readonly username?: string;
  readonly password?: string;
  readonly cacheDir?: string;
  readonly requestTimeoutMs?: number;
  readonly liveTransport?: boolean;
  /**
   * Test/internal seam for S02 auth-session wiring. Payloads are deliberately
   * unknown so the package entrypoint does not expose raw protocol response types.
   */
  readonly authTransport?: SchlageClientAuthTransport;
  /**
   * Test/internal seam for authenticated Schlage protocol calls. Session and
   * protocol payloads are deliberately unknown at the public option boundary.
   */
  readonly protocolTransport?: SchlageClientProtocolTransport;
}

export interface SchlageLockSummary {
  readonly id: SchlageLockId;
  readonly name: string;
  readonly subtitle?: string;
  readonly deviceType?: string;
  readonly modelName?: string;
  readonly connected?: boolean;
}

export type SchlageLockState = 'locked' | 'unlocked' | 'unknown';

export interface SchlageLockStatus {
  readonly id: SchlageLockId;
  readonly state: SchlageLockState;
  readonly batteryLevel?: number;
  readonly updatedAt?: Date;
  readonly deviceType?: string;
  readonly modelName?: string;
  readonly connected?: boolean;
  readonly isJammed?: boolean;
  readonly beeperEnabled?: boolean;
  readonly lockAndLeaveEnabled?: boolean;
  readonly autoLockTime?: number;
  readonly firmwareVersion?: string;
  readonly macAddress?: string;
  readonly lockStateMetadata?: SchlageLockStateMetadata;
  readonly users?: readonly SchlageUser[];
}

export interface SchlageCommandResult {
  readonly id: SchlageLockId;
  readonly accepted: boolean;
  readonly observedState?: SchlageLockState;
}

export interface SchlageUser {
  readonly id: string;
  readonly email: string;
  readonly name?: string;
}

export interface SchlageDaysOfWeek {
  readonly sun: boolean;
  readonly mon: boolean;
  readonly tue: boolean;
  readonly wed: boolean;
  readonly thu: boolean;
  readonly fri: boolean;
  readonly sat: boolean;
}

export type SchlageAccessCodeSchedule =
  | {
      readonly type: 'temporary';
      readonly startsAt: Date;
      readonly endsAt: Date;
    }
  | {
      readonly type: 'recurring';
      readonly daysOfWeek: SchlageDaysOfWeek;
      readonly startHour: number;
      readonly startMinute: number;
      readonly endHour: number;
      readonly endMinute: number;
    };

export interface SchlageAccessCode {
  readonly id: string;
  readonly lockId: SchlageLockId;
  readonly name: string;
  readonly code: string;
  readonly disabled: boolean;
  readonly schedule?: SchlageAccessCodeSchedule;
}

export interface SchlageAccessCodeInput {
  readonly name: string;
  readonly code: string;
  readonly disabled?: boolean;
  readonly notifyOnUse?: boolean;
  readonly schedule?: SchlageAccessCodeSchedule;
}

export interface SchlageLockLog {
  readonly lockId: SchlageLockId;
  readonly createdAt: Date;
  readonly message: string;
  readonly eventCode?: number;
  readonly accessorId?: string;
  readonly accessCodeId?: string;
}

export interface SchlageLockStateMetadata {
  readonly actionType: string;
  readonly uuid?: string;
  readonly name?: string;
}

export type SchlageLockDiagnostics = Record<string, unknown>;

export interface SchlageListLogsOptions {
  readonly limit?: number;
  readonly sortDesc?: boolean;
}

export interface SchlageWriteResult {
  readonly lockId: SchlageLockId;
  readonly accepted: boolean;
  readonly accessCodeId?: string;
}

export type SchlageLockSetting =
  | 'beeperEnabled'
  | 'lockAndLeaveEnabled'
  | 'autoLockTime';

export class SchlageNotImplementedError extends SchlageError {
  constructor(methodName: string) {
    super({
      code: 'SCHLAGE_NOT_IMPLEMENTED',
      message: `${methodName} is not implemented until the Schlage protocol port lands.`,
    });
    this.name = 'SchlageNotImplementedError';
  }
}

export class SchlageClient {
  readonly #options: SchlageClientOptions;
  #authManager: SchlageAuthManager | undefined;
  #liveTransports: LiveSchlageTransports | undefined;
  #cacheSnapshot: PublicSchlageTokenCacheSnapshot | undefined;
  #cacheLoaded = false;
  readonly #pendingCommandStates = new Map<
    SchlageLockId,
    { readonly state: Exclude<SchlageLockState, 'unknown'>; readonly expiresAt: number }
  >();

  constructor(options: SchlageClientOptions = {}) {
    this.#options = { ...options };
  }

  get options(): SchlageClientOptions {
    return { ...this.#options };
  }

  getAuthSnapshot(): PublicSchlageAuthSnapshot {
    try {
      if (this.#authManager === undefined) {
        return this.#withCacheSnapshot(
          createPublicSchlageAuthSnapshot({
            phase: 'signed-out',
            username: this.#options.username,
          }),
        );
      }

      return this.#withCacheSnapshot(this.#authManager.getSnapshot());
    } catch (error) {
      return this.#withCacheSnapshot(
        createPublicSchlageAuthSnapshot({
          phase: 'missing-credentials',
          username: this.#options.username,
          error,
        }),
      );
    }
  }

  async authCheck(): Promise<PublicSchlageAuthSnapshot> {
    return this.#ensureSession();
  }

  async refreshSession(): Promise<PublicSchlageAuthSnapshot> {
    return this.#ensureSession({ forceRefresh: true });
  }

  async listLocks(): Promise<SchlageLockSummary[]> {
    const session = await this.#ensureSessionMaterial();
    const payload = await this.#callProtocol('listLocks', (transport) =>
      transport.listLocks(session),
    );
    return normalizeLockListPayload(payload);
  }

  async getStatus(lockId: SchlageLockId): Promise<SchlageLockStatus> {
    assertValidLockId(lockId);
    const normalizedLockId = lockId.trim();
    const session = await this.#ensureSessionMaterial();
    const payload = await this.#callProtocol('getStatus', (transport) =>
      transport.getStatus(session, normalizedLockId),
    );
    return this.#applyPendingCommandState(
      normalizeLockStatusPayload(normalizedLockId, payload),
    );
  }

  async lock(lockId: SchlageLockId): Promise<SchlageCommandResult> {
    return this.#command('lock', lockId);
  }

  async unlock(lockId: SchlageLockId): Promise<SchlageCommandResult> {
    return this.#command('unlock', lockId);
  }

  async listUsers(): Promise<SchlageUser[]> {
    const session = await this.#ensureSessionMaterial();
    const payload = await this.#callProtocol('listUsers', (transport) => {
      if (transport.listUsers === undefined) {
        throw new SchlageNotImplementedError('SchlageClient.listUsers');
      }
      return transport.listUsers(session);
    });
    return normalizeUserListPayload(payload);
  }

  async listAccessCodes(lockId: SchlageLockId): Promise<SchlageAccessCode[]> {
    assertValidLockId(lockId);
    const normalizedLockId = lockId.trim();
    const session = await this.#ensureSessionMaterial();
    const payload = await this.#callProtocol('listAccessCodes', (transport) => {
      if (transport.listAccessCodes === undefined) {
        throw new SchlageNotImplementedError('SchlageClient.listAccessCodes');
      }
      return transport.listAccessCodes(session, normalizedLockId);
    });
    return normalizeAccessCodeListPayload(normalizedLockId, payload);
  }

  async listLogs(
    lockId: SchlageLockId,
    options: SchlageListLogsOptions = {},
  ): Promise<SchlageLockLog[]> {
    assertValidLockId(lockId);
    const normalizedLockId = lockId.trim();
    const session = await this.#ensureSessionMaterial();
    const payload = await this.#callProtocol('listLogs', (transport) => {
      if (transport.listLogs === undefined) {
        throw new SchlageNotImplementedError('SchlageClient.listLogs');
      }
      return transport.listLogs(session, normalizedLockId, options);
    });
    return normalizeLockLogListPayload(normalizedLockId, payload);
  }

  async getDiagnostics(
    lockId: SchlageLockId,
  ): Promise<SchlageLockDiagnostics> {
    assertValidLockId(lockId);
    const normalizedLockId = lockId.trim();
    const session = await this.#ensureSessionMaterial();
    const payload = await this.#callProtocol('getDiagnostics', (transport) => {
      if (transport.getDiagnostics === undefined) {
        throw new SchlageNotImplementedError('SchlageClient.getDiagnostics');
      }
      return transport.getDiagnostics(session, normalizedLockId);
    });
    return normalizeLockDiagnosticsPayload(payload);
  }

  async keypadDisabled(
    lockId: SchlageLockId,
    logs?: readonly SchlageLockLog[],
  ): Promise<boolean> {
    assertValidLockId(lockId);
    return isKeypadDisabledFromLogs(logs ?? (await this.listLogs(lockId)));
  }

  async lastChangedBy(lockId: SchlageLockId): Promise<string | null> {
    return resolveLastChangedBy(await this.getStatus(lockId)) ?? null;
  }

  async addAccessCode(
    lockId: SchlageLockId,
    input: SchlageAccessCodeInput,
  ): Promise<SchlageWriteResult> {
    assertValidLockId(lockId);
    const normalizedLockId = lockId.trim();
    createAccessCodeProtocolPayload(input);
    const session = await this.#ensureSessionMaterial();
    const payload = await this.#callProtocol('addAccessCode', (transport) => {
      if (transport.addAccessCode === undefined) {
        throw new SchlageNotImplementedError('SchlageClient.addAccessCode');
      }
      return transport.addAccessCode(session, normalizedLockId, input);
    });
    return normalizeWriteResultPayload(normalizedLockId, payload);
  }

  async updateAccessCode(
    lockId: SchlageLockId,
    accessCodeId: string,
    input: SchlageAccessCodeInput,
  ): Promise<SchlageWriteResult> {
    assertValidLockId(lockId);
    assertValidLockId(accessCodeId);
    const normalizedLockId = lockId.trim();
    const normalizedAccessCodeId = accessCodeId.trim();
    createAccessCodeProtocolPayload(input, normalizedAccessCodeId);
    const session = await this.#ensureSessionMaterial();
    const payload = await this.#callProtocol(
      'updateAccessCode',
      (transport) => {
        if (transport.updateAccessCode === undefined) {
          throw new SchlageNotImplementedError(
            'SchlageClient.updateAccessCode',
          );
        }
        return transport.updateAccessCode(
          session,
          normalizedLockId,
          normalizedAccessCodeId,
          input,
        );
      },
    );
    return normalizeWriteResultPayload(normalizedLockId, payload);
  }

  async deleteAccessCode(
    lockId: SchlageLockId,
    accessCodeId: string,
  ): Promise<SchlageWriteResult> {
    assertValidLockId(lockId);
    assertValidLockId(accessCodeId);
    const normalizedLockId = lockId.trim();
    const normalizedAccessCodeId = accessCodeId.trim();
    const session = await this.#ensureSessionMaterial();
    const payload = await this.#callProtocol(
      'deleteAccessCode',
      (transport) => {
        if (transport.deleteAccessCode === undefined) {
          throw new SchlageNotImplementedError(
            'SchlageClient.deleteAccessCode',
          );
        }
        return transport.deleteAccessCode(
          session,
          normalizedLockId,
          normalizedAccessCodeId,
        );
      },
    );
    return normalizeWriteResultPayload(normalizedLockId, payload);
  }

  async setBeeper(
    lockId: SchlageLockId,
    enabled: boolean,
  ): Promise<SchlageWriteResult> {
    return this.#setLockSetting(lockId, 'beeperEnabled', enabled);
  }

  async setLockAndLeave(
    lockId: SchlageLockId,
    enabled: boolean,
  ): Promise<SchlageWriteResult> {
    return this.#setLockSetting(lockId, 'lockAndLeaveEnabled', enabled);
  }

  async setAutoLockTime(
    lockId: SchlageLockId,
    seconds: number,
  ): Promise<SchlageWriteResult> {
    return this.#setLockSetting(lockId, 'autoLockTime', seconds);
  }

  async #ensureSession(
    options: EnsureSchlageSessionOptions = {},
  ): Promise<PublicSchlageAuthSnapshot> {
    const manager = await this.#getAuthManager();
    return this.#withCacheSnapshot(await manager.ensureSession(options));
  }

  async #ensureSessionMaterial(
    options: EnsureSchlageSessionOptions = {},
  ): Promise<SchlageAuthTransportSession> {
    const manager = await this.#getAuthManager();
    return manager.ensureSessionMaterial(options);
  }

  async #callProtocol(
    operation: SchlageProtocolOperation,
    call: (transport: SchlageClientProtocolTransport) => Promise<unknown>,
  ): Promise<unknown> {
    const transport =
      this.#options.protocolTransport ??
      this.#getLiveTransports()?.protocolTransport;
    if (transport === undefined) {
      throw new SchlageNotImplementedError(`SchlageClient.${operation}`);
    }

    try {
      return await call(transport);
    } catch (error) {
      throw mapProtocolOperationError(error, operation);
    }
  }

  async #command(
    command: SchlageProtocolCommand,
    lockId: SchlageLockId,
  ): Promise<SchlageCommandResult> {
    assertValidLockId(lockId);
    const normalizedLockId = lockId.trim();
    const session = await this.#ensureSessionMaterial();
    const payload = await this.#callProtocol(command, (transport) => {
      const call = transport[command];
      if (call === undefined) {
        throw new SchlageNotImplementedError(`SchlageClient.${command}`);
      }

      return call(session, normalizedLockId);
    });
    const result = normalizeCommandPayload(normalizedLockId, payload);
    if (
      result.accepted &&
      (result.observedState === 'locked' || result.observedState === 'unlocked')
    ) {
      this.#pendingCommandStates.set(normalizedLockId, {
        state: result.observedState,
        expiresAt: Date.now() + 15_000,
      });
    }
    return result;
  }

  #applyPendingCommandState(status: SchlageLockStatus): SchlageLockStatus {
    const pending = this.#pendingCommandStates.get(status.id);
    if (pending === undefined) {
      return status;
    }

    if (Date.now() > pending.expiresAt) {
      this.#pendingCommandStates.delete(status.id);
      return status;
    }

    if (status.state === pending.state) {
      this.#pendingCommandStates.delete(status.id);
      return status;
    }

    return { ...status, state: pending.state };
  }

  async #setLockSetting(
    lockId: SchlageLockId,
    setting: SchlageLockSetting,
    value: boolean | number,
  ): Promise<SchlageWriteResult> {
    assertValidLockId(lockId);
    const normalizedLockId = lockId.trim();
    createLockSettingProtocolPayload(setting, value);
    const session = await this.#ensureSessionMaterial();
    const payload = await this.#callProtocol('setLockSetting', (transport) => {
      if (transport.setLockSetting === undefined) {
        throw new SchlageNotImplementedError('SchlageClient.setLockSetting');
      }
      return transport.setLockSetting(
        session,
        normalizedLockId,
        setting,
        value,
      );
    });
    return normalizeWriteResultPayload(normalizedLockId, payload);
  }

  async #getAuthManager(): Promise<SchlageAuthManager> {
    if (this.#authManager !== undefined) {
      return this.#authManager;
    }

    const initialSession = await this.#readInitialCachedSession();
    this.#authManager = new SchlageAuthManager({
      credentials: {
        username: this.#options.username ?? '',
        password: this.#options.password ?? '',
      },
      transport: createAuthManagerTransport(
        this.#options.authTransport ??
          this.#getLiveTransports()?.authTransport ??
          createMissingAuthTransport('SchlageClient.authCheck'),
      ),
      ...(initialSession === undefined ? {} : { initialSession }),
      onSessionUpdated: async (session) => {
        await this.#writeUpdatedSession(session);
      },
    });

    return this.#authManager;
  }

  async #readInitialCachedSession(): Promise<
    SchlageAuthTransportSession | undefined
  > {
    if (this.#cacheLoaded || this.#options.cacheDir === undefined) {
      return undefined;
    }

    this.#cacheLoaded = true;
    const result = await readSchlageTokenCache({
      cacheDir: this.#options.cacheDir,
    });
    this.#cacheSnapshot = result.snapshot;

    if (result.status === 'hit' || result.status === 'expired') {
      return result.session;
    }

    return undefined;
  }

  async #writeUpdatedSession(
    session: SchlageAuthTransportSession,
  ): Promise<void> {
    if (this.#options.cacheDir === undefined) {
      return;
    }

    const result = await writeSchlageTokenCache({
      cacheDir: this.#options.cacheDir,
      session,
    });
    this.#cacheSnapshot = result.snapshot;
  }

  #withCacheSnapshot(
    snapshot: PublicSchlageAuthSnapshot,
  ): PublicSchlageAuthSnapshot {
    if (this.#cacheSnapshot === undefined) {
      return snapshot;
    }

    return {
      ...snapshot,
      cache: this.#cacheSnapshot,
    };
  }

  #getLiveTransports(): LiveSchlageTransports | undefined {
    if (
      this.#options.liveTransport === false ||
      this.#options.authTransport !== undefined ||
      this.#options.protocolTransport !== undefined
    ) {
      return undefined;
    }

    this.#liveTransports ??= createLiveSchlageTransports({
      timeoutMs: this.#options.requestTimeoutMs,
    });
    return this.#liveTransports;
  }
}

function createAuthManagerTransport(
  transport: SchlageClientAuthTransport,
): SchlageAuthTransport {
  return {
    signIn: async (credentials) => {
      const result = await transport.signIn(credentials);
      assertValidSessionMaterial(result);
      return result;
    },
    refresh: async (session) => {
      const result = await transport.refresh(session);
      assertValidSessionMaterial(result);
      return result;
    },
  };
}

function createMissingAuthTransport(
  methodName: string,
): SchlageClientAuthTransport {
  return {
    async signIn() {
      throw new SchlageNotImplementedError(methodName);
    },
    async refresh() {
      throw new SchlageNotImplementedError(methodName);
    },
  };
}
