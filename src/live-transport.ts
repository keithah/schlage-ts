import { createHmac, createHash, randomBytes, hkdfSync } from 'node:crypto';
import type {
  SchlageAuthTransportSession,
  SchlageCredentials,
} from './auth.js';
import { SchlageError, classifySchlageFailure } from './errors.js';
import {
  createAccessCodeProtocolPayload,
  createLockSettingProtocolPayload,
} from './protocol.js';
import type {
  SchlageAccessCodeInput,
  SchlageClientAuthTransport,
  SchlageClientProtocolTransport,
  SchlageListLogsOptions,
  SchlageLockSetting,
  SchlageLockState,
} from './index.js';

const API_BASE_URL = 'https://api.allegion.yonomi.cloud/v1';
const USER_POOL_REGION = 'us-west-2';
const COGNITO_ENDPOINT = `https://cognito-idp.${USER_POOL_REGION}.amazonaws.com/`;
const COGNITO_TARGET_PREFIX = 'AWSCognitoIdentityProviderService';
const DEFAULT_TIMEOUT_MS = 30_000;
const INFO_BITS = Buffer.from('Caldera Derived Key', 'utf8');
const HEX_N =
  'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1' +
  '29024E088A67CC74020BBEA63B139B22514A08798E3404DD' +
  'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245' +
  'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' +
  'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D' +
  'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F' +
  '83655D23DCA3AD961C62F356208552BB9ED529077096966D' +
  '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' +
  'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9' +
  'DE2BCBF6955817183995497CEA956AE515D2261898FA0510' +
  '15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64' +
  'ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7' +
  'ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6' +
  'BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C' +
  'BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31' +
  '43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF';
const N = BigInt(`0x${HEX_N}`);
const G = 2n;
const K = BigInt(`0x${hashHex(Buffer.concat([padHex(N), padHex(G)]))}`);

export interface LiveSchlageTransportOptions {
  readonly fetch?: typeof fetch;
  readonly timeoutMs?: number;
  readonly now?: () => Date;
  readonly randomBytes?: (size: number) => Buffer;
  readonly apiKey?: string;
  readonly clientId?: string;
  readonly clientSecret?: string;
  readonly userPoolId?: string;
}

export interface LiveSchlageTransports {
  readonly authTransport: SchlageClientAuthTransport;
  readonly protocolTransport: SchlageClientProtocolTransport;
}

interface CognitoAuthResult {
  readonly AccessToken?: unknown;
  readonly RefreshToken?: unknown;
  readonly ExpiresIn?: unknown;
}

export function createLiveSchlageTransports(
  options: LiveSchlageTransportOptions = {},
): LiveSchlageTransports {
  let runtime: Runtime | undefined;
  const getRuntime = (): Runtime => {
    runtime ??= createRuntime(options);
    return runtime;
  };
  return {
    authTransport: {
      signIn: (credentials) => signIn(credentials, getRuntime()),
      refresh: (session) => refresh(session, getRuntime()),
    },
    protocolTransport: {
      listLocks: (session) => listLocks(session, getRuntime()),
      getStatus: (session, lockId) => getStatus(session, lockId, getRuntime()),
      lock: (session, lockId) =>
        setLockState(session, lockId, 'lock', getRuntime()),
      unlock: (session, lockId) =>
        setLockState(session, lockId, 'unlock', getRuntime()),
      listUsers: (session) => listUsers(session, getRuntime()),
      listAccessCodes: (session, lockId) =>
        listAccessCodes(session, lockId, getRuntime()),
      listLogs: (session, lockId, options) =>
        listLogs(session, lockId, options, getRuntime()),
      getDiagnostics: (session, lockId) =>
        getDiagnostics(session, lockId, getRuntime()),
      addAccessCode: (session, lockId, input) =>
        addAccessCode(session, lockId, input, getRuntime()),
      updateAccessCode: (session, lockId, accessCodeId, input) =>
        updateAccessCode(session, lockId, accessCodeId, input, getRuntime()),
      deleteAccessCode: (session, lockId, accessCodeId) =>
        deleteAccessCode(session, lockId, accessCodeId, getRuntime()),
      setLockSetting: (session, lockId, setting, value) =>
        setLockSetting(session, lockId, setting, value, getRuntime()),
    },
  };
}

async function signIn(
  credentials: SchlageCredentials,
  runtime: Runtime,
): Promise<SchlageAuthTransportSession> {
  const srp = createSrpState(runtime);
  const initiate = await cognitoRequest(
    'InitiateAuth',
    {
      AuthFlow: 'USER_SRP_AUTH',
      ClientId: runtime.clientId,
      AuthParameters: {
        USERNAME: credentials.username,
        SRP_A: srp.publicAHex,
        SECRET_HASH: secretHash(credentials.username, runtime),
      },
    },
    runtime,
  );

  const challengeName = readString(initiate, 'ChallengeName');
  if (challengeName !== 'PASSWORD_VERIFIER') {
    throw new SchlageError({
      code: 'SCHLAGE_AUTH_PROTOCOL',
      message: 'Schlage auth challenge was not usable.',
      retryable: true,
    });
  }

  const challenge = readRecord(initiate, 'ChallengeParameters');
  const usernameForSrp = readString(challenge, 'USER_ID_FOR_SRP');
  const challengeUsername =
    readOptionalString(challenge, 'USERNAME') ?? credentials.username;
  const timestamp = formatCognitoTimestamp(runtime.now());
  const claim = calculatePasswordClaim({
    password: credentials.password,
    runtime,
    srp,
    saltHex: readString(challenge, 'SALT'),
    srpBHex: readString(challenge, 'SRP_B'),
    secretBlockBase64: readString(challenge, 'SECRET_BLOCK'),
    usernameForSrp,
    timestamp,
  });

  const response = await cognitoRequest(
    'RespondToAuthChallenge',
    {
      ChallengeName: 'PASSWORD_VERIFIER',
      ClientId: runtime.clientId,
      ChallengeResponses: {
        USERNAME: challengeUsername,
        PASSWORD_CLAIM_SECRET_BLOCK: readString(challenge, 'SECRET_BLOCK'),
        PASSWORD_CLAIM_SIGNATURE: claim,
        TIMESTAMP: timestamp,
        SECRET_HASH: secretHash(challengeUsername, runtime),
      },
    },
    runtime,
  );

  return authResultToSession(
    readRecord(response, 'AuthenticationResult'),
    runtime.now(),
  );
}

async function refresh(
  session: unknown,
  runtime: Runtime,
): Promise<SchlageAuthTransportSession> {
  const refreshToken = readSessionString(session, 'refreshToken');
  const accountId = readOptionalSessionString(session, 'accountId');
  const response = await cognitoRequest(
    'InitiateAuth',
    {
      AuthFlow: 'REFRESH_TOKEN_AUTH',
      ClientId: runtime.clientId,
      AuthParameters: {
        REFRESH_TOKEN: refreshToken,
        ...(accountId === undefined
          ? {}
          : { SECRET_HASH: secretHash(accountId, runtime), USERNAME: accountId }),
      },
    },
    runtime,
  );

  return authResultToSession(
    {
      ...readRecord(response, 'AuthenticationResult'),
      RefreshToken: refreshToken,
    },
    runtime.now(),
    accountId,
  );
}

async function listLocks(session: unknown, runtime: Runtime): Promise<unknown> {
  const payload = await apiRequest(
    session,
    'GET',
    'devices?archetype=lock',
    undefined,
    runtime,
  );
  if (!Array.isArray(payload)) {
    throw malformedProtocolError();
  }

  return { locks: payload.map(lockSummaryFromDevice) };
}

async function getStatus(
  session: unknown,
  lockId: string,
  runtime: Runtime,
): Promise<unknown> {
  return statusFromDevice(
    await apiRequest(
      session,
      'GET',
      `devices/${encodeURIComponent(lockId)}`,
      undefined,
      runtime,
    ),
  );
}

async function setLockState(
  session: unknown,
  lockId: string,
  command: 'lock' | 'unlock',
  runtime: Runtime,
): Promise<unknown> {
  const lockState = command === 'lock' ? 1 : 0;
  const payload = await apiRequest(
    session,
    'PUT',
    `devices/${encodeURIComponent(lockId)}`,
    { attributes: { lockState } },
    runtime,
  );

  if (isRecord(payload) && payload.accepted === false) {
    return { accepted: false, ...readObservedState(payload) };
  }

  return { accepted: true, ...readObservedState(statusFromDevice(payload)) };
}

async function listUsers(session: unknown, runtime: Runtime): Promise<unknown> {
  const payload = await apiRequest(session, 'GET', 'users', undefined, runtime);
  if (!Array.isArray(payload)) {
    throw malformedProtocolError();
  }

  return { users: payload.map(userFromPayload) };
}

async function listAccessCodes(
  session: unknown,
  lockId: string,
  runtime: Runtime,
): Promise<unknown> {
  const payload = await apiRequest(
    session,
    'GET',
    `devices/${encodeURIComponent(lockId)}/storage/accesscode`,
    undefined,
    runtime,
  );
  if (!Array.isArray(payload)) {
    throw malformedProtocolError();
  }

  return { accessCodes: payload.map(accessCodeFromPayload) };
}

async function listLogs(
  session: unknown,
  lockId: string,
  options: SchlageListLogsOptions | undefined,
  runtime: Runtime,
): Promise<unknown> {
  const params = new URLSearchParams();
  if (options?.limit !== undefined) {
    params.set('limit', String(options.limit));
  }
  if (options?.sortDesc === true) {
    params.set('sort', 'desc');
  }
  const query = params.toString();
  const payload = await apiRequest(
    session,
    'GET',
    `devices/${encodeURIComponent(lockId)}/logs${query.length === 0 ? '' : `?${query}`}`,
    undefined,
    runtime,
  );
  if (!Array.isArray(payload)) {
    throw malformedProtocolError();
  }

  return { logs: payload };
}

async function getDiagnostics(
  session: unknown,
  lockId: string,
  runtime: Runtime,
): Promise<unknown> {
  return apiRequest(
    session,
    'GET',
    `devices/${encodeURIComponent(lockId)}`,
    undefined,
    runtime,
  );
}

async function addAccessCode(
  session: unknown,
  lockId: string,
  input: SchlageAccessCodeInput,
  runtime: Runtime,
): Promise<unknown> {
  return apiRequest(
    session,
    'POST',
    `devices/${encodeURIComponent(lockId)}/storage/accesscode`,
    createAccessCodeProtocolPayload(input),
    runtime,
  );
}

async function updateAccessCode(
  session: unknown,
  lockId: string,
  accessCodeId: string,
  input: SchlageAccessCodeInput,
  runtime: Runtime,
): Promise<unknown> {
  return apiRequest(
    session,
    'PUT',
    `devices/${encodeURIComponent(lockId)}/storage/accesscode/${encodeURIComponent(accessCodeId)}`,
    createAccessCodeProtocolPayload(input, accessCodeId),
    runtime,
  );
}

async function deleteAccessCode(
  session: unknown,
  lockId: string,
  accessCodeId: string,
  runtime: Runtime,
): Promise<unknown> {
  const payload = await apiRequest(
    session,
    'DELETE',
    `devices/${encodeURIComponent(lockId)}/storage/accesscode/${encodeURIComponent(accessCodeId)}`,
    undefined,
    runtime,
  );
  return payload ?? { accepted: true, accesscodeId: accessCodeId };
}

async function setLockSetting(
  session: unknown,
  lockId: string,
  setting: SchlageLockSetting,
  value: boolean | number,
  runtime: Runtime,
): Promise<unknown> {
  return apiRequest(
    session,
    'PUT',
    `devices/${encodeURIComponent(lockId)}`,
    { attributes: createLockSettingProtocolPayload(setting, value) },
    runtime,
  );
}

async function cognitoRequest(
  action: 'InitiateAuth' | 'RespondToAuthChallenge',
  body: unknown,
  runtime: Runtime,
): Promise<unknown> {
  return requestJson(
    COGNITO_ENDPOINT,
    {
      method: 'POST',
      headers: {
        'content-type': 'application/x-amz-json-1.1',
        'x-amz-target': `${COGNITO_TARGET_PREFIX}.${action}`,
      },
      body: JSON.stringify(body),
    },
    runtime,
  );
}

async function apiRequest(
  session: unknown,
  method: 'DELETE' | 'GET' | 'POST' | 'PUT',
  path: string,
  body: unknown,
  runtime: Runtime,
): Promise<unknown> {
  const accessToken = readSessionString(session, 'accessToken');
  return requestJson(
    `${API_BASE_URL}/${path}`,
    {
      method,
      headers: {
        authorization: `Bearer ${accessToken}`,
        'content-type': 'application/json',
        'x-api-key': runtime.apiKey,
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    },
    runtime,
  );
}

async function requestJson(
  url: string,
  init: RequestInit,
  runtime: Runtime,
): Promise<unknown> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), runtime.timeoutMs);
  try {
    const response = await runtime.fetch(url, {
      ...init,
      signal: controller.signal,
    });
    const text = await response.text();
    const payload = text.length === 0 ? undefined : parseJson(text);
    if (!response.ok) {
      throw classifiedTransportError(httpError(response.status));
    }
    return payload;
  } catch (error) {
    if (error instanceof SchlageError) {
      throw error;
    }
    if (isAbortError(error)) {
      throw classifiedTransportError(
        Object.assign(new Error('Schlage request timed out.'), {
          code: 'ETIMEDOUT',
        }),
      );
    }
    throw classifiedTransportError(error);
  } finally {
    clearTimeout(timeout);
  }
}

function parseJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    throw malformedProtocolError();
  }
}

function authResultToSession(
  result: CognitoAuthResult,
  now: Date,
  existingAccountId?: string,
): SchlageAuthTransportSession {
  const accessToken = readString(result, 'AccessToken');
  const refreshToken = readString(result, 'RefreshToken');
  const expiresIn = readNumber(result, 'ExpiresIn');
  const accountId = existingAccountId ?? readJwtSubject(accessToken);
  return {
    accessToken,
    refreshToken,
    expiresAt: new Date(now.getTime() + expiresIn * 1000),
    refreshedAt: now,
    ...(accountId === undefined ? {} : { accountId }),
  };
}

function lockSummaryFromDevice(device: unknown): unknown {
  assertRecord(device);
  const subtitle =
    readOptionalString(device, 'subtitle') ??
    readOptionalString(device, 'subTitle');
  return {
    id: readString(device, 'deviceId'),
    name: readString(device, 'name'),
    ...(subtitle === undefined ? {} : { subtitle }),
    ...readOptionalDeviceMetadata(device),
  };
}

function statusFromDevice(device: unknown): unknown {
  assertRecord(device);
  const attributes = readRecord(device, 'attributes');
  const lockState = attributes.lockState;
  return {
    state:
      lockState === 1 ? 'locked' : lockState === 0 ? 'unlocked' : 'unknown',
    ...(typeof attributes.batteryLevel === 'number'
      ? { batteryLevel: attributes.batteryLevel }
      : {}),
    ...(typeof device.lastUpdated === 'string'
      ? { updatedAt: device.lastUpdated }
      : {}),
    ...readOptionalDeviceMetadata(device),
    ...(lockState === 2 ? { isJammed: true } : {}),
    ...readOptionalFlag(attributes, 'beeperEnabled', 'beeperEnabled'),
    ...readOptionalFlag(
      attributes,
      'lockAndLeaveEnabled',
      'lockAndLeaveEnabled',
    ),
    ...readOptionalNumber(attributes, 'autoLockTime', 'autoLockTime'),
    ...readOptionalStringAs(
      attributes,
      'mainFirmwareVersion',
      'firmwareVersion',
    ),
    ...readOptionalStringAs(attributes, 'macAddress', 'macAddress'),
    ...readOptionalRawObjectAs(
      attributes,
      'lockStateMetadata',
      'lockStateMetadata',
    ),
    ...(Array.isArray(device.users)
      ? { users: device.users.map(userFromPayload) }
      : {}),
  };
}

function userFromPayload(user: unknown): unknown {
  assertRecord(user);
  return {
    id: readString(user, 'identityId'),
    email: readString(user, 'email'),
    ...readOptionalStringAs(user, 'friendlyName', 'name'),
  };
}

function accessCodeFromPayload(code: unknown): unknown {
  assertRecord(code);
  const accessCode = readAccessCodeValue(code);
  return {
    id: readString(code, 'accesscodeId'),
    name: readString(code, 'friendlyName'),
    code: accessCode,
    disabled: readBooleanLike(code, 'disabled'),
    ...readTransportAccessCodeSchedule(code),
  };
}

function readOptionalDeviceMetadata(
  device: Record<string, unknown>,
): Record<string, unknown> {
  return {
    ...readOptionalStringAs(device, 'devicetypeId', 'deviceType'),
    ...readOptionalStringAs(device, 'modelName', 'modelName'),
    ...readOptionalBoolean(device, 'connected', 'connected'),
  };
}

function readObservedState(payload: unknown): {
  observedState?: SchlageLockState;
} {
  if (!isRecord(payload)) {
    return {};
  }
  const state = payload.state;
  return typeof state === 'string'
    ? {
        observedState:
          state === 'locked' || state === 'unlocked' ? state : 'unknown',
      }
    : {};
}

interface Runtime {
  readonly fetch: typeof fetch;
  readonly timeoutMs: number;
  readonly now: () => Date;
  readonly randomBytes: (size: number) => Buffer;
  readonly apiKey: string;
  readonly clientId: string;
  readonly clientSecret: string;
  readonly userPoolName: string;
}

function createRuntime(options: LiveSchlageTransportOptions): Runtime {
  const userPoolId = readRequiredRuntimeSecret(
    options.userPoolId ?? process.env.SCHLAGE_USER_POOL_ID,
    'SCHLAGE_USER_POOL_ID',
  );
  return {
    fetch: options.fetch ?? fetch,
    timeoutMs: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    now: options.now ?? (() => new Date()),
    randomBytes: options.randomBytes ?? randomBytes,
    apiKey: readRequiredRuntimeSecret(
      options.apiKey ?? process.env.SCHLAGE_API_KEY,
      'SCHLAGE_API_KEY',
    ),
    clientId: readRequiredRuntimeSecret(
      options.clientId ?? process.env.SCHLAGE_CLIENT_ID,
      'SCHLAGE_CLIENT_ID',
    ),
    clientSecret: readRequiredRuntimeSecret(
      options.clientSecret ?? process.env.SCHLAGE_CLIENT_SECRET,
      'SCHLAGE_CLIENT_SECRET',
    ),
    userPoolName: userPoolId.split('_')[1] ?? userPoolId,
  };
}

interface SrpState {
  readonly privateA: bigint;
  readonly publicA: bigint;
  readonly publicAHex: string;
}

function createSrpState(runtime: Runtime): SrpState {
  const privateA = BigInt(`0x${runtime.randomBytes(128).toString('hex')}`) % N;
  const publicA = modPow(G, privateA, N);
  return { privateA, publicA, publicAHex: publicA.toString(16) };
}

function calculatePasswordClaim(input: {
  readonly password: string;
  readonly runtime: Runtime;
  readonly srp: SrpState;
  readonly saltHex: string;
  readonly srpBHex: string;
  readonly secretBlockBase64: string;
  readonly usernameForSrp: string;
  readonly timestamp: string;
}): string {
  const srpB = BigInt(`0x${input.srpBHex}`);
  const u = BigInt(
    `0x${hashHex(Buffer.concat([padHex(input.srp.publicA), padHex(srpB)]))}`,
  );
  const userPasswordHash = hashBuffer(
    Buffer.from(
      `${input.runtime.userPoolName}${input.usernameForSrp}:${input.password}`,
      'utf8',
    ),
  );
  const x = BigInt(
    `0x${hashHex(Buffer.concat([padHex(input.saltHex), userPasswordHash]))}`,
  );
  const gModPowX = modPow(G, x, N);
  const intValue = srpB - K * gModPowX;
  const s = modPow(intValue, input.srp.privateA + u * x, N);
  const key = Buffer.from(
    hkdfSync('sha256', padHex(s), padHex(u), INFO_BITS, 16),
  );
  return createHmac('sha256', key)
    .update(
      Buffer.concat([
        Buffer.from(input.runtime.userPoolName, 'utf8'),
        Buffer.from(input.usernameForSrp, 'utf8'),
        Buffer.from(input.secretBlockBase64, 'base64'),
        Buffer.from(input.timestamp, 'utf8'),
      ]),
    )
    .digest('base64');
}

function secretHash(username: string, runtime: Runtime): string {
  return createHmac('sha256', runtime.clientSecret)
    .update(`${username}${runtime.clientId}`)
    .digest('base64');
}

function readRequiredRuntimeSecret(
  value: string | undefined,
  envName: string,
): string {
  if (typeof value === 'string' && value.trim().length > 0) {
    return value.trim();
  }

  throw new SchlageError({
    code: 'SCHLAGE_CONFIG_MISSING_CREDENTIALS',
    message: `${envName} is required for the live Schlage transport.`,
    retryable: false,
  });
}

function formatCognitoTimestamp(date: Date): string {
  const weekday = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'][
    date.getUTCDay()
  ];
  const month = [
    'Jan',
    'Feb',
    'Mar',
    'Apr',
    'May',
    'Jun',
    'Jul',
    'Aug',
    'Sep',
    'Oct',
    'Nov',
    'Dec',
  ][date.getUTCMonth()];
  const day = String(date.getUTCDate()).padStart(2, '0');
  const time = [date.getUTCHours(), date.getUTCMinutes(), date.getUTCSeconds()]
    .map((part) => String(part).padStart(2, '0'))
    .join(':');
  return `${weekday} ${month} ${day} ${time} UTC ${date.getUTCFullYear()}`;
}

function hashHex(value: Buffer): string {
  return createHash('sha256').update(value).digest('hex');
}

function hashBuffer(value: Buffer): Buffer {
  return createHash('sha256').update(value).digest();
}

function padHex(value: bigint | string): Buffer {
  let hex = typeof value === 'bigint' ? value.toString(16) : value;
  if (hex.length % 2 === 1) {
    hex = `0${hex}`;
  } else if ('89ABCDEFabcdef'.includes(hex[0] ?? '')) {
    hex = `00${hex}`;
  }
  return Buffer.from(hex, 'hex');
}

function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  let result = 1n;
  let b = ((base % modulus) + modulus) % modulus;
  let e = exponent;
  while (e > 0n) {
    if (e % 2n === 1n) {
      result = (result * b) % modulus;
    }
    e /= 2n;
    b = (b * b) % modulus;
  }
  return result;
}

function httpError(status: number): Error & { status: number } {
  return Object.assign(new Error('Schlage HTTP request failed.'), { status });
}

function classifiedTransportError(error: unknown): SchlageError {
  const classification = classifySchlageFailure(error);
  return new SchlageError({
    code:
      classification.code === 'SCHLAGE_UNKNOWN_ERROR'
        ? 'SCHLAGE_PROTOCOL_TRANSPORT'
        : classification.code,
    message: 'Schlage live transport request failed.',
    cause: error,
    retryable:
      classification.code === 'SCHLAGE_UNKNOWN_ERROR'
        ? true
        : classification.retryable,
  });
}

function malformedProtocolError(): SchlageError {
  return new SchlageError({
    code: 'SCHLAGE_PROTOCOL_MALFORMED',
    message: 'Schlage protocol response was malformed.',
    retryable: true,
  });
}

function readJwtSubject(jwt: string): string | undefined {
  const [, payload] = jwt.split('.');
  if (payload === undefined) {
    return undefined;
  }
  try {
    const decoded = JSON.parse(
      Buffer.from(
        payload.replace(/-/g, '+').replace(/_/g, '/'),
        'base64',
      ).toString('utf8'),
    ) as unknown;
    return isRecord(decoded) && typeof decoded.sub === 'string'
      ? decoded.sub
      : undefined;
  } catch {
    return undefined;
  }
}

function readSessionString(
  value: unknown,
  property: 'accessToken' | 'refreshToken',
): string {
  assertRecord(value);
  return readString(value, property);
}

function readOptionalSessionString(
  value: unknown,
  property: 'accountId',
): string | undefined {
  return isRecord(value) &&
    typeof value[property] === 'string' &&
    value[property].trim().length > 0
    ? value[property].trim()
    : undefined;
}

function readRecord(value: unknown, property: string): Record<string, unknown> {
  assertRecord(value);
  const field = value[property];
  if (!isRecord(field)) {
    throw malformedProtocolError();
  }
  return field;
}

function readString(value: unknown, property: string): string {
  assertRecord(value);
  const field = value[property];
  if (typeof field !== 'string' || field.trim().length === 0) {
    throw malformedProtocolError();
  }
  return field.trim();
}

function readAccessCodeValue(value: unknown): string {
  assertRecord(value);
  const field = value.accessCode;
  const length =
    typeof value.accessCodeLength === 'number' &&
    Number.isInteger(value.accessCodeLength)
      ? value.accessCodeLength
      : undefined;
  if (typeof field === 'number' && Number.isInteger(field) && field >= 0) {
    return length === undefined
      ? String(field)
      : String(field).padStart(length, '0');
  }
  if (typeof field === 'string' && field.trim().length > 0) {
    return field.trim();
  }
  throw malformedProtocolError();
}

function readBooleanLike(value: unknown, property: string): boolean {
  assertRecord(value);
  const field = value[property];
  if (typeof field === 'boolean') {
    return field;
  }
  if (field === 0 || field === 1) {
    return field === 1;
  }
  throw malformedProtocolError();
}

function readTransportAccessCodeSchedule(
  value: Record<string, unknown>,
): Record<string, unknown> {
  const activationSecs = readOptionalInteger(value, 'activationSecs');
  const expirationSecs = readOptionalInteger(value, 'expirationSecs');
  if (
    activationSecs !== undefined &&
    expirationSecs !== undefined &&
    !(activationSecs === 0 && expirationSecs === 0xffffffff)
  ) {
    return {
      schedule: {
        type: 'temporary',
        startsAt: new Date(activationSecs * 1000).toISOString(),
        endsAt: new Date(expirationSecs * 1000).toISOString(),
      },
    };
  }
  return {};
}

function readOptionalInteger(
  value: Record<string, unknown>,
  property: string,
): number | undefined {
  const field = value[property];
  if (field === undefined || field === null) {
    return undefined;
  }
  if (typeof field !== 'number' || !Number.isInteger(field)) {
    throw malformedProtocolError();
  }
  return field;
}

function readOptionalString(
  value: unknown,
  property: string,
): string | undefined {
  return isRecord(value) &&
    typeof value[property] === 'string' &&
    value[property].trim().length > 0
    ? value[property].trim()
    : undefined;
}

function readOptionalStringAs(
  value: unknown,
  property: string,
  outputProperty: string,
): Record<string, string> {
  const field = readOptionalString(value, property);
  return field === undefined ? {} : { [outputProperty]: field };
}

function readOptionalRawObjectAs(
  value: unknown,
  property: string,
  outputProperty: string,
): Record<string, unknown> {
  if (!isRecord(value) || !isRecord(value[property])) {
    return {};
  }
  return { [outputProperty]: value[property] };
}

function readOptionalBoolean(
  value: unknown,
  property: string,
  outputProperty: string,
): Record<string, boolean> {
  if (!isRecord(value)) {
    return {};
  }
  const field = value[property];
  if (field === undefined || field === null) {
    return {};
  }
  if (typeof field !== 'boolean') {
    throw malformedProtocolError();
  }
  return { [outputProperty]: field };
}

function readOptionalFlag(
  value: unknown,
  property: string,
  outputProperty: string,
): Record<string, boolean> {
  if (!isRecord(value)) {
    return {};
  }
  const field = value[property];
  if (field === undefined || field === null) {
    return {};
  }
  if (field !== 0 && field !== 1 && typeof field !== 'boolean') {
    throw malformedProtocolError();
  }
  return { [outputProperty]: field === true || field === 1 };
}

function readOptionalNumber(
  value: unknown,
  property: string,
  outputProperty: string,
): Record<string, number> {
  if (!isRecord(value)) {
    return {};
  }
  const field = value[property];
  if (field === undefined || field === null) {
    return {};
  }
  if (typeof field !== 'number' || !Number.isFinite(field)) {
    throw malformedProtocolError();
  }
  return { [outputProperty]: field };
}

function readNumber(value: unknown, property: string): number {
  assertRecord(value);
  const field = value[property];
  if (typeof field !== 'number' || !Number.isFinite(field)) {
    throw malformedProtocolError();
  }
  return field;
}

function assertRecord(
  value: unknown,
): asserts value is Record<string, unknown> {
  if (!isRecord(value)) {
    throw malformedProtocolError();
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isAbortError(error: unknown): boolean {
  return isRecord(error) && error.name === 'AbortError';
}
