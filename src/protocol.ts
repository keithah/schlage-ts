import { SchlageError, classifySchlageFailure } from './errors.js';
import type {
  SchlageAccessCode,
  SchlageAccessCodeInput,
  SchlageAccessCodeSchedule,
  SchlageCommandResult,
  SchlageDaysOfWeek,
  SchlageLockId,
  SchlageLockDiagnostics,
  SchlageLockLog,
  SchlageLockStateMetadata,
  SchlageLockState,
  SchlageLockStatus,
  SchlageLockSummary,
  SchlageUser,
  SchlageWriteResult,
} from './index.js';

export interface SchlageProtocolTransport {
  readonly listLocks: () => Promise<unknown>;
  readonly getStatus: (lockId: SchlageLockId) => Promise<unknown>;
  readonly lock: (lockId: SchlageLockId) => Promise<unknown>;
  readonly unlock: (lockId: SchlageLockId) => Promise<unknown>;
}

export type SchlageProtocolCommand = 'lock' | 'unlock';
export type SchlageProtocolOperation =
  | 'listLocks'
  | 'getStatus'
  | 'listUsers'
  | 'listAccessCodes'
  | 'listLogs'
  | 'getDiagnostics'
  | 'addAccessCode'
  | 'updateAccessCode'
  | 'deleteAccessCode'
  | 'setLockSetting'
  | SchlageProtocolCommand;

const MALFORMED_PROTOCOL_MESSAGE = 'Schlage protocol response was malformed.';
const INVALID_LOCK_ID_MESSAGE = 'Schlage lock ID is required.';
const MIN_TIME = 0;
const MAX_TIME = 0xffffffff;
const ALL_DAYS = '7F';
const AUTO_LOCK_TIMES = new Set([0, 5, 15, 30, 60, 120, 240, 300, 360, 600]);
const DEFAULT_UUID = 'ffffffff-ffff-ffff-ffff-ffffffffffff';
const REDACTED_VALUE = '<REDACTED>';
const DIAGNOSTICS_ALLOWED_PATHS = [
  'attributes.accessCodeLength',
  'attributes.actAlarmBuzzerEnabled',
  'attributes.actAlarmState',
  'attributes.actuationCurrentMax',
  'attributes.alarmSelection',
  'attributes.alarmSensitivity',
  'attributes.alarmState',
  'attributes.autoLockTime',
  'attributes.batteryChangeDate',
  'attributes.batteryLevel',
  'attributes.batteryLowState',
  'attributes.batterySaverConfig',
  'attributes.batterySaverState',
  'attributes.beeperEnabled',
  'attributes.bleFirmwareVersion',
  'attributes.firmwareUpdate',
  'attributes.homePosCurrentMax',
  'attributes.keypadFirmwareVersion',
  'attributes.lockAndLeaveEnabled',
  'attributes.lockState',
  'attributes.lockStateMetadata',
  'attributes.mainFirmwareVersion',
  'attributes.mode',
  'attributes.modelName',
  'attributes.periodicDeepQueryTimeSetting',
  'attributes.psPollEnabled',
  'attributes.timezone',
  'attributes.wifiFirmwareVersion',
  'attributes.wifiRssi',
  'connected',
  'connectivityUpdated',
  'created',
  'devicetypeId',
  'lastUpdated',
  'modelName',
  'name',
  'role',
  'timezone',
];
const LOG_EVENT_MESSAGES = new Map<number, string>([
  [-1, 'Unknown'],
  [0, 'Unknown'],
  [1, 'Locked by keypad'],
  [2, 'Unlocked by keypad'],
  [3, 'Locked by thumbturn'],
  [4, 'Unlocked by thumbturn'],
  [5, 'Locked by Schlage button'],
  [6, 'Locked by mobile device'],
  [7, 'Unlocked by mobile device'],
  [8, 'Locked by time'],
  [9, 'Unlocked by time'],
  [10, 'Lock jammed'],
  [11, 'Keypad disabled invalid code'],
  [12, 'Alarm triggered'],
  [14, 'Access code user added'],
  [15, 'Access code user deleted'],
  [16, 'Mobile user added'],
  [17, 'Mobile user deleted'],
  [18, 'Admin privilege added'],
  [19, 'Admin privilege deleted'],
  [20, 'Firmware updated'],
  [21, 'Low battery indicated'],
  [22, 'Batteries replaced'],
  [23, 'Forced entry alarm silenced'],
  [27, 'Hall sensor comm error'],
  [28, 'FDR failed'],
  [29, 'Critical battery state'],
  [30, 'All access code deleted'],
  [32, 'Firmware update failed'],
  [33, 'Bluetooth firmware download failed'],
  [34, 'WiFi firmware download failed'],
  [35, 'Keypad disconnected'],
  [36, 'WiFi AP disconnect'],
  [37, 'WiFi host disconnect'],
  [38, 'WiFi AP connect'],
  [39, 'WiFi host connect'],
  [40, 'User DB failure'],
  [48, 'Passage mode activated'],
  [49, 'Passage mode deactivated'],
  [52, 'Unlocked by Apple key'],
  [53, 'Locked by Apple key'],
  [54, 'Motor jammed on fail'],
  [55, 'Motor jammed off fail'],
  [56, 'Motor jammed retries exceeded'],
  [255, 'History cleared'],
]);

export function assertValidLockId(
  lockId: unknown,
): asserts lockId is SchlageLockId {
  if (typeof lockId !== 'string' || lockId.trim().length === 0) {
    throw new SchlageError({
      code: 'SCHLAGE_LOCK_ID_INVALID',
      message: INVALID_LOCK_ID_MESSAGE,
      retryable: false,
    });
  }
}

export function normalizeLockListPayload(
  payload: unknown,
): SchlageLockSummary[] {
  const locks = extractLockArray(payload);
  return locks.map((lock) => ({
    id: readRequiredString(lock, 'id'),
    name: readRequiredString(lock, 'name'),
    ...readOptionalString(lock, 'subtitle', 'subtitle'),
    ...readOptionalString(lock, 'deviceType', 'deviceType'),
    ...readOptionalString(lock, 'modelName', 'modelName'),
    ...readOptionalBoolean(lock, 'connected', 'connected'),
  }));
}

export function normalizeLockStatusPayload(
  lockId: SchlageLockId,
  payload: unknown,
): SchlageLockStatus {
  assertValidLockId(lockId);
  assertRecord(payload);

  return {
    id: lockId.trim(),
    state: normalizeLockState(readRequiredString(payload, 'state')),
    ...readOptionalBatteryLevel(payload),
    ...readOptionalUpdatedAt(payload),
    ...readOptionalString(payload, 'deviceType', 'deviceType'),
    ...readOptionalString(payload, 'modelName', 'modelName'),
    ...readOptionalBoolean(payload, 'connected', 'connected'),
    ...readOptionalBoolean(payload, 'isJammed', 'isJammed'),
    ...readOptionalBoolean(payload, 'beeperEnabled', 'beeperEnabled'),
    ...readOptionalBoolean(
      payload,
      'lockAndLeaveEnabled',
      'lockAndLeaveEnabled',
    ),
    ...readOptionalNumber(payload, 'autoLockTime', 'autoLockTime'),
    ...readOptionalString(payload, 'firmwareVersion', 'firmwareVersion'),
    ...readOptionalString(payload, 'macAddress', 'macAddress'),
    ...readOptionalLockStateMetadata(payload),
  };
}

export function normalizeUserListPayload(payload: unknown): SchlageUser[] {
  const users = extractArray(payload, 'users');
  return users.map((user) => ({
    id: readFirstRequiredString(user, ['id', 'identityId']),
    email: readRequiredString(user, 'email'),
    ...readOptionalString(user, 'friendlyName', 'name'),
  }));
}

export function normalizeAccessCodeListPayload(
  lockId: SchlageLockId,
  payload: unknown,
): SchlageAccessCode[] {
  assertValidLockId(lockId);
  const normalizedLockId = lockId.trim();
  const codes = extractArray(payload, 'accessCodes');

  return codes.map((code) => {
    const accessCode = readAccessCodeValue(code);
    return {
      id: readFirstRequiredString(code, ['id', 'accesscodeId', 'accessCodeId']),
      lockId: normalizedLockId,
      name: readFirstRequiredString(code, ['name', 'friendlyName']),
      code: accessCode,
      disabled: readBooleanLike(code, 'disabled'),
      ...readAccessCodeSchedule(code),
    };
  });
}

export function normalizeLockLogListPayload(
  lockId: SchlageLockId,
  payload: unknown,
): SchlageLockLog[] {
  assertValidLockId(lockId);
  const normalizedLockId = lockId.trim();
  const logs = extractArray(payload, 'logs');

  return logs.map((log) => {
    const message = readRecord(log, 'message');
    const eventCode = readRequiredNumber(message, 'eventCode');
    return {
      lockId: normalizedLockId,
      createdAt: readRequiredDate(log, 'createdAt'),
      message: LOG_EVENT_MESSAGES.get(eventCode) ?? 'Unknown',
      eventCode,
      ...readOptionalDefaultUuid(message, 'accessorUuid', 'accessorId'),
      ...readOptionalDefaultUuid(message, 'keypadUuid', 'accessCodeId'),
    };
  });
}

export function normalizeLockDiagnosticsPayload(
  payload: unknown,
): SchlageLockDiagnostics {
  assertRecord(payload);
  return redactDiagnosticsRecord(payload, DIAGNOSTICS_ALLOWED_PATHS);
}

export function isKeypadDisabledFromLogs(
  logs: readonly SchlageLockLog[],
): boolean {
  if (logs.length === 0) {
    return false;
  }

  const newestLog = [...logs].sort(
    (left, right) => right.createdAt.getTime() - left.createdAt.getTime(),
  )[0];
  return (
    newestLog?.eventCode === 11 ||
    newestLog?.message === 'Keypad disabled invalid code'
  );
}

export function resolveLastChangedBy(
  status: SchlageLockStatus,
): string | undefined {
  const metadata = status.lockStateMetadata;
  if (metadata === undefined) {
    return undefined;
  }

  const userName =
    metadata.name ??
    (metadata.uuid === undefined
      ? undefined
      : status.users?.find((user) => user.id === metadata.uuid)?.name);
  const userSuffix = userName === undefined ? '' : ` - ${userName}`;

  switch (metadata.actionType) {
    case 'thumbTurn':
      return 'thumbturn';
    case '1touchLocking':
      return '1-touch locking';
    case 'accesscode':
      return `keypad - ${metadata.name ?? 'unknown'}`;
    case 'AppleHomeNFC':
      return `apple nfc device${userSuffix}`;
    case 'virtualKey':
      return `mobile device${userSuffix}`;
    default:
      return 'unknown';
  }
}

export function normalizeCommandPayload(
  lockId: SchlageLockId,
  payload: unknown,
): SchlageCommandResult {
  assertValidLockId(lockId);
  assertRecord(payload);

  const accepted = payload.accepted;
  if (typeof accepted !== 'boolean') {
    throw malformedProtocolError();
  }

  return {
    id: lockId.trim(),
    accepted,
    ...readOptionalObservedState(payload),
  };
}

export function normalizeWriteResultPayload(
  lockId: SchlageLockId,
  payload: unknown,
): SchlageWriteResult {
  assertValidLockId(lockId);
  assertRecord(payload);

  const accepted = payload.accepted ?? true;
  if (typeof accepted !== 'boolean') {
    throw malformedProtocolError();
  }

  return {
    lockId: lockId.trim(),
    accepted,
    ...readOptionalString(payload, 'accesscodeId', 'accessCodeId'),
  };
}

export function createAccessCodeProtocolPayload(
  input: SchlageAccessCodeInput,
  accessCodeId?: string,
): Record<string, unknown> {
  const name = input.name.trim();
  if (name.length === 0 || !/^\d+$/.test(input.code)) {
    throw invalidInputError(
      'Schlage access code name and numeric code are required.',
    );
  }

  return {
    ...(accessCodeId === undefined
      ? {}
      : { accesscodeId: accessCodeId.trim() }),
    friendlyName: name,
    accessCode: Number.parseInt(input.code, 10),
    accessCodeLength: input.code.length,
    notificationEnabled: input.notifyOnUse === true ? 1 : 0,
    disabled: input.disabled === true ? 1 : 0,
    activationSecs: MIN_TIME,
    expirationSecs: MAX_TIME,
    schedule1: defaultRecurringSchedulePayload(),
    ...scheduleToProtocolPayload(input.schedule),
  };
}

export function createLockSettingProtocolPayload(
  setting: 'beeperEnabled' | 'lockAndLeaveEnabled' | 'autoLockTime',
  value: boolean | number,
): Record<string, number> {
  if (setting === 'autoLockTime') {
    if (typeof value !== 'number' || !AUTO_LOCK_TIMES.has(value)) {
      throw invalidInputError('Schlage auto-lock time is not supported.');
    }
    return { autoLockTime: value };
  }

  if (typeof value !== 'boolean') {
    throw invalidInputError('Schlage lock setting value is invalid.');
  }

  return { [setting]: value ? 1 : 0 };
}

export function mapProtocolOperationError(
  error: unknown,
  operation: SchlageProtocolOperation,
): SchlageError {
  if (error instanceof SchlageError) {
    return error;
  }

  const classification = classifySchlageFailure(error);

  return new SchlageError({
    code:
      classification.code === 'SCHLAGE_UNKNOWN_ERROR'
        ? 'SCHLAGE_PROTOCOL_TRANSPORT'
        : classification.code,
    message: `Schlage ${operation} operation failed.`,
    cause: error,
    retryable:
      classification.code === 'SCHLAGE_UNKNOWN_ERROR'
        ? true
        : classification.retryable,
  });
}

function extractLockArray(payload: unknown): unknown[] {
  if (Array.isArray(payload)) {
    return payload;
  }

  if (isRecord(payload) && Array.isArray(payload.locks)) {
    return payload.locks;
  }

  throw malformedProtocolError();
}

function readRequiredString(record: unknown, field: string): string {
  assertRecord(record);
  const value = record[field];

  if (typeof value !== 'string' || value.trim().length === 0) {
    throw malformedProtocolError();
  }

  return value.trim();
}

function readOptionalString<T extends string>(
  record: unknown,
  field: string,
  outputField: T,
): { readonly [K in T]?: string } {
  assertRecord(record);
  const value = record[field];

  if (value === undefined || value === null) {
    return {};
  }

  if (typeof value !== 'string') {
    throw malformedProtocolError();
  }

  const trimmed = value.trim();
  return trimmed.length === 0
    ? {}
    : ({ [outputField]: trimmed } as { readonly [K in T]?: string });
}

function readOptionalBoolean<T extends string>(
  record: unknown,
  field: string,
  outputField: T,
): { readonly [K in T]?: boolean } {
  assertRecord(record);
  const value = record[field];
  if (value === undefined || value === null) {
    return {};
  }
  if (typeof value !== 'boolean') {
    throw malformedProtocolError();
  }
  return { [outputField]: value } as { readonly [K in T]?: boolean };
}

function readOptionalNumber<T extends string>(
  record: unknown,
  field: string,
  outputField: T,
): { readonly [K in T]?: number } {
  assertRecord(record);
  const value = record[field];
  if (value === undefined || value === null) {
    return {};
  }
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw malformedProtocolError();
  }
  return { [outputField]: value } as { readonly [K in T]?: number };
}

function normalizeLockState(value: string): SchlageLockState {
  const normalized = value.trim().toLowerCase();
  if (normalized === 'locked' || normalized === 'unlocked') {
    return normalized;
  }

  return 'unknown';
}

function readOptionalBatteryLevel(
  record: Record<string, unknown>,
): Pick<SchlageLockStatus, 'batteryLevel'> {
  const value = record.batteryLevel ?? record.battery;
  if (value === undefined || value === null) {
    return {};
  }

  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw malformedProtocolError();
  }

  return { batteryLevel: value };
}

function readOptionalUpdatedAt(
  record: Record<string, unknown>,
): Pick<SchlageLockStatus, 'updatedAt'> {
  const value = record.updatedAt;
  if (value === undefined || value === null) {
    return {};
  }

  const updatedAt = coerceDate(value);
  if (updatedAt === undefined) {
    throw malformedProtocolError();
  }

  return { updatedAt };
}

function readOptionalLockStateMetadata(
  record: Record<string, unknown>,
): Pick<SchlageLockStatus, 'lockStateMetadata'> {
  const value = record.lockStateMetadata;
  if (value === undefined || value === null) {
    return {};
  }
  assertRecord(value);

  const metadata: SchlageLockStateMetadata = {
    actionType: readRequiredString(value, 'actionType'),
    ...readOptionalString(value, 'UUID', 'uuid'),
    ...readOptionalString(value, 'uuid', 'uuid'),
    ...readOptionalString(value, 'name', 'name'),
  };
  return { lockStateMetadata: metadata };
}

function readAccessCodeValue(record: unknown): string {
  assertRecord(record);
  const value = record.accessCode ?? record.code;
  const length =
    typeof record.accessCodeLength === 'number' &&
    Number.isInteger(record.accessCodeLength)
      ? record.accessCodeLength
      : undefined;

  if (typeof value === 'number' && Number.isInteger(value) && value >= 0) {
    return length === undefined
      ? String(value)
      : String(value).padStart(length, '0');
  }

  if (typeof value === 'string' && value.trim().length > 0) {
    return value.trim();
  }

  throw malformedProtocolError();
}

function readAccessCodeSchedule(
  record: unknown,
): Pick<SchlageAccessCode, 'schedule'> {
  assertRecord(record);
  const activationSecs = readOptionalInteger(record, 'activationSecs');
  const expirationSecs = readOptionalInteger(record, 'expirationSecs');

  if (
    activationSecs !== undefined &&
    expirationSecs !== undefined &&
    !(activationSecs === MIN_TIME && expirationSecs === MAX_TIME)
  ) {
    return {
      schedule: {
        type: 'temporary',
        startsAt: new Date(activationSecs * 1000),
        endsAt: new Date(expirationSecs * 1000),
      },
    };
  }

  if (
    isRecord(record.schedule1) &&
    !isDefaultRecurringSchedule(record.schedule1)
  ) {
    return { schedule: recurringScheduleFromRecord(record.schedule1) };
  }

  return {};
}

function scheduleToProtocolPayload(
  schedule: SchlageAccessCodeSchedule | undefined,
): Record<string, unknown> {
  if (schedule === undefined) {
    return {};
  }

  if (schedule.type === 'temporary') {
    return {
      activationSecs: Math.floor(schedule.startsAt.getTime() / 1000),
      expirationSecs: Math.floor(schedule.endsAt.getTime() / 1000),
    };
  }

  return {
    schedule1: {
      daysOfWeek: daysOfWeekToHex(schedule.daysOfWeek),
      startHour: schedule.startHour,
      startMinute: schedule.startMinute,
      endHour: schedule.endHour,
      endMinute: schedule.endMinute,
    },
  };
}

function defaultRecurringSchedulePayload(): Record<string, number | string> {
  return {
    daysOfWeek: ALL_DAYS,
    startHour: 0,
    startMinute: 0,
    endHour: 23,
    endMinute: 59,
  };
}

function recurringScheduleFromRecord(
  record: Record<string, unknown>,
): SchlageAccessCodeSchedule {
  return {
    type: 'recurring',
    daysOfWeek: daysOfWeekFromHex(readRequiredString(record, 'daysOfWeek')),
    startHour: readRequiredNumber(record, 'startHour'),
    startMinute: readRequiredNumber(record, 'startMinute'),
    endHour: readRequiredNumber(record, 'endHour'),
    endMinute: readRequiredNumber(record, 'endMinute'),
  };
}

function isDefaultRecurringSchedule(record: Record<string, unknown>): boolean {
  return (
    record.daysOfWeek === ALL_DAYS &&
    record.startHour === 0 &&
    record.startMinute === 0 &&
    record.endHour === 23 &&
    record.endMinute === 59
  );
}

function daysOfWeekFromHex(value: string): SchlageDaysOfWeek {
  const parsed = Number.parseInt(value, 16);
  if (!Number.isInteger(parsed) || parsed < 0 || parsed > 0x7f) {
    throw malformedProtocolError();
  }

  return {
    sun: (parsed & 0x40) !== 0,
    mon: (parsed & 0x20) !== 0,
    tue: (parsed & 0x10) !== 0,
    wed: (parsed & 0x08) !== 0,
    thu: (parsed & 0x04) !== 0,
    fri: (parsed & 0x02) !== 0,
    sat: (parsed & 0x01) !== 0,
  };
}

function daysOfWeekToHex(days: SchlageDaysOfWeek): string {
  const values = [
    days.sun,
    days.mon,
    days.tue,
    days.wed,
    days.thu,
    days.fri,
    days.sat,
  ];
  return values
    .reduce((acc, enabled) => (acc << 1) | (enabled ? 1 : 0), 0)
    .toString(16)
    .toUpperCase();
}

function readBooleanLike(record: unknown, field: string): boolean {
  assertRecord(record);
  const value = record[field];
  if (typeof value === 'boolean') {
    return value;
  }
  if (value === 0 || value === 1) {
    return value === 1;
  }
  throw malformedProtocolError();
}

function readOptionalInteger(
  record: Record<string, unknown>,
  field: string,
): number | undefined {
  const value = record[field];
  if (value === undefined || value === null) {
    return undefined;
  }
  if (typeof value !== 'number' || !Number.isInteger(value)) {
    throw malformedProtocolError();
  }
  return value;
}

function readRequiredNumber(record: unknown, field: string): number {
  assertRecord(record);
  const value = record[field];
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw malformedProtocolError();
  }
  return value;
}

function readRequiredDate(record: unknown, field: string): Date {
  assertRecord(record);
  const date = coerceDate(record[field]);
  if (date === undefined) {
    throw malformedProtocolError();
  }
  return date;
}

function readOptionalDefaultUuid<T extends string>(
  record: unknown,
  field: string,
  outputField: T,
): { readonly [K in T]?: string } {
  assertRecord(record);
  const value = record[field];
  if (value === undefined || value === null || value === DEFAULT_UUID) {
    return {};
  }
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw malformedProtocolError();
  }
  return { [outputField]: value.trim() } as { readonly [K in T]?: string };
}

function redactDiagnosticsRecord(
  record: Record<string, unknown>,
  allowed: readonly string[],
): Record<string, unknown> {
  const allowedHere = allowed.reduce<Record<string, string[]>>((acc, path) => {
    const [key = '', ...children] = path.split('.');
    if (key.length === 0) {
      return acc;
    }
    acc[key] = [...(acc[key] ?? []), children.join('.') || '*'];
    return acc;
  }, {});

  return Object.fromEntries(
    Object.entries(record).map(([key, value]) => {
      const childAllowed = allowedHere[key] ?? [];
      if (childAllowed.includes('*')) {
        return [key, value];
      }
      if (isRecord(value)) {
        return [key, redactDiagnosticsRecord(value, childAllowed)];
      }
      return [key, Array.isArray(value) ? [REDACTED_VALUE] : REDACTED_VALUE];
    }),
  );
}

function readFirstRequiredString(
  record: unknown,
  fields: readonly string[],
): string {
  assertRecord(record);
  for (const field of fields) {
    const value = record[field];
    if (typeof value === 'string' && value.trim().length > 0) {
      return value.trim();
    }
  }
  throw malformedProtocolError();
}

function readRecord(record: unknown, field: string): Record<string, unknown> {
  assertRecord(record);
  const value = record[field];
  if (!isRecord(value)) {
    throw malformedProtocolError();
  }
  return value;
}

function extractArray(payload: unknown, field: string): unknown[] {
  if (Array.isArray(payload)) {
    return payload;
  }

  if (isRecord(payload) && Array.isArray(payload[field])) {
    return payload[field];
  }

  throw malformedProtocolError();
}

function readOptionalObservedState(
  record: Record<string, unknown>,
): Pick<SchlageCommandResult, 'observedState'> {
  const value = record.observedState ?? record.state;
  if (value === undefined || value === null) {
    return {};
  }

  if (typeof value !== 'string') {
    throw malformedProtocolError();
  }

  return { observedState: normalizeLockState(value) };
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

function malformedProtocolError(): SchlageError {
  return new SchlageError({
    code: 'SCHLAGE_PROTOCOL_MALFORMED',
    message: MALFORMED_PROTOCOL_MESSAGE,
    retryable: true,
  });
}

function invalidInputError(message: string): SchlageError {
  return new SchlageError({
    code: 'SCHLAGE_LOCK_ID_INVALID',
    message,
    retryable: false,
  });
}
