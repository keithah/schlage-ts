import { describe, expect, it } from 'vitest';
import { toPublicSchlageError } from '../src/errors.js';
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
} from '../src/protocol.js';

function expectSchlageError(
  run: () => unknown,
  expected: { code: string; message?: string; retryable?: boolean },
): void {
  try {
    run();
    throw new Error('expected SchlageError');
  } catch (error) {
    expect(error).toMatchObject(expected);
  }
}

describe('Schlage protocol normalizers', () => {
  it('normalizes valid lock list payloads without exposing raw protocol fields', () => {
    const locks = normalizeLockListPayload({
      locks: [
        {
          id: ' front-door ',
          name: ' Front Door ',
          subtitle: ' sf front ',
          accessToken: 'raw-list-token-value-00000000000000000000',
          accountId: 'account-12345',
        },
        { id: 'garage', name: 'Garage' },
      ],
    });

    expect(locks).toEqual([
      { id: 'front-door', name: 'Front Door', subtitle: 'sf front' },
      { id: 'garage', name: 'Garage' },
    ]);
    expect(locks.map((lock) => Object.keys(lock))).toEqual([
      ['id', 'name', 'subtitle'],
      ['id', 'name'],
    ]);
    expect(JSON.stringify(locks)).not.toContain('raw-list-token-value');
    expect(JSON.stringify(locks)).not.toContain('account-12345');
  });

  it('normalizes empty lock lists', () => {
    expect(normalizeLockListPayload([])).toEqual([]);
    expect(normalizeLockListPayload({ locks: [] })).toEqual([]);
  });

  it('normalizes status payloads to stable public status objects', () => {
    const status = normalizeLockStatusPayload('front-door', {
      id: 'different-raw-id-ignored',
      state: 'LOCKED',
      battery: 82,
      updatedAt: '2025-01-02T03:04:05.000Z',
      deviceType: 'be499',
      modelName: 'Encode Plus',
      connected: true,
      isJammed: false,
      beeperEnabled: true,
      lockAndLeaveEnabled: false,
      autoLockTime: 60,
      firmwareVersion: '1.2.3',
      lockStateMetadata: {
        actionType: 'virtualKey',
        UUID: 'user-1',
        name: 'Operator Code',
      },
      users: [
        {
          identityId: 'user-1',
          friendlyName: 'Operator',
          email: 'operator@example.test',
        },
      ],
      refreshToken: 'raw-status-refresh-token-00000000000000000000',
    });

    expect(status).toEqual({
      id: 'front-door',
      state: 'locked',
      batteryLevel: 82,
      updatedAt: new Date('2025-01-02T03:04:05.000Z'),
      deviceType: 'be499',
      modelName: 'Encode Plus',
      connected: true,
      isJammed: false,
      beeperEnabled: true,
      lockAndLeaveEnabled: false,
      autoLockTime: 60,
      firmwareVersion: '1.2.3',
      lockStateMetadata: {
        actionType: 'virtualKey',
        uuid: 'user-1',
        name: 'Operator Code',
      },
    });
    expect(JSON.stringify(status)).not.toContain('raw-status-refresh-token');
    expect(JSON.stringify(status)).not.toContain('operator@example.test');
  });

  it('normalizes users without exposing raw identity payload fields', () => {
    const users = normalizeUserListPayload({
      users: [
        {
          identityId: ' user-1 ',
          friendlyName: ' Operator ',
          email: ' operator@example.test ',
          accessToken: 'raw-user-token-00000000000000000000',
        },
      ],
    });

    expect(users).toEqual([
      { id: 'user-1', name: 'Operator', email: 'operator@example.test' },
    ]);
    expect(JSON.stringify(users)).not.toContain('raw-user-token');
  });

  it('normalizes access codes with temporary and recurring schedules', () => {
    const codes = normalizeAccessCodeListPayload('front-door', [
      {
        accesscodeId: ' code-1 ',
        friendlyName: ' Cleaner ',
        accessCode: 42,
        accessCodeLength: 4,
        disabled: 0,
        activationSecs: 1735689600,
        expirationSecs: 1735776000,
        accessToken: 'raw-code-token-00000000000000000000',
      },
      {
        accesscodeId: ' code-2 ',
        friendlyName: ' Dog Walker ',
        accessCode: '8642',
        disabled: 1,
        activationSecs: 0,
        expirationSecs: 4294967295,
        schedule1: {
          daysOfWeek: '2A',
          startHour: 8,
          startMinute: 30,
          endHour: 17,
          endMinute: 45,
        },
      },
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
      {
        id: 'code-2',
        lockId: 'front-door',
        name: 'Dog Walker',
        code: '8642',
        disabled: true,
        schedule: {
          type: 'recurring',
          daysOfWeek: {
            sun: false,
            mon: true,
            tue: false,
            wed: true,
            thu: false,
            fri: true,
            sat: false,
          },
          startHour: 8,
          startMinute: 30,
          endHour: 17,
          endMinute: 45,
        },
      },
    ]);
    expect(JSON.stringify(codes)).not.toContain('raw-code-token');
  });

  it('normalizes lock logs to stable public messages', () => {
    const logs = normalizeLockLogListPayload('front-door', [
      {
        createdAt: '2025-01-02T03:04:05.000Z',
        message: {
          eventCode: 2,
          accessorUuid: 'user-1',
          keypadUuid: 'ffffffff-ffff-ffff-ffff-ffffffffffff',
        },
        rawToken: 'raw-log-token-00000000000000000000',
      },
    ]);

    expect(logs).toEqual([
      {
        lockId: 'front-door',
        createdAt: new Date('2025-01-02T03:04:05.000Z'),
        message: 'Unlocked by keypad',
        eventCode: 2,
        accessorId: 'user-1',
      },
    ]);
    expect(JSON.stringify(logs)).not.toContain('raw-log-token');
  });

  it('normalizes diagnostics with pyschlage-compatible redaction', () => {
    const diagnostics = normalizeLockDiagnosticsPayload({
      deviceId: 'front-door-secret-id',
      name: 'Front Door',
      devicetypeId: 'be499',
      connected: true,
      role: 'lock',
      accountId: 'raw-account-secret-12345',
      attributes: {
        batteryLevel: 91,
        lockState: 1,
        lockStateMetadata: {
          actionType: 'accesscode',
          UUID: 'code-1',
          name: 'Cleaner',
        },
        accessToken: 'raw-diagnostic-token-00000000000000000000',
      },
      users: [{ email: 'operator@example.test' }],
    });

    expect(diagnostics).toEqual({
      deviceId: '<REDACTED>',
      name: 'Front Door',
      devicetypeId: 'be499',
      connected: true,
      role: 'lock',
      accountId: '<REDACTED>',
      attributes: {
        batteryLevel: 91,
        lockState: 1,
        lockStateMetadata: {
          actionType: 'accesscode',
          UUID: 'code-1',
          name: 'Cleaner',
        },
        accessToken: '<REDACTED>',
      },
      users: ['<REDACTED>'],
    });
    expect(JSON.stringify(diagnostics)).not.toContain('raw-diagnostic-token');
    expect(JSON.stringify(diagnostics)).not.toContain('operator@example.test');
  });

  it('resolves pyschlage keypad-disabled and last-changed-by helpers from normalized data', () => {
    const keypadDisabledLogs = normalizeLockLogListPayload('front-door', [
      {
        createdAt: '2025-01-02T03:04:05.000Z',
        message: { eventCode: 2, accessorUuid: 'user-1', keypadUuid: 'code-1' },
      },
      {
        createdAt: '2025-01-02T03:05:05.000Z',
        message: {
          eventCode: 11,
          accessorUuid: 'ffffffff-ffff-ffff-ffff-ffffffffffff',
          keypadUuid: 'ffffffff-ffff-ffff-ffff-ffffffffffff',
        },
      },
    ]);
    const keypadEnabledLogs = normalizeLockLogListPayload('front-door', [
      {
        createdAt: '2025-01-02T03:06:05.000Z',
        message: { eventCode: 2, accessorUuid: 'user-1', keypadUuid: 'code-1' },
      },
      {
        createdAt: '2025-01-02T03:05:05.000Z',
        message: {
          eventCode: 11,
          accessorUuid: 'ffffffff-ffff-ffff-ffff-ffffffffffff',
          keypadUuid: 'ffffffff-ffff-ffff-ffff-ffffffffffff',
        },
      },
    ]);

    expect(isKeypadDisabledFromLogs(keypadDisabledLogs)).toBe(true);
    expect(isKeypadDisabledFromLogs(keypadEnabledLogs)).toBe(false);
    expect(isKeypadDisabledFromLogs([])).toBe(false);
    expect(
      resolveLastChangedBy({
        id: 'front-door',
        state: 'locked',
        lockStateMetadata: {
          actionType: 'accesscode',
          uuid: 'code-1',
          name: 'Cleaner',
        },
      }),
    ).toBe('keypad - Cleaner');
    expect(
      resolveLastChangedBy({
        id: 'front-door',
        state: 'locked',
        lockStateMetadata: {
          actionType: 'virtualKey',
          uuid: 'user-1',
          name: 'Operator',
        },
      }),
    ).toBe('mobile device - Operator');
    expect(
      resolveLastChangedBy({
        id: 'front-door',
        state: 'locked',
        lockStateMetadata: { actionType: 'thumbTurn' },
      }),
    ).toBe('thumbturn');
  });

  it('maps unknown status states to unknown instead of leaking protocol-specific values', () => {
    expect(
      normalizeLockStatusPayload('front-door', {
        state: 'jammed-by-protocol-code',
      }),
    ).toEqual({
      id: 'front-door',
      state: 'unknown',
    });
  });

  it('normalizes accepted and failed command payloads', () => {
    const accepted = normalizeCommandPayload('front-door', {
      accepted: true,
      observedState: 'locked',
      protocolRequestId: 'request-12345',
    });
    const failed = normalizeCommandPayload('front-door', {
      accepted: false,
      state: 'unlocked',
      reason: 'transport-specific-rejection',
    });
    const unknown = normalizeCommandPayload('front-door', {
      accepted: false,
      observedState: 'jammed-by-protocol-code',
    });

    expect(accepted).toEqual({
      id: 'front-door',
      accepted: true,
      observedState: 'locked',
    });
    expect(failed).toEqual({
      id: 'front-door',
      accepted: false,
      observedState: 'unlocked',
    });
    expect(unknown).toEqual({
      id: 'front-door',
      accepted: false,
      observedState: 'unknown',
    });
    expect(Object.keys(accepted)).toEqual(['id', 'accepted', 'observedState']);
    expect(Object.keys(failed)).toEqual(['id', 'accepted', 'observedState']);
    expect(JSON.stringify([accepted, failed, unknown])).not.toContain(
      'request-12345',
    );
    expect(JSON.stringify([accepted, failed, unknown])).not.toContain(
      'transport-specific-rejection',
    );
  });

  it('normalizes write results without leaking protocol-specific fields', () => {
    const result = normalizeWriteResultPayload('front-door', {
      accepted: true,
      accesscodeId: 'code-1',
      requestId: 'raw-write-request-token-00000000000000000000',
    });

    expect(result).toEqual({
      lockId: 'front-door',
      accepted: true,
      accessCodeId: 'code-1',
    });
    expect(JSON.stringify(result)).not.toContain('raw-write-request-token');
  });

  it('creates access-code write payloads using pyschlage-compatible fields', () => {
    expect(
      createAccessCodeProtocolPayload({
        name: ' Cleaner ',
        code: '0042',
        disabled: false,
        schedule: {
          type: 'temporary',
          startsAt: new Date('2025-01-01T00:00:00.000Z'),
          endsAt: new Date('2025-01-02T00:00:00.000Z'),
        },
      }),
    ).toEqual({
      friendlyName: 'Cleaner',
      accessCode: 42,
      accessCodeLength: 4,
      disabled: 0,
      notificationEnabled: 0,
      activationSecs: 1735689600,
      expirationSecs: 1735776000,
      schedule1: {
        daysOfWeek: '7F',
        startHour: 0,
        startMinute: 0,
        endHour: 23,
        endMinute: 59,
      },
    });

    expect(
      createAccessCodeProtocolPayload(
        {
          name: 'Dog Walker',
          code: '8642',
          disabled: true,
          notifyOnUse: true,
          schedule: {
            type: 'recurring',
            daysOfWeek: {
              sun: false,
              mon: true,
              tue: false,
              wed: true,
              thu: false,
              fri: true,
              sat: false,
            },
            startHour: 8,
            startMinute: 30,
            endHour: 17,
            endMinute: 45,
          },
        },
        'code-2',
      ),
    ).toEqual({
      accesscodeId: 'code-2',
      friendlyName: 'Dog Walker',
      accessCode: 8642,
      accessCodeLength: 4,
      disabled: 1,
      notificationEnabled: 1,
      activationSecs: 0,
      expirationSecs: 4294967295,
      schedule1: {
        daysOfWeek: '2A',
        startHour: 8,
        startMinute: 30,
        endHour: 17,
        endMinute: 45,
      },
    });
  });

  it('creates lock setting payloads and rejects invalid auto-lock values', () => {
    expect(createLockSettingProtocolPayload('beeperEnabled', true)).toEqual({
      beeperEnabled: 1,
    });
    expect(
      createLockSettingProtocolPayload('lockAndLeaveEnabled', false),
    ).toEqual({
      lockAndLeaveEnabled: 0,
    });
    expect(createLockSettingProtocolPayload('autoLockTime', 60)).toEqual({
      autoLockTime: 60,
    });
    expectSchlageError(
      () => createLockSettingProtocolPayload('autoLockTime', 7),
      {
        code: 'SCHLAGE_LOCK_ID_INVALID',
        retryable: false,
      },
    );
  });

  it('rejects blank lock IDs with validation-safe errors before protocol use', () => {
    for (const lockId of ['', '   ', null, undefined]) {
      expectSchlageError(() => assertValidLockId(lockId), {
        code: 'SCHLAGE_LOCK_ID_INVALID',
        message: 'Schlage lock ID is required.',
        retryable: false,
      });
      expectSchlageError(
        () => normalizeLockStatusPayload(lockId as never, { state: 'locked' }),
        {
          code: 'SCHLAGE_LOCK_ID_INVALID',
        },
      );
      expectSchlageError(
        () => normalizeCommandPayload(lockId as never, { accepted: true }),
        {
          code: 'SCHLAGE_LOCK_ID_INVALID',
        },
      );
    }
  });

  it('rejects malformed list/status/command payloads with protocol-safe errors', () => {
    for (const payload of [null, {}, { locks: {} }, 'not-array']) {
      expectSchlageError(() => normalizeLockListPayload(payload), {
        code: 'SCHLAGE_PROTOCOL_MALFORMED',
        message: 'Schlage protocol response was malformed.',
        retryable: true,
      });
    }

    for (const payload of [
      [{ name: 'Missing ID' }],
      [{ id: 'missing-name' }],
      [{ id: 'blank-name', name: ' ' }],
      { locks: [{ id: 'front-door', name: null }] },
    ]) {
      expectSchlageError(() => normalizeLockListPayload(payload), {
        code: 'SCHLAGE_PROTOCOL_MALFORMED',
      });
    }

    for (const payload of [
      {},
      { state: '' },
      { state: null },
      { state: 'locked', battery: Number.NaN },
    ]) {
      expectSchlageError(
        () => normalizeLockStatusPayload('front-door', payload),
        {
          code: 'SCHLAGE_PROTOCOL_MALFORMED',
        },
      );
    }

    for (const payload of [
      {},
      { accepted: 'true' },
      { accepted: 1 },
      { accepted: true, observedState: 1 },
    ]) {
      expectSchlageError(() => normalizeCommandPayload('front-door', payload), {
        code: 'SCHLAGE_PROTOCOL_MALFORMED',
      });
    }
  });

  it('redacts secret-shaped malformed values from public protocol failures', () => {
    try {
      normalizeLockListPayload([
        {
          id: 'front-door',
          token: 'malformed-protocol-token-00000000000000000000',
          password: 'hunter2',
        },
      ]);
      throw new Error('expected normalizer to reject missing lock name');
    } catch (error) {
      const publicError = toPublicSchlageError(error);
      expect(publicError).toEqual({
        name: 'SchlageError',
        code: 'SCHLAGE_PROTOCOL_MALFORMED',
        message: 'Schlage protocol response was malformed.',
        retryable: true,
      });
      expect(JSON.stringify(publicError)).not.toContain(
        'malformed-protocol-token',
      );
      expect(JSON.stringify(publicError)).not.toContain('hunter2');
    }
  });

  it('wraps unknown protocol operation failures with safe retryable diagnostics', () => {
    const wrapped = mapProtocolOperationError(
      new Error(
        'authorization=Bearer unsafe-transport-token-00000000000000000000 operator@example.test',
      ),
      'unlock',
    );

    expect(wrapped).toMatchObject({
      code: 'SCHLAGE_PROTOCOL_TRANSPORT',
      message: 'Schlage unlock operation failed.',
      retryable: true,
    });
    expect(toPublicSchlageError(wrapped)).toEqual({
      name: 'SchlageError',
      code: 'SCHLAGE_PROTOCOL_TRANSPORT',
      message: 'Schlage unlock operation failed.',
      retryable: true,
    });
    expect(JSON.stringify(toPublicSchlageError(wrapped))).not.toContain(
      'unsafe-transport-token',
    );
    expect(JSON.stringify(toPublicSchlageError(wrapped))).not.toContain(
      'operator@example.test',
    );
  });
});
