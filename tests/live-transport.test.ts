import { createHmac } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import {
  createLiveSchlageTransports,
  toPublicSchlageError,
  type SchlageClientAuthTransport,
} from '../src/index.js';

type FetchMock = ReturnType<typeof vi.fn<typeof fetch>>;
type Session = Awaited<ReturnType<SchlageClientAuthTransport['signIn']>>;

const now = new Date('2025-01-02T03:04:05.000Z');
const vectorNow = new Date('2025-01-20T03:04:05.000Z');
const liveOptions = {
  apiKey: 'test-api-key',
  clientId: 'test-client-id',
  clientSecret: 'test-client-secret',
  userPoolId: 'us-west-2_testpool',
};
const srpPrivateABytes = Buffer.from(
  '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003a0c92075c0dbf3b8acbc5f96ce3f0ad2',
  'hex',
);
const jwt = `header.${Buffer.from(JSON.stringify({ sub: 'raw-account-id-secret-12345' })).toString('base64url')}.signature`;
const session: Session = {
  accessToken: jwt,
  refreshToken: 'refresh-token-secret-00000000000000000000',
  expiresAt: new Date('2999-01-01T00:00:00.000Z'),
  refreshedAt: now,
  accountId: 'raw-account-id-secret-12345',
};

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function textResponse(body: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: { 'content-type': 'text/plain' },
  });
}

function transport(
  fetchMock: FetchMock,
  timeoutMs = 1000,
  options: Partial<Parameters<typeof createLiveSchlageTransports>[0]> = {},
) {
  return createLiveSchlageTransports({
    fetch: fetchMock,
    timeoutMs,
    now: () => now,
    ...liveOptions,
    ...options,
  });
}

function secretHash(username: string): string {
  return createHmac('sha256', liveOptions.clientSecret)
    .update(`${username}${liveOptions.clientId}`)
    .digest('base64');
}

describe('live Schlage transport', () => {
  it('maps Cognito SRP sign-in responses to private session material without exposing tokens publicly', async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        jsonResponse({
          ChallengeName: 'PASSWORD_VERIFIER',
          ChallengeParameters: {
            USER_ID_FOR_SRP: 'operator@example.test',
            SALT: 'deadbeef',
            SRP_B: 'f'.repeat(384),
            SECRET_BLOCK: Buffer.from('secret-block').toString('base64'),
          },
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse({
          AuthenticationResult: {
            AccessToken: jwt,
            RefreshToken: 'refresh-token-secret-00000000000000000000',
            ExpiresIn: 3600,
          },
        }),
      );

    const result = await transport(fetchMock).authTransport.signIn({
      username: 'operator@example.test',
      password: 'password-secret-00000000000000000000',
    });

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(result).toMatchObject({
      accessToken: jwt,
      refreshToken: 'refresh-token-secret-00000000000000000000',
      accountId: 'raw-account-id-secret-12345',
      refreshedAt: now,
      expiresAt: new Date('2025-01-02T04:04:05.000Z'),
    });
    expect(
      JSON.stringify(toPublicSchlageError(new Error(JSON.stringify(result)))),
    ).not.toContain('refresh-token-secret');
  });

  it('uses Cognito challenge USERNAME for challenge response identity when it differs from USER_ID_FOR_SRP', async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        jsonResponse({
          ChallengeName: 'PASSWORD_VERIFIER',
          ChallengeParameters: {
            USERNAME: 'internal-cognito-username',
            USER_ID_FOR_SRP: 'srp-user-id',
            SALT: 'deadbeef',
            SRP_B: 'f'.repeat(384),
            SECRET_BLOCK: Buffer.from('secret-block').toString('base64'),
          },
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse({
          AuthenticationResult: {
            AccessToken: jwt,
            RefreshToken: 'refresh-token-secret-00000000000000000000',
            ExpiresIn: 3600,
          },
        }),
      );

    await transport(fetchMock).authTransport.signIn({
      username: 'operator@example.test',
      password: 'password-secret-00000000000000000000',
    });

    const responseBody = JSON.parse(
      String(fetchMock.mock.calls[1]?.[1]?.body),
    ) as {
      ChallengeResponses: Record<string, string>;
    };
    expect(responseBody.ChallengeResponses.USERNAME).toBe(
      'internal-cognito-username',
    );
    expect(responseBody.ChallengeResponses.SECRET_HASH).toBe(
      secretHash('internal-cognito-username'),
    );
  });

  it('matches the Cognito SRP signature vector when salt requires positive hex padding', async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        jsonResponse({
          ChallengeName: 'PASSWORD_VERIFIER',
          ChallengeParameters: {
            USERNAME: 'srp-user-id',
            USER_ID_FOR_SRP: 'srp-user-id',
            SALT: 'deadbeefcafebabe0011223344556677',
            SRP_B: 'f'.repeat(768),
            SECRET_BLOCK: Buffer.from('secret-block').toString('base64'),
          },
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse({
          AuthenticationResult: {
            AccessToken: jwt,
            RefreshToken: 'refresh-token-secret-00000000000000000000',
            ExpiresIn: 3600,
          },
        }),
      );

    await createLiveSchlageTransports({
      fetch: fetchMock,
      timeoutMs: 1000,
      now: () => vectorNow,
      randomBytes: () => srpPrivateABytes,
      ...liveOptions,
    }).authTransport.signIn({
      username: 'operator@example.test',
      password: 'password-secret-00000000000000000000',
    });

    const responseBody = JSON.parse(
      String(fetchMock.mock.calls[1]?.[1]?.body),
    ) as {
      ChallengeResponses: Record<string, string>;
    };
    const expectedSignature = [
      'ATgbe9L8Po9G',
      'CozcuWrz7EDP',
      'E5Ix62G2qn7hxt',
      '/a7Ro=',
    ].join('');
    expect(responseBody.ChallengeResponses.PASSWORD_CLAIM_SIGNATURE).toBe(
      expectedSignature,
    );
  });

  it('normalizes live list/status/lock/unlock payloads into the existing protocol shapes', async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        jsonResponse([
          {
            deviceId: 'front-door',
            name: 'Front Door',
            subtitle: 'sf front',
            devicetypeId: 'be499',
            modelName: 'Encode Plus',
            connected: true,
            attributes: {
              lockState: 1,
              batteryLevel: 88,
              beeperEnabled: 1,
              lockAndLeaveEnabled: 0,
              autoLockTime: 60,
              mainFirmwareVersion: '1.2.3',
              macAddress: 'aa:bb:cc:dd:ee:ff',
            },
            accessToken: 'raw-list-token-secret-00000000000000000000',
          },
        ]),
      )
      .mockResolvedValueOnce(
        jsonResponse({
          deviceId: 'front-door',
          name: 'Front Door',
          devicetypeId: 'be499',
          modelName: 'Encode Plus',
          connected: true,
          attributes: {
            lockState: 2,
            batteryLevel: 88,
            beeperEnabled: 1,
            lockAndLeaveEnabled: 0,
            autoLockTime: 60,
            mainFirmwareVersion: '1.2.3',
            macAddress: 'aa:bb:cc:dd:ee:ff',
          },
          lastUpdated: '2025-01-02T03:04:05.000Z',
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse({
          deviceId: 'front-door',
          name: 'Front Door',
          attributes: { lockState: 1, batteryLevel: 88 },
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse({
          deviceId: 'front-door',
          name: 'Front Door',
          attributes: { lockState: 0, batteryLevel: 88 },
        }),
      );

    const { protocolTransport } = transport(fetchMock);

    await expect(protocolTransport.listLocks(session)).resolves.toEqual({
      locks: [
        {
          id: 'front-door',
          name: 'Front Door',
          subtitle: 'sf front',
          deviceType: 'be499',
          modelName: 'Encode Plus',
          connected: true,
        },
      ],
    });
    await expect(
      protocolTransport.getStatus(session, 'front-door'),
    ).resolves.toEqual({
      state: 'unknown',
      batteryLevel: 88,
      updatedAt: '2025-01-02T03:04:05.000Z',
      deviceType: 'be499',
      modelName: 'Encode Plus',
      connected: true,
      isJammed: true,
      beeperEnabled: true,
      lockAndLeaveEnabled: false,
      autoLockTime: 60,
      firmwareVersion: '1.2.3',
      macAddress: 'aa:bb:cc:dd:ee:ff',
    });
    await expect(
      protocolTransport.lock?.(session, 'front-door'),
    ).resolves.toEqual({ accepted: true, observedState: 'locked' });
    await expect(
      protocolTransport.unlock?.(session, 'front-door'),
    ).resolves.toEqual({ accepted: true, observedState: 'unlocked' });

    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      'https://api.allegion.yonomi.cloud/v1/devices?archetype=lock',
      expect.objectContaining({ method: 'GET' }),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      3,
      'https://api.allegion.yonomi.cloud/v1/devices/front-door',
      expect.objectContaining({
        method: 'PUT',
        body: JSON.stringify({ attributes: { lockState: 1 } }),
      }),
    );
  });

  it('normalizes live users, access codes, and lock logs from pyschlage-compatible read paths', async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        jsonResponse([
          {
            identityId: 'user-1',
            friendlyName: 'Operator',
            email: 'operator@example.test',
          },
        ]),
      )
      .mockResolvedValueOnce(
        jsonResponse([
          {
            accesscodeId: 'code-1',
            friendlyName: 'Cleaner',
            accessCode: 42,
            accessCodeLength: 4,
            disabled: 0,
            activationSecs: 1735689600,
            expirationSecs: 1735776000,
          },
        ]),
      )
      .mockResolvedValueOnce(
        jsonResponse([
          {
            createdAt: '2025-01-02T03:04:05.000Z',
            message: {
              eventCode: 2,
              accessorUuid: 'user-1',
              keypadUuid: 'code-1',
            },
          },
        ]),
      );
    const { protocolTransport } = transport(fetchMock);

    await expect(protocolTransport.listUsers?.(session)).resolves.toEqual({
      users: [
        { id: 'user-1', name: 'Operator', email: 'operator@example.test' },
      ],
    });
    await expect(
      protocolTransport.listAccessCodes?.(session, 'front-door'),
    ).resolves.toEqual({
      accessCodes: [
        {
          id: 'code-1',
          name: 'Cleaner',
          code: '0042',
          disabled: false,
          schedule: {
            type: 'temporary',
            startsAt: '2025-01-01T00:00:00.000Z',
            endsAt: '2025-01-02T00:00:00.000Z',
          },
        },
      ],
    });
    await expect(
      protocolTransport.listLogs?.(session, 'front-door', {
        limit: 25,
        sortDesc: true,
      }),
    ).resolves.toEqual({
      logs: [
        {
          createdAt: '2025-01-02T03:04:05.000Z',
          message: {
            eventCode: 2,
            accessorUuid: 'user-1',
            keypadUuid: 'code-1',
          },
        },
      ],
    });

    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      'https://api.allegion.yonomi.cloud/v1/users',
      expect.objectContaining({ method: 'GET' }),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      'https://api.allegion.yonomi.cloud/v1/devices/front-door/storage/accesscode',
      expect.objectContaining({ method: 'GET' }),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      3,
      'https://api.allegion.yonomi.cloud/v1/devices/front-door/logs?limit=25&sort=desc',
      expect.objectContaining({ method: 'GET' }),
    );
  });

  it('reads raw live diagnostics from the pyschlage-compatible device path', async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValueOnce(
      jsonResponse({
        deviceId: 'front-door',
        name: 'Front Door',
        attributes: {
          batteryLevel: 91,
          accessToken: 'raw-live-diagnostic-token-00000000000000000000',
        },
      }),
    );
    const { protocolTransport } = transport(fetchMock);

    await expect(
      protocolTransport.getDiagnostics?.(session, 'front-door'),
    ).resolves.toEqual({
      deviceId: 'front-door',
      name: 'Front Door',
      attributes: {
        batteryLevel: 91,
        accessToken: 'raw-live-diagnostic-token-00000000000000000000',
      },
    });

    expect(fetchMock).toHaveBeenCalledExactlyOnceWith(
      'https://api.allegion.yonomi.cloud/v1/devices/front-door',
      expect.objectContaining({ method: 'GET' }),
    );
  });

  it('sends live access-code and settings writes through pyschlage-compatible paths', async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        jsonResponse({ accepted: true, accesscodeId: 'code-2' }),
      )
      .mockResolvedValueOnce(
        jsonResponse({ accepted: true, accesscodeId: 'code-1' }),
      )
      .mockResolvedValueOnce(
        jsonResponse({ accepted: true, accesscodeId: 'code-1' }),
      )
      .mockResolvedValueOnce(jsonResponse({ accepted: true }))
      .mockResolvedValueOnce(jsonResponse({ accepted: true }))
      .mockResolvedValueOnce(jsonResponse({ accepted: true }));
    const { protocolTransport } = transport(fetchMock);

    await expect(
      protocolTransport.addAccessCode?.(session, 'front-door', {
        name: 'Cleaner',
        code: '0042',
        disabled: false,
      }),
    ).resolves.toEqual({ accepted: true, accesscodeId: 'code-2' });
    await expect(
      protocolTransport.updateAccessCode?.(session, 'front-door', 'code-1', {
        name: 'Cleaner Updated',
        code: '0043',
        disabled: true,
      }),
    ).resolves.toEqual({ accepted: true, accesscodeId: 'code-1' });
    await expect(
      protocolTransport.deleteAccessCode?.(session, 'front-door', 'code-1'),
    ).resolves.toEqual({ accepted: true, accesscodeId: 'code-1' });
    await expect(
      protocolTransport.setLockSetting?.(
        session,
        'front-door',
        'beeperEnabled',
        true,
      ),
    ).resolves.toEqual({ accepted: true });
    await expect(
      protocolTransport.setLockSetting?.(
        session,
        'front-door',
        'lockAndLeaveEnabled',
        false,
      ),
    ).resolves.toEqual({ accepted: true });
    await expect(
      protocolTransport.setLockSetting?.(
        session,
        'front-door',
        'autoLockTime',
        60,
      ),
    ).resolves.toEqual({ accepted: true });

    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      'https://api.allegion.yonomi.cloud/v1/devices/front-door/storage/accesscode',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({
          friendlyName: 'Cleaner',
          accessCode: 42,
          accessCodeLength: 4,
          notificationEnabled: 0,
          disabled: 0,
          activationSecs: 0,
          expirationSecs: 4294967295,
          schedule1: {
            daysOfWeek: '7F',
            startHour: 0,
            startMinute: 0,
            endHour: 23,
            endMinute: 59,
          },
        }),
      }),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      'https://api.allegion.yonomi.cloud/v1/devices/front-door/storage/accesscode/code-1',
      expect.objectContaining({ method: 'PUT' }),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      3,
      'https://api.allegion.yonomi.cloud/v1/devices/front-door/storage/accesscode/code-1',
      expect.objectContaining({ method: 'DELETE' }),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      4,
      'https://api.allegion.yonomi.cloud/v1/devices/front-door',
      expect.objectContaining({
        method: 'PUT',
        body: JSON.stringify({ attributes: { beeperEnabled: 1 } }),
      }),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      5,
      'https://api.allegion.yonomi.cloud/v1/devices/front-door',
      expect.objectContaining({
        method: 'PUT',
        body: JSON.stringify({ attributes: { lockAndLeaveEnabled: 0 } }),
      }),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      6,
      'https://api.allegion.yonomi.cloud/v1/devices/front-door',
      expect.objectContaining({
        method: 'PUT',
        body: JSON.stringify({ attributes: { autoLockTime: 60 } }),
      }),
    );
  });

  it('treats empty successful access-code delete responses as accepted', async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(new Response(null, { status: 204 }));
    const { protocolTransport } = transport(fetchMock);

    await expect(
      protocolTransport.deleteAccessCode?.(session, 'front-door', 'code-1'),
    ).resolves.toEqual({ accepted: true, accesscodeId: 'code-1' });

    expect(fetchMock).toHaveBeenCalledExactlyOnceWith(
      'https://api.allegion.yonomi.cloud/v1/devices/front-door/storage/accesscode/code-1',
      expect.objectContaining({ method: 'DELETE' }),
    );
  });

  it('classifies malformed JSON and malformed device shapes as protocol malformed', async () => {
    const badJson = transport(
      vi.fn<typeof fetch>().mockResolvedValueOnce(textResponse('{nope', 200)),
    ).protocolTransport;
    await expect(badJson.listLocks(session)).rejects.toMatchObject({
      code: 'SCHLAGE_PROTOCOL_MALFORMED',
      retryable: true,
    });

    const missingLockFields = transport(
      vi
        .fn<typeof fetch>()
        .mockResolvedValueOnce(jsonResponse([{ name: 'Front Door' }])),
    ).protocolTransport;
    await expect(missingLockFields.listLocks(session)).rejects.toMatchObject({
      code: 'SCHLAGE_PROTOCOL_MALFORMED',
      retryable: true,
    });
  });

  it('maps auth and rate-limit HTTP failures through the S06 taxonomy', async () => {
    const unauthorized = transport(
      vi
        .fn<typeof fetch>()
        .mockResolvedValueOnce(jsonResponse({ message: 'nope' }, 401)),
    ).authTransport;
    await expect(
      unauthorized.signIn({
        username: 'operator@example.test',
        password: 'secret',
      }),
    ).rejects.toMatchObject({
      code: 'SCHLAGE_AUTH_FAILED',
      retryable: false,
    });

    const rateLimited = transport(
      vi
        .fn<typeof fetch>()
        .mockResolvedValueOnce(jsonResponse({ message: 'slow down' }, 429)),
    ).protocolTransport;
    try {
      await rateLimited.listLocks(session);
      throw new Error('expected rate limit');
    } catch (error) {
      expect(toPublicSchlageError(error)).toEqual({
        name: 'SchlageError',
        code: 'SCHLAGE_RATE_LIMITED',
        message: 'Schlage live transport request failed.',
        retryable: true,
      });
    }
  });

  it('marks network and timeout failures as retryable transport failures through protocol mapping', async () => {
    const networkError = Object.assign(
      new Error(
        'socket closed access_token=network-token-secret-00000000000000000000',
      ),
      { code: 'ECONNRESET' },
    );
    const network = transport(
      vi.fn<typeof fetch>().mockRejectedValueOnce(networkError),
    ).protocolTransport;
    await expect(
      network.getStatus(session, 'front-door'),
    ).rejects.toMatchObject({
      code: 'SCHLAGE_PROTOCOL_TRANSPORT',
      retryable: true,
    });

    const abort = Object.assign(new Error('aborted'), { name: 'AbortError' });
    const timedOut = transport(
      vi.fn<typeof fetch>().mockRejectedValueOnce(abort),
    ).protocolTransport;
    await expect(
      timedOut.getStatus(session, 'front-door'),
    ).rejects.toMatchObject({
      code: 'SCHLAGE_PROTOCOL_TRANSPORT',
      retryable: true,
    });
  });

  it('normalizes command accepted:false responses without leaking transport-specific reasons', async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValueOnce(
      jsonResponse({
        accepted: false,
        state: 'jammed-protocol-value',
        reason: 'policy-rejected-secret-token-00000000000000000000',
      }),
    );

    const result = await transport(fetchMock).protocolTransport.lock?.(
      session,
      'front-door',
    );

    expect(result).toEqual({ accepted: false, observedState: 'unknown' });
    expect(JSON.stringify(result)).not.toContain(
      'policy-rejected-secret-token',
    );
  });
});
