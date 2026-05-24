import { describe, expect, it } from 'vitest';
import {
  SchlageError,
  classifySchlageFailure,
  toPublicSchlageError,
  wrapUnknownSchlageError,
  type SchlageErrorCode,
} from '../src/errors.js';

const FAKE_JWT = [
  'eyJhbGciOiJIUzI1NiJ9',
  'eyJzdWIiOiJvcGVyYXRvckBleGFtcGxlLnRlc3QifQ',
  'signaturevalue000000000000',
].join('.');

const SECRET_FIXTURES = [
  'operator@example.test',
  'hunter2',
  'raw-access-token-value-00000000000000000000',
  'raw-refresh-token-value-00000000000000000000',
  'bearer-session-secret-00000000000000000000',
  FAKE_JWT,
  'account-12345',
  '/tmp/schlage-cache/token-cache.json',
];

function rendered(value: unknown): string {
  return JSON.stringify(value);
}

function expectNoSecretText(value: unknown): void {
  const output = rendered(value);

  for (const secret of SECRET_FIXTURES) {
    expect(output).not.toContain(secret);
  }

  expect(output).not.toContain('Error:');
  expect(output).not.toContain('stack');
}

describe('failure visibility and redaction contract', () => {
  it('preserves safe SchlageError codes and retryable flags through public snapshots', () => {
    const error = new SchlageError({
      code: 'SCHLAGE_AUTH_FAILED',
      message:
        'Schlage auth failed for operator@example.test with access_token=raw-access-token-value-00000000000000000000',
      retryable: true,
      cause: new Error('password=hunter2'),
    });

    expect(toPublicSchlageError(error)).toEqual({
      name: 'SchlageError',
      code: 'SCHLAGE_AUTH_FAILED',
      message:
        'Schlage auth failed for [REDACTED] with access_token=[REDACTED]',
      retryable: true,
    });
    expect(wrapUnknownSchlageError(error)).toBe(error);
    expectNoSecretText(toPublicSchlageError(error));
  });

  it('wraps malformed and unknown thrown values as non-secret unknown failures', () => {
    for (const thrown of [
      new Error(
        'password=hunter2 authorization=Bearer bearer-session-secret-00000000000000000000',
      ),
      'bearer raw-access-token-value-00000000000000000000 operator@example.test',
      {
        message: 'refresh_token=raw-refresh-token-value-00000000000000000000',
        accountId: 'account-12345',
      },
      null,
    ]) {
      const publicError = toPublicSchlageError(thrown);
      const wrapped = wrapUnknownSchlageError(thrown);

      expect(publicError).toEqual({
        name: 'SchlageError',
        code: 'SCHLAGE_UNKNOWN_ERROR',
        message:
          'Schlage operation failed. See the error code for a safe diagnostic category.',
        retryable: false,
      });
      expect(toPublicSchlageError(wrapped)).toEqual(publicError);
      expect(wrapped.cause).toBe(thrown);
      expectNoSecretText(publicError);
      expectNoSecretText(wrapped);
    }
  });

  it('redacts email, password, token, bearer, JWT, session, account, and cache-path shaped text', () => {
    const error = new SchlageError({
      code: 'SCHLAGE_CACHE_READ_FAILED',
      message:
        `operator@example.test password=hunter2 access_token=raw-access-token-value-00000000000000000000 refresh_token=raw-refresh-token-value-00000000000000000000 authorization=Bearer bearer-session-secret-00000000000000000000 jwt=${FAKE_JWT} session=raw-session-value-00000000000000000000 accountId=account-12345 cache=/tmp/schlage-cache/token-cache.json`,
      retryable: true,
    });

    const publicError = toPublicSchlageError(error);

    expect(publicError).toMatchObject({
      code: 'SCHLAGE_CACHE_READ_FAILED',
      retryable: true,
    });
    expectNoSecretText(publicError);
    expect(publicError.message).toContain('[REDACTED]');
  });

  it('classifies retryable transport, rate-limit, auth, protocol, and cache failure categories without prose branching', () => {
    const cases: ReadonlyArray<{
      readonly input: unknown;
      readonly expected: {
        readonly code: SchlageErrorCode;
        readonly retryable: boolean;
      };
    }> = [
      {
        input: { code: 'ETIMEDOUT' },
        expected: { code: 'SCHLAGE_PROTOCOL_TRANSPORT', retryable: true },
      },
      {
        input: { code: 'ECONNRESET' },
        expected: { code: 'SCHLAGE_PROTOCOL_TRANSPORT', retryable: true },
      },
      {
        input: { status: 429 },
        expected: { code: 'SCHLAGE_RATE_LIMITED', retryable: true },
      },
      {
        input: { statusCode: 401 },
        expected: { code: 'SCHLAGE_AUTH_FAILED', retryable: false },
      },
      {
        input: { statusCode: 403 },
        expected: { code: 'SCHLAGE_AUTH_FAILED', retryable: false },
      },
      {
        input: { statusCode: 502 },
        expected: { code: 'SCHLAGE_PROTOCOL_TRANSPORT', retryable: true },
      },
      {
        input: { code: 'ENOENT' },
        expected: { code: 'SCHLAGE_CACHE_READ_FAILED', retryable: false },
      },
      {
        input: { code: 'EACCES' },
        expected: { code: 'SCHLAGE_CACHE_REJECTED', retryable: false },
      },
    ];

    for (const { input, expected } of cases) {
      expect(classifySchlageFailure(input)).toEqual(expected);
    }
  });

  it('uses classification when wrapping unknown transport-style failures', () => {
    const rateLimited = wrapUnknownSchlageError({
      statusCode: 429,
      message:
        'rate limited for token=raw-access-token-value-00000000000000000000',
    });
    const timeout = wrapUnknownSchlageError({
      code: 'ETIMEDOUT',
      message: 'timeout for operator@example.test',
    });

    expect(toPublicSchlageError(rateLimited)).toEqual({
      name: 'SchlageError',
      code: 'SCHLAGE_RATE_LIMITED',
      message:
        'Schlage operation failed. See the error code for a safe diagnostic category.',
      retryable: true,
    });
    expect(toPublicSchlageError(timeout)).toEqual({
      name: 'SchlageError',
      code: 'SCHLAGE_PROTOCOL_TRANSPORT',
      message:
        'Schlage operation failed. See the error code for a safe diagnostic category.',
      retryable: true,
    });
    expectNoSecretText(rateLimited);
    expectNoSecretText(timeout);
  });
});
