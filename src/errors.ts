const DEFAULT_SAFE_MESSAGE =
  'Schlage operation failed. See the error code for a safe diagnostic category.';

export type SchlageErrorCode =
  | 'SCHLAGE_CONFIG_MISSING_CREDENTIALS'
  | 'SCHLAGE_CONFIG_MALFORMED'
  | 'SCHLAGE_CONFIG_READ_FAILED'
  | 'SCHLAGE_CACHE_MALFORMED'
  | 'SCHLAGE_CACHE_REJECTED'
  | 'SCHLAGE_CACHE_READ_FAILED'
  | 'SCHLAGE_CACHE_WRITE_FAILED'
  | 'SCHLAGE_AUTH_FAILED'
  | 'SCHLAGE_AUTH_PROTOCOL'
  | 'SCHLAGE_RATE_LIMITED'
  | 'SCHLAGE_LOCK_ID_INVALID'
  | 'SCHLAGE_PROTOCOL_MALFORMED'
  | 'SCHLAGE_PROTOCOL_TRANSPORT'
  | 'SCHLAGE_UNKNOWN_ERROR'
  | 'SCHLAGE_NOT_IMPLEMENTED';

export interface SchlageErrorOptions {
  readonly code: SchlageErrorCode;
  readonly message: string;
  readonly cause?: unknown;
  readonly retryable?: boolean;
}

export interface PublicSchlageErrorSnapshot {
  readonly name: 'SchlageError';
  readonly code: SchlageErrorCode;
  readonly message: string;
  readonly retryable: boolean;
}

export interface SchlageFailureClassification {
  readonly code: SchlageErrorCode;
  readonly retryable: boolean;
}

const TRANSPORT_ERROR_CODES = new Set([
  'ECONNABORTED',
  'ECONNRESET',
  'ENETDOWN',
  'ENETUNREACH',
  'EPIPE',
  'ETIMEDOUT',
]);
const CACHE_REJECTED_ERROR_CODES = new Set(['EACCES', 'EPERM']);
const CACHE_READ_ERROR_CODES = new Set(['ENOENT', 'ENOTDIR']);

export class SchlageError extends Error {
  readonly code: SchlageErrorCode;
  readonly retryable: boolean;

  constructor(options: SchlageErrorOptions) {
    super(redactUnsafeText(options.message), { cause: options.cause });
    this.name = 'SchlageError';
    this.code = options.code;
    this.retryable = options.retryable ?? false;
  }

  toJSON(): PublicSchlageErrorSnapshot {
    return {
      name: 'SchlageError',
      code: this.code,
      message: this.message,
      retryable: this.retryable,
    };
  }
}

export function isSchlageError(error: unknown): error is SchlageError {
  return error instanceof SchlageError;
}

export function toPublicSchlageError(
  error: unknown,
): PublicSchlageErrorSnapshot {
  if (error instanceof SchlageError) {
    return error.toJSON();
  }

  return {
    name: 'SchlageError',
    code: 'SCHLAGE_UNKNOWN_ERROR',
    message: DEFAULT_SAFE_MESSAGE,
    retryable: false,
  };
}

export function wrapUnknownSchlageError(
  error: unknown,
  message = DEFAULT_SAFE_MESSAGE,
): SchlageError {
  if (error instanceof SchlageError) {
    return error;
  }

  const classification = classifySchlageFailure(error);

  return new SchlageError({
    code: classification.code,
    message,
    cause: error,
    retryable: classification.retryable,
  });
}

export function classifySchlageFailure(
  error: unknown,
): SchlageFailureClassification {
  const status =
    readNumericProperty(error, 'status') ??
    readNumericProperty(error, 'statusCode');
  if (status === 429) {
    return { code: 'SCHLAGE_RATE_LIMITED', retryable: true };
  }

  if (status === 401 || status === 403) {
    return { code: 'SCHLAGE_AUTH_FAILED', retryable: false };
  }

  if (status !== undefined && (status === 408 || status >= 500)) {
    return { code: 'SCHLAGE_PROTOCOL_TRANSPORT', retryable: true };
  }

  const code = readStringProperty(error, 'code')?.toUpperCase();
  if (code !== undefined) {
    if (TRANSPORT_ERROR_CODES.has(code)) {
      return { code: 'SCHLAGE_PROTOCOL_TRANSPORT', retryable: true };
    }

    if (CACHE_REJECTED_ERROR_CODES.has(code)) {
      return { code: 'SCHLAGE_CACHE_REJECTED', retryable: false };
    }

    if (CACHE_READ_ERROR_CODES.has(code)) {
      return { code: 'SCHLAGE_CACHE_READ_FAILED', retryable: false };
    }
  }

  return { code: 'SCHLAGE_UNKNOWN_ERROR', retryable: false };
}

export function redactUnsafeText(value: string): string {
  return value
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/giu, '[REDACTED]')
    .replace(
      /\b(password|passcode|token|access_token|refresh_token|session|secret|authorization|jwt|accountId|account_id|cache|cacheDir|cache_dir)\b\s*[:=]\s*[^\s,;)}\]]+/giu,
      '$1=[REDACTED]',
    )
    .replace(/\b(bearer|basic)\s+[a-z0-9._~+/=-]+/giu, '$1 [REDACTED]')
    .replace(
      /\b[a-z0-9_-]{20,}\.[a-z0-9_-]{20,}\.[a-z0-9_-]{12,}\b/giu,
      '[REDACTED_TOKEN]',
    )
    .replace(
      /\b(?:bearer|session|schlage|refresh|access)?token[-_a-z0-9]{16,}\b/giu,
      '[REDACTED_TOKEN]',
    )
    .replace(
      /\b(?:bearer|session|secret|access|refresh)[-_a-z0-9]{16,}\b/giu,
      '[REDACTED_TOKEN]',
    )
    .replace(/\baccount[-_a-z0-9]{6,}\b/giu, '[REDACTED_ACCOUNT]')
    .replace(
      /(?:~|\.{0,2}\/|\b[A-Z]:\\|\/)[^\s,;)}\]]*(?:schlage|cache)[^\s,;)}\]]*/giu,
      '[REDACTED_PATH]',
    );
}

function readNumericProperty(
  value: unknown,
  property: 'status' | 'statusCode',
): number | undefined {
  if (!isRecord(value)) {
    return undefined;
  }

  const propertyValue = value[property];
  return typeof propertyValue === 'number' && Number.isFinite(propertyValue)
    ? propertyValue
    : undefined;
}

function readStringProperty(
  value: unknown,
  property: 'code',
): string | undefined {
  if (!isRecord(value)) {
    return undefined;
  }

  const propertyValue = value[property];
  return typeof propertyValue === 'string' && propertyValue.trim().length > 0
    ? propertyValue.trim()
    : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}
