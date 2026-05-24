import { readFileSync } from 'node:fs';
import { parse as parseYaml } from 'yaml';
import { validateSchlageCredentials, type SchlageCredentials } from './auth.js';
import { SchlageError } from './errors.js';

export type SchlageConfigValueSource = 'explicit' | 'yaml' | 'environment';

export interface SchlageConfigEnvironment {
  readonly [name: string]: string | undefined;
}

export interface SchlageConfigOptions {
  readonly username?: string;
  readonly password?: string;
  readonly lockId?: string;
  readonly cacheDir?: string;
  readonly configPath?: string;
  readonly configText?: string;
  readonly env?: SchlageConfigEnvironment;
}

export interface SchlageDiagnosticsConfig {
  readonly redactedOutputDir?: string;
}

export interface ResolvedSchlageConfig {
  readonly credentials: SchlageCredentials;
  readonly lockId?: string;
  readonly cacheDir?: string;
  readonly diagnostics: SchlageDiagnosticsConfig;
  readonly sources: {
    readonly username: SchlageConfigValueSource;
    readonly password: SchlageConfigValueSource;
    readonly lockId?: SchlageConfigValueSource;
    readonly cacheDir?: SchlageConfigValueSource;
    readonly diagnosticsRedactedOutputDir?: SchlageConfigValueSource;
  };
}

export interface PublicSchlageConfigSnapshot {
  readonly hasCredentials: boolean;
  readonly username: '[REDACTED_USERNAME]' | null;
  readonly lockIdConfigured: boolean;
  readonly cacheDirConfigured: boolean;
  readonly diagnosticsOutputConfigured: boolean;
  readonly sources: ResolvedSchlageConfig['sources'];
}

export interface SchlageYamlConfig {
  readonly schlage: {
    readonly username?: string;
    readonly usernameEnv?: string;
    readonly password?: string;
    readonly passwordEnv?: string;
    readonly lockId?: string;
    readonly lockIdEnv?: string;
    readonly cacheDir?: string;
    readonly cacheDirEnv?: string;
  };
  readonly diagnostics?: {
    readonly redactedOutputDir?: string;
    readonly redactedOutputDirEnv?: string;
  };
}

interface ResolvedValue {
  readonly value?: string;
  readonly source?: SchlageConfigValueSource;
}

const DEFAULT_ENV = process.env;

export function resolveSchlageConfig(
  options: SchlageConfigOptions = {},
): ResolvedSchlageConfig {
  const env = options.env ?? DEFAULT_ENV;
  const yamlConfig = loadYamlConfig(options, env);

  const username = firstResolvedValue(
    fromExplicit(options.username),
    fromYamlValue(yamlConfig?.schlage.username),
    fromEnvReference(yamlConfig?.schlage.usernameEnv, env),
    fromEnvReference('SCHLAGE_USERNAME', env),
  );
  const password = firstResolvedValue(
    fromExplicit(options.password),
    fromYamlValue(yamlConfig?.schlage.password),
    fromEnvReference(yamlConfig?.schlage.passwordEnv, env),
    fromEnvReference('SCHLAGE_PASSWORD', env),
  );
  const lockId = firstResolvedValue(
    fromExplicit(options.lockId),
    fromYamlValue(yamlConfig?.schlage.lockId),
    fromEnvReference(yamlConfig?.schlage.lockIdEnv, env),
    fromEnvReference('SCHLAGE_LOCK_ID', env),
  );
  const cacheDir = firstResolvedValue(
    fromExplicit(options.cacheDir),
    fromYamlValue(yamlConfig?.schlage.cacheDir),
    fromEnvReference(yamlConfig?.schlage.cacheDirEnv, env),
    fromEnvReference('SCHLAGE_CACHE_DIR', env),
  );
  const diagnosticsRedactedOutputDir = firstResolvedValue(
    fromYamlValue(yamlConfig?.diagnostics?.redactedOutputDir),
    fromEnvReference(yamlConfig?.diagnostics?.redactedOutputDirEnv, env),
  );

  const credentials = validateSchlageCredentials({
    username: username.value,
    password: password.value,
  });

  return {
    credentials,
    ...(lockId.value === undefined ? {} : { lockId: lockId.value }),
    ...(cacheDir.value === undefined ? {} : { cacheDir: cacheDir.value }),
    diagnostics: {
      ...(diagnosticsRedactedOutputDir.value === undefined
        ? {}
        : { redactedOutputDir: diagnosticsRedactedOutputDir.value }),
    },
    sources: {
      username: requireSource(username, 'username'),
      password: requireSource(password, 'password'),
      ...(lockId.source === undefined ? {} : { lockId: lockId.source }),
      ...(cacheDir.source === undefined ? {} : { cacheDir: cacheDir.source }),
      ...(diagnosticsRedactedOutputDir.source === undefined
        ? {}
        : {
            diagnosticsRedactedOutputDir: diagnosticsRedactedOutputDir.source,
          }),
    },
  };
}

export function createPublicSchlageConfigSnapshot(
  config: ResolvedSchlageConfig,
): PublicSchlageConfigSnapshot {
  return {
    hasCredentials: true,
    username: '[REDACTED_USERNAME]',
    lockIdConfigured: config.lockId !== undefined,
    cacheDirConfigured: config.cacheDir !== undefined,
    diagnosticsOutputConfigured:
      config.diagnostics.redactedOutputDir !== undefined,
    sources: config.sources,
  };
}

export function parseSchlageConfigYaml(configText: string): SchlageYamlConfig {
  let parsed: unknown;

  try {
    parsed = parseYaml(configText);
  } catch (error) {
    throw new SchlageError({
      code: 'SCHLAGE_CONFIG_MALFORMED',
      message: 'Schlage config YAML could not be parsed.',
      cause: error,
    });
  }

  if (!isRecord(parsed)) {
    throw malformedConfig('Schlage config must be a YAML mapping.');
  }

  const schlage = parsed.schlage;
  if (!isRecord(schlage)) {
    throw malformedConfig('Schlage config must include a schlage mapping.');
  }

  const diagnostics = parsed.diagnostics;
  if (diagnostics !== undefined && !isRecord(diagnostics)) {
    throw malformedConfig(
      'Schlage config diagnostics section must be a mapping.',
    );
  }

  rejectUnknownKeys(parsed, ['schlage', 'diagnostics'], 'root');
  rejectUnknownKeys(
    schlage,
    [
      'username',
      'usernameEnv',
      'password',
      'passwordEnv',
      'lockId',
      'lockIdEnv',
      'cacheDir',
      'cacheDirEnv',
    ],
    'schlage',
  );

  if (diagnostics !== undefined) {
    rejectUnknownKeys(
      diagnostics,
      ['redactedOutputDir', 'redactedOutputDirEnv'],
      'diagnostics',
    );
  }

  return {
    schlage: {
      ...(optionalString(schlage.username, 'schlage.username') === undefined
        ? {}
        : { username: optionalString(schlage.username, 'schlage.username') }),
      ...(optionalString(schlage.usernameEnv, 'schlage.usernameEnv') ===
      undefined
        ? {}
        : {
            usernameEnv: optionalString(
              schlage.usernameEnv,
              'schlage.usernameEnv',
            ),
          }),
      ...(optionalString(schlage.password, 'schlage.password') === undefined
        ? {}
        : { password: optionalString(schlage.password, 'schlage.password') }),
      ...(optionalString(schlage.passwordEnv, 'schlage.passwordEnv') ===
      undefined
        ? {}
        : {
            passwordEnv: optionalString(
              schlage.passwordEnv,
              'schlage.passwordEnv',
            ),
          }),
      ...(optionalString(schlage.lockId, 'schlage.lockId') === undefined
        ? {}
        : { lockId: optionalString(schlage.lockId, 'schlage.lockId') }),
      ...(optionalString(schlage.lockIdEnv, 'schlage.lockIdEnv') === undefined
        ? {}
        : {
            lockIdEnv: optionalString(schlage.lockIdEnv, 'schlage.lockIdEnv'),
          }),
      ...(optionalString(schlage.cacheDir, 'schlage.cacheDir') === undefined
        ? {}
        : { cacheDir: optionalString(schlage.cacheDir, 'schlage.cacheDir') }),
      ...(optionalString(schlage.cacheDirEnv, 'schlage.cacheDirEnv') ===
      undefined
        ? {}
        : {
            cacheDirEnv: optionalString(
              schlage.cacheDirEnv,
              'schlage.cacheDirEnv',
            ),
          }),
    },
    ...(diagnostics === undefined
      ? {}
      : {
          diagnostics: {
            ...(optionalString(
              diagnostics.redactedOutputDir,
              'diagnostics.redactedOutputDir',
            ) === undefined
              ? {}
              : {
                  redactedOutputDir: optionalString(
                    diagnostics.redactedOutputDir,
                    'diagnostics.redactedOutputDir',
                  ),
                }),
            ...(optionalString(
              diagnostics.redactedOutputDirEnv,
              'diagnostics.redactedOutputDirEnv',
            ) === undefined
              ? {}
              : {
                  redactedOutputDirEnv: optionalString(
                    diagnostics.redactedOutputDirEnv,
                    'diagnostics.redactedOutputDirEnv',
                  ),
                }),
          },
        }),
  };
}

function loadYamlConfig(
  options: SchlageConfigOptions,
  env: SchlageConfigEnvironment,
): SchlageYamlConfig | undefined {
  if (options.configText !== undefined) {
    return parseSchlageConfigYaml(options.configText);
  }

  const configPath =
    trimToUndefined(options.configPath) ?? trimToUndefined(env.SCHLAGE_CONFIG);
  if (configPath === undefined) {
    return undefined;
  }

  try {
    return parseSchlageConfigYaml(readFileSync(configPath, 'utf8'));
  } catch (error) {
    if (error instanceof SchlageError) {
      throw error;
    }

    throw new SchlageError({
      code: 'SCHLAGE_CONFIG_READ_FAILED',
      message: 'Schlage config file could not be read.',
      cause: error,
    });
  }
}

function fromExplicit(value: string | undefined): ResolvedValue {
  return fromString(value, 'explicit');
}

function fromYamlValue(value: string | undefined): ResolvedValue {
  return fromString(value, 'yaml');
}

function fromEnvReference(
  name: string | undefined,
  env: SchlageConfigEnvironment,
): ResolvedValue {
  const envName = trimToUndefined(name);
  if (envName === undefined) {
    return {};
  }

  return fromString(env[envName], 'environment');
}

function fromString(
  value: string | undefined,
  source: SchlageConfigValueSource,
): ResolvedValue {
  const trimmed = trimToUndefined(value);
  return trimmed === undefined ? {} : { value: trimmed, source };
}

function firstResolvedValue(
  ...values: readonly ResolvedValue[]
): ResolvedValue {
  return values.find((value) => value.value !== undefined) ?? {};
}

function requireSource(
  value: ResolvedValue,
  fieldName: string,
): SchlageConfigValueSource {
  if (value.source === undefined) {
    throw new SchlageError({
      code: 'SCHLAGE_CONFIG_MISSING_CREDENTIALS',
      message: `Schlage ${fieldName} is required.`,
    });
  }

  return value.source;
}

function malformedConfig(message: string): SchlageError {
  return new SchlageError({ code: 'SCHLAGE_CONFIG_MALFORMED', message });
}

function rejectUnknownKeys(
  record: Record<string, unknown>,
  allowedKeys: readonly string[],
  section: string,
): void {
  for (const key of Object.keys(record)) {
    if (!allowedKeys.includes(key)) {
      throw malformedConfig(
        `Schlage config ${section} section includes an unsupported field.`,
      );
    }
  }
}

function optionalString(value: unknown, fieldName: string): string | undefined {
  if (value === undefined) {
    return undefined;
  }

  if (typeof value !== 'string') {
    throw malformedConfig(`Schlage config ${fieldName} must be a string.`);
  }

  return value;
}

function trimToUndefined(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  return trimmed === undefined || trimmed.length === 0 ? undefined : trimmed;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
