import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  SchlageError,
  createPublicSchlageConfigSnapshot,
  parseSchlageConfigYaml,
  resolveSchlageConfig,
  toPublicSchlageError,
} from '../src/index.js';

const repoRoot = join(import.meta.dirname, '..');

function safeError(error: unknown): ReturnType<typeof toPublicSchlageError> {
  return toPublicSchlageError(error);
}

describe('Schlage config resolution', () => {
  it('resolves explicit options before YAML values and environment defaults', () => {
    const config = resolveSchlageConfig({
      username: ' explicit-user@example.test ',
      password: ' explicit-password ',
      lockId: ' explicit-lock ',
      cacheDir: './explicit-cache',
      configText: `
schlage:
  username: yaml-user@example.test
  password: yaml-password
  lockId: yaml-lock
  cacheDir: ./yaml-cache
`,
      env: {
        SCHLAGE_USERNAME: 'env-user@example.test',
        SCHLAGE_PASSWORD: 'env-password',
        SCHLAGE_LOCK_ID: 'env-lock',
        SCHLAGE_CACHE_DIR: './env-cache',
      },
    });

    expect(config).toMatchObject({
      credentials: {
        username: 'explicit-user@example.test',
        password: 'explicit-password',
      },
      lockId: 'explicit-lock',
      cacheDir: './explicit-cache',
      sources: {
        username: 'explicit',
        password: 'explicit',
        lockId: 'explicit',
        cacheDir: 'explicit',
      },
    });
  });

  it('resolves YAML direct values before process environment defaults', () => {
    const config = resolveSchlageConfig({
      configText: `
schlage:
  username: yaml-user@example.test
  password: yaml-password
  lockId: yaml-lock
  cacheDir: ./yaml-cache
diagnostics:
  redactedOutputDir: ./.schlage-cache/diagnostics
`,
      env: {
        SCHLAGE_USERNAME: 'env-user@example.test',
        SCHLAGE_PASSWORD: 'env-password',
        SCHLAGE_LOCK_ID: 'env-lock',
        SCHLAGE_CACHE_DIR: './env-cache',
      },
    });

    expect(config).toMatchObject({
      credentials: {
        username: 'yaml-user@example.test',
        password: 'yaml-password',
      },
      lockId: 'yaml-lock',
      cacheDir: './yaml-cache',
      diagnostics: { redactedOutputDir: './.schlage-cache/diagnostics' },
      sources: {
        username: 'yaml',
        password: 'yaml',
        lockId: 'yaml',
        cacheDir: 'yaml',
        diagnosticsRedactedOutputDir: 'yaml',
      },
    });
  });

  it('resolves YAML environment indirection from config.example.yaml conventions', () => {
    const exampleConfig = readFileSync(
      join(repoRoot, 'config.example.yaml'),
      'utf8',
    );
    const config = resolveSchlageConfig({
      configText: exampleConfig,
      env: {
        SCHLAGE_USERNAME: 'operator@example.test',
        SCHLAGE_PASSWORD: 'passphrase',
        SCHLAGE_LOCK_ID: 'front-door',
      },
    });

    expect(config).toMatchObject({
      credentials: {
        username: 'operator@example.test',
        password: 'passphrase',
      },
      lockId: 'front-door',
      cacheDir: './.schlage-cache',
      sources: {
        username: 'environment',
        password: 'environment',
        lockId: 'environment',
        cacheDir: 'yaml',
      },
    });
  });

  it('falls back to default environment variables when no YAML config is provided', () => {
    const config = resolveSchlageConfig({
      env: {
        SCHLAGE_USERNAME: 'operator@example.test',
        SCHLAGE_PASSWORD: 'passphrase',
        SCHLAGE_LOCK_ID: 'front-door',
        SCHLAGE_CACHE_DIR: './.schlage-cache',
      },
    });

    expect(config).toMatchObject({
      credentials: {
        username: 'operator@example.test',
        password: 'passphrase',
      },
      lockId: 'front-door',
      cacheDir: './.schlage-cache',
      sources: {
        username: 'environment',
        password: 'environment',
        lockId: 'environment',
        cacheDir: 'environment',
      },
    });
  });

  it('returns typed config errors for missing or blank credentials', () => {
    for (const options of [
      { env: {} },
      { username: ' ', password: 'passphrase', env: {} },
      {
        configText:
          'schlage:\n  usernameEnv: SCHLAGE_USERNAME\n  passwordEnv: SCHLAGE_PASSWORD\n',
        env: {},
      },
      {
        configText:
          'schlage:\n  usernameEnv: SCHLAGE_USERNAME\n  passwordEnv: SCHLAGE_PASSWORD\n',
        env: {
          SCHLAGE_USERNAME: 'operator@example.test',
          SCHLAGE_PASSWORD: '   ',
        },
      },
    ]) {
      expect(() => resolveSchlageConfig(options)).toThrow(SchlageError);
      try {
        resolveSchlageConfig(options);
      } catch (error) {
        expect(safeError(error).code).toBe(
          'SCHLAGE_CONFIG_MISSING_CREDENTIALS',
        );
      }
    }
  });

  it('maps malformed YAML and schema mistakes to safe typed config errors', () => {
    for (const configText of [
      'schlage: [unterminated',
      'diagnostics:\n  redactedOutputDir: ./.schlage-cache/diagnostics\n',
      'schlage: not-a-map\n',
      'schlage:\n  usernameEnv: 42\n  passwordEnv: SCHLAGE_PASSWORD\n',
      'schlage:\n  usernameEnv: SCHLAGE_USERNAME\n  passwordEnv: SCHLAGE_PASSWORD\n  token: unsafe-token-value-00000000000000000000\n',
      'schlage:\n  usernameEnv: SCHLAGE_USERNAME\n  passwordEnv: SCHLAGE_PASSWORD\ndiagnostics: true\n',
    ]) {
      expect(() => parseSchlageConfigYaml(configText)).toThrow(SchlageError);
      try {
        parseSchlageConfigYaml(configText);
      } catch (error) {
        const publicError = safeError(error);
        expect(publicError.code).toBe('SCHLAGE_CONFIG_MALFORMED');
        expect(JSON.stringify(publicError)).not.toContain('unsafe-token-value');
      }
    }
  });

  it('maps config file read failures without exposing path contents or file contents', () => {
    const secretShapedPath =
      '/definitely-missing/password=hunter2/token=unsafe-token-value-00000000000000000000.yaml';

    expect(() =>
      resolveSchlageConfig({ configPath: secretShapedPath, env: {} }),
    ).toThrow(SchlageError);

    try {
      resolveSchlageConfig({ configPath: secretShapedPath, env: {} });
    } catch (error) {
      const publicError = safeError(error);
      const rendered = JSON.stringify(publicError);
      expect(publicError).toMatchObject({
        code: 'SCHLAGE_CONFIG_READ_FAILED',
        message: 'Schlage config file could not be read.',
      });
      expect(rendered).not.toContain('hunter2');
      expect(rendered).not.toContain('unsafe-token-value');
      expect(rendered).not.toContain(secretShapedPath);
    }
  });

  it('creates a public config snapshot without exposing credentials or identifiers', () => {
    const config = resolveSchlageConfig({
      configText: `
schlage:
  username: operator@example.test
  password: password=unsafe-password
  lockId: lock-secret-12345
  cacheDir: ./.schlage-cache
diagnostics:
  redactedOutputDir: ./.schlage-cache/diagnostics
`,
      env: {},
    });

    const snapshot = createPublicSchlageConfigSnapshot(config);
    const rendered = JSON.stringify(snapshot);

    expect(snapshot).toEqual({
      hasCredentials: true,
      username: '[REDACTED_USERNAME]',
      lockIdConfigured: true,
      cacheDirConfigured: true,
      diagnosticsOutputConfigured: true,
      sources: {
        username: 'yaml',
        password: 'yaml',
        lockId: 'yaml',
        cacheDir: 'yaml',
        diagnosticsRedactedOutputDir: 'yaml',
      },
    });
    expect(rendered).not.toContain('operator@example.test');
    expect(rendered).not.toContain('unsafe-password');
    expect(rendered).not.toContain('lock-secret-12345');
  });
});
