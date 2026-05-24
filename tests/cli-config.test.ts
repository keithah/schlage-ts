import { execFileSync } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { afterEach, describe, expect, it } from 'vitest';
import { SCHLAGE_TOKEN_CACHE_FILENAME } from '../src/index.js';

const repoRoot = join(import.meta.dirname, '..');
const tempRoots: string[] = [];

interface CliResult {
  readonly status: 0 | 1;
  readonly stdout: string;
  readonly stderr: string;
}

function runCli(
  args: readonly string[],
  env: NodeJS.ProcessEnv = {},
): CliResult {
  try {
    const stdout = execFileSync(
      process.execPath,
      ['--import', 'tsx', join(repoRoot, 'src/cli.ts'), ...args],
      {
        cwd: repoRoot,
        env: {
          PATH: process.env.PATH,
          SCHLAGE_TS_DISABLE_LIVE_TRANSPORT: '1',
          ...env,
        },
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
      },
    );
    return { status: 0, stdout, stderr: '' };
  } catch (error) {
    const failure = error as {
      stdout?: Buffer | string;
      stderr?: Buffer | string;
    };
    return {
      status: 1,
      stdout: failure.stdout?.toString() ?? '',
      stderr: failure.stderr?.toString() ?? '',
    };
  }
}

async function tempDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'schlage-cli-config-test-'));
  tempRoots.push(dir);
  return dir;
}

async function writeActiveCache(cacheDir: string): Promise<void> {
  await writeFile(
    join(cacheDir, SCHLAGE_TOKEN_CACHE_FILENAME),
    `${JSON.stringify(
      {
        accessToken: 'cli-cache-access-token-value-00000000000000000000',
        refreshToken: 'cli-cache-refresh-token-value-00000000000000000000',
        expiresAt: '2999-01-01T00:00:00.000Z',
        refreshedAt: '2025-01-01T00:00:00.000Z',
        accountId: 'cli-cache-account-secret-12345',
      },
      null,
      2,
    )}\n`,
    'utf8',
  );
}

function parseJson<T>(text: string): T {
  return JSON.parse(text) as T;
}

afterEach(async () => {
  await Promise.all(
    tempRoots.splice(0).map((dir) => rm(dir, { force: true, recursive: true })),
  );
});

describe('CLI config and cache composition', () => {
  it('prints auth-check help with shared config flags and no secret examples', () => {
    const result = runCli(['auth-check', '--help']);

    expect(result.status).toBe(0);
    expect(result.stdout).toContain('--config <path>');
    expect(result.stdout).toContain('--username <username>');
    expect(result.stdout).toContain('--password <password>');
    expect(result.stdout).toContain('--cache-dir <path>');
    expect(result.stdout).not.toContain('SCHLAGE_PASSWORD=');
  });

  it('resolves env credentials and reuses an active cache without exposing cache payloads', async () => {
    const cacheDir = await tempDir();
    await writeActiveCache(cacheDir);

    const result = runCli(['auth-check'], {
      SCHLAGE_USERNAME: 'operator@example.test',
      SCHLAGE_PASSWORD: 'password=cli-env-secret',
      SCHLAGE_CACHE_DIR: cacheDir,
    });
    const payload = parseJson<{
      ok: true;
      config: {
        username: string;
        sources: Record<string, string>;
        cacheDirConfigured: boolean;
      };
      auth: {
        authenticated: boolean;
        username: string;
        cache: { status: string };
      };
    }>(result.stdout);
    const rendered = JSON.stringify(payload);

    expect(result.status).toBe(0);
    expect(result.stderr).toBe('');
    expect(payload).toMatchObject({
      ok: true,
      config: {
        username: '[REDACTED_USERNAME]',
        cacheDirConfigured: true,
        sources: {
          username: 'environment',
          password: 'environment',
          cacheDir: 'environment',
        },
      },
      auth: {
        authenticated: true,
        username: '[REDACTED_USERNAME]',
        cache: { status: 'hit' },
      },
    });
    expect(rendered).not.toContain('operator@example.test');
    expect(rendered).not.toContain('cli-env-secret');
    expect(rendered).not.toContain('cli-cache-access-token-value');
    expect(rendered).not.toContain('cli-cache-refresh-token-value');
    expect(rendered).not.toContain('cli-cache-account-secret');
  });

  it('resolves YAML env indirection and reports the missing transport as a public typed error', async () => {
    const root = await tempDir();
    const configPath = join(root, 'config.yaml');
    const cacheDir = join(root, 'empty-cache');
    await writeFile(
      configPath,
      `schlage:\n  usernameEnv: CLI_USER\n  passwordEnv: CLI_PASS\n  cacheDir: ${JSON.stringify(cacheDir)}\n`,
      'utf8',
    );

    const result = runCli(['auth-check', '--config', configPath], {
      CLI_USER: 'yaml-operator@example.test',
      CLI_PASS: 'password=yaml-secret',
    });
    const payload = parseJson<{
      ok: false;
      config: { sources: Record<string, string> };
      auth: { error: { code: string } };
      error: { code: string; message: string };
    }>(result.stderr);
    const rendered = JSON.stringify(payload);

    expect(result.status).toBe(1);
    expect(result.stdout).toBe('');
    expect(payload.config.sources).toMatchObject({
      username: 'environment',
      password: 'environment',
      cacheDir: 'yaml',
    });
    expect(payload.auth.error.code).toBe('SCHLAGE_NOT_IMPLEMENTED');
    expect(payload.error.code).toBe('SCHLAGE_NOT_IMPLEMENTED');
    expect(rendered).not.toContain('yaml-operator@example.test');
    expect(rendered).not.toContain('yaml-secret');
  });

  it('returns safe public config errors for missing credentials, blank env indirection, malformed config, and missing files', async () => {
    const blankConfig = join(await tempDir(), 'blank.yaml');
    await writeFile(
      blankConfig,
      'schlage:\n  usernameEnv: CLI_USER\n  passwordEnv: CLI_PASS\n',
      'utf8',
    );
    const malformedConfig = join(await tempDir(), 'malformed.yaml');
    await writeFile(
      malformedConfig,
      'schlage:\n  token: token-shaped-config-secret-00000000000000000000\n',
      'utf8',
    );

    const cases = [
      {
        result: runCli(['auth-check']),
        code: 'SCHLAGE_CONFIG_MISSING_CREDENTIALS',
      },
      {
        result: runCli(['auth-check', '--config', blankConfig], {
          CLI_USER: 'operator@example.test',
          CLI_PASS: '   ',
        }),
        code: 'SCHLAGE_CONFIG_MISSING_CREDENTIALS',
      },
      {
        result: runCli(['auth-check', '--config', malformedConfig]),
        code: 'SCHLAGE_CONFIG_MALFORMED',
      },
      {
        result: runCli([
          'auth-check',
          '--config',
          '/missing/password=unsafe/token=unsafe-token-value-00000000000000000000.yaml',
        ]),
        code: 'SCHLAGE_CONFIG_READ_FAILED',
      },
    ];

    for (const { result, code } of cases) {
      const payload = parseJson<{ ok: false; error: { code: string } }>(
        result.stderr,
      );
      const rendered = JSON.stringify(payload);
      expect(result.status).toBe(1);
      expect(result.stdout).toBe('');
      expect(payload.error.code).toBe(code);
      expect(rendered).not.toContain('operator@example.test');
      expect(rendered).not.toContain('unsafe-token-value');
      expect(rendered).not.toContain('token-shaped-config-secret');
      expect(rendered).not.toContain('password=unsafe');
    }
  });

  it('reports corrupt cache status during auth-check without leaking cache contents', async () => {
    const cacheDir = await tempDir();
    await writeFile(
      join(cacheDir, SCHLAGE_TOKEN_CACHE_FILENAME),
      '{"accessToken":"cli-cache-corrupt-token-value-00000000000000000000"',
      'utf8',
    );

    const result = runCli([
      'auth-check',
      '--username',
      'operator@example.test',
      '--password',
      'password=flag-secret',
      '--cache-dir',
      cacheDir,
    ]);
    const payload = parseJson<{
      ok: false;
      auth: { cache: { status: string; error: { code: string } } };
      error: { code: string };
    }>(result.stderr);
    const rendered = JSON.stringify(payload);

    expect(result.status).toBe(1);
    expect(payload.auth.cache).toMatchObject({
      status: 'malformed',
      error: { code: 'SCHLAGE_CACHE_MALFORMED' },
    });
    expect(payload.error.code).toBe('SCHLAGE_NOT_IMPLEMENTED');
    expect(rendered).not.toContain('cli-cache-corrupt-token-value');
    expect(rendered).not.toContain('flag-secret');
    expect(rendered).not.toContain(cacheDir);
  });

  it('keeps S05 no-transport command failures safe while accepting shared config flags', async () => {
    const cacheDir = await tempDir();
    await writeActiveCache(cacheDir);

    const result = runCli(['list-locks', '--cache-dir', cacheDir], {
      SCHLAGE_USERNAME: 'operator@example.test',
      SCHLAGE_PASSWORD: 'password=placeholder-secret',
    });
    const payload = parseJson<{
      ok: false;
      config: { username: string; sources: Record<string, string> };
      auth: { phase: string; username: string; cache?: { status: string } };
      error: { code: string; message: string };
    }>(result.stderr);
    const rendered = JSON.stringify(payload);

    expect(result.status).toBe(1);
    expect(result.stdout).toBe('');
    expect(payload).toMatchObject({
      ok: false,
      config: {
        username: '[REDACTED_USERNAME]',
        sources: {
          username: 'environment',
          password: 'environment',
          cacheDir: 'explicit',
        },
      },
      auth: {
        phase: 'authenticated',
        username: '[REDACTED_USERNAME]',
        cache: { status: 'hit' },
      },
      error: { code: 'SCHLAGE_NOT_IMPLEMENTED' },
    });
    expect(rendered).not.toContain('operator@example.test');
    expect(rendered).not.toContain('placeholder-secret');
    expect(rendered).not.toContain('cli-cache-access-token-value');
    expect(rendered).not.toContain('cli-cache-refresh-token-value');
    expect(rendered).not.toContain('cli-cache-account-secret');
    expect(rendered).not.toContain(cacheDir);
  });
});
