import { existsSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';
import {
  SchlageClient,
  type SchlageClientAuthTransport,
  type SchlageClientProtocolTransport,
} from '../src/index.js';
import { createCli } from '../src/cli.js';

const repoRoot = join(import.meta.dirname, '..');

function runCli(...args: string[]): string {
  return execFileSync(
    process.execPath,
    ['--import', 'tsx', join(repoRoot, 'src/cli.ts'), ...args],
    {
      cwd: repoRoot,
      encoding: 'utf8',
    },
  );
}

describe('package bootstrap', () => {
  it('declares library, CLI, and deterministic scripts', () => {
    const packageJson = JSON.parse(
      readFileSync(join(repoRoot, 'package.json'), 'utf8'),
    ) as {
      name: string;
      type: string;
      bin: Record<string, string>;
      exports: Record<string, unknown>;
      scripts: Record<string, string>;
    };

    expect(packageJson.name).toBe('schlage-ts');
    expect(packageJson.type).toBe('module');
    expect(packageJson.bin['schlage-ts']).toBe('./dist/cli.js');
    expect(packageJson.exports['.']).toBeDefined();
    expect(packageJson.scripts).toMatchObject({
      build: 'tsc',
      test: 'vitest run',
      lint: 'eslint src/ tests/',
      typecheck: 'tsc --noEmit',
      'verify:local': 'bash scripts/verify-local.sh',
      'verify:live': 'bash scripts/verify-live.sh',
      'verify:live:preflight': 'bash scripts/verify-live.sh --preflight',
    });
  });

  it('provides a repeatable S01 verification script', () => {
    const scriptPath = join(repoRoot, 'scripts/verify-s01.sh');
    const script = readFileSync(scriptPath, 'utf8');

    expect(statSync(scriptPath).mode & 0o111).not.toBe(0);
    expect(script).toContain('npm test');
    expect(script).toContain('npm run typecheck');
    expect(script).toContain('npm run lint');
    expect(script).toContain('npm run build');
    expect(script).toContain('node dist/cli.js --version');
    expect(script).toContain('node dist/cli.js --help');
    expect(script).toContain('dist/index.js');
    expect(script).toContain('dist/cli.d.ts');
  });

  it('provides a repeatable S02 verification script with auth/session guardrails', () => {
    const scriptPath = join(repoRoot, 'scripts/verify-s02.sh');
    const script = readFileSync(scriptPath, 'utf8');

    expect(statSync(scriptPath).mode & 0o111).not.toBe(0);
    expect(script).toContain('npm test');
    expect(script).toContain('npm run typecheck');
    expect(script).toContain('npm run lint');
    expect(script).toContain('npm run build');
    expect(script).toContain('node dist/cli.js --version');
    expect(script).toContain('node dist/cli.js --help');
    expect(script).toContain('dist/auth.d.ts');
    expect(script).toContain('dist/errors.d.ts');
    expect(script).toContain('dist/index.d.ts');
    expect(script).toContain('PublicSchlageAuthSnapshot');
    expect(script).toContain('SchlageErrorCode');
    expect(script).toContain('SchlageClientAuthTransport');
    expect(script).not.toContain('printenv');
    expect(script).not.toContain('SCHLAGE_PASSWORD=');
    expect(script).not.toContain('SCHLAGE_TOKEN=');
  });

  it('provides a repeatable S04 verification script with protocol declaration and redaction guardrails', () => {
    const scriptPath = join(repoRoot, 'scripts/verify-s04.sh');
    const script = readFileSync(scriptPath, 'utf8');

    expect(statSync(scriptPath).mode & 0o111).not.toBe(0);
    expect(script).toContain('npm test');
    expect(script).toContain('npm run typecheck');
    expect(script).toContain('npm run lint');
    expect(script).toContain('npm run build');
    expect(script).toContain('node dist/cli.js --version');
    expect(script).toContain('node dist/cli.js auth-check --help');
    expect(script).toContain('SchlageLockSummary');
    expect(script).toContain('SchlageLockStatus');
    expect(script).toContain('SchlageCommandResult');
    expect(script).toContain('listLocks');
    expect(script).toContain('getStatus');
    expect(script).toContain('lock');
    expect(script).toContain('unlock');
    expect(script).toContain('SCHLAGE_PROTOCOL_MALFORMED');
    expect(script).toContain('SCHLAGE_PROTOCOL_TRANSPORT');
    expect(script).toContain('verify-s04-secret');
  });

  it('provides a repeatable S05 verification script with CLI envelope and redaction guardrails', () => {
    const scriptPath = join(repoRoot, 'scripts/verify-s05.sh');
    const script = readFileSync(scriptPath, 'utf8');

    expect(statSync(scriptPath).mode & 0o111).not.toBe(0);
    expect(script).toContain('npm test');
    expect(script).toContain('npm run typecheck');
    expect(script).toContain('npm run lint');
    expect(script).toContain('npm run build');
    expect(script).toContain('node dist/cli.js --version');
    expect(script).toContain('node dist/cli.js list-locks --help');
    expect(script).toContain('node dist/cli.js unlock --help');
    expect(script).toContain('assert_json_failure');
    expect(script).toContain('run_no_transport_failure "list-locks"');
    expect(script).toContain('run_no_transport_failure "status"');
    expect(script).toContain('run_no_transport_failure "lock"');
    expect(script).toContain('run_no_transport_failure "unlock"');
    expect(script).toContain('CliSuccessPayload');
    expect(script).toContain('CliFailurePayload');
    expect(script).toContain('PublicSchlageErrorSnapshot');
    expect(script).toContain('SCHLAGE_CONFIG_MISSING_CREDENTIALS');
    expect(script).toContain('SCHLAGE_NOT_IMPLEMENTED');
    expect(script).toContain('verify-s05-secret');
  });

  it('provides a repeatable S06 verification script with failure taxonomy and redaction guardrails', () => {
    const scriptPath = join(repoRoot, 'scripts/verify-s06.sh');
    const script = readFileSync(scriptPath, 'utf8');

    expect(statSync(scriptPath).mode & 0o111).not.toBe(0);
    expect(script).toContain('tests/failure-visibility.test.ts');
    expect(script).toContain('tests/cli-commands.test.ts');
    expect(script).toContain('tests/cli-config.test.ts');
    expect(script).toContain('npm test');
    expect(script).toContain('npm run typecheck');
    expect(script).toContain('npm run lint');
    expect(script).toContain('npm run build');
    expect(script).toContain('node dist/cli.js --version');
    expect(script).toContain('assert_json_failure');
    expect(script).toContain('payload.command');
    expect(script).toContain('SCHLAGE_RATE_LIMITED');
    expect(script).toContain('SchlageFailureClassification');
    expect(script).toContain('classifySchlageFailure');
    expect(script).toContain('verify-s06-secret');
    expect(script).toContain('unexpected-command-token');
    expect(script).toContain('S06 verification passed.');
  });

  it('exports typed SchlageClient protocol contracts without contacting Schlage hardware', async () => {
    const authTransport: SchlageClientAuthTransport = {
      signIn: async () => ({
        accessToken: 'bootstrap-access-token-value-00000000000000000000',
        refreshToken: 'bootstrap-refresh-token-value-00000000000000000000',
        expiresAt: new Date('2999-01-01T00:00:00.000Z'),
        refreshedAt: new Date('2025-01-01T00:00:00.000Z'),
      }),
      refresh: async () => ({
        accessToken: 'bootstrap-access-token-value-00000000000000000000',
        refreshToken: 'bootstrap-refresh-token-value-00000000000000000000',
        expiresAt: new Date('2999-01-01T00:00:00.000Z'),
        refreshedAt: new Date('2025-01-01T00:00:00.000Z'),
      }),
    };
    const protocolTransport: SchlageClientProtocolTransport = {
      listLocks: async () => [{ id: 'front-door', name: 'Front Door' }],
      getStatus: async () => ({ state: 'locked' }),
      lock: async () => ({ accepted: true, observedState: 'locked' }),
      unlock: async () => ({ accepted: true, observedState: 'unlocked' }),
    };
    const client = new SchlageClient({
      username: 'operator@example.test',
      password: 'passphrase',
      cacheDir: './.schlage-cache',
      authTransport,
      protocolTransport,
    });

    expect(client.options.cacheDir).toBe('./.schlage-cache');
    await expect(client.listLocks()).resolves.toEqual([
      { id: 'front-door', name: 'Front Door' },
    ]);
    await expect(client.getStatus('front-door')).resolves.toMatchObject({
      id: 'front-door',
      state: 'locked',
    });
    await expect(client.lock('front-door')).resolves.toEqual({
      id: 'front-door',
      accepted: true,
      observedState: 'locked',
    });
    await expect(client.unlock('front-door')).resolves.toEqual({
      id: 'front-door',
      accepted: true,
      observedState: 'unlocked',
    });
  });

  it('prints CLI help and version without credentials', () => {
    expect(runCli('--version').trim()).toBe('0.1.0');

    const help = runCli('--help');
    expect(help).toContain('Usage: schlage-ts [options] [command]');
    expect(help).toContain('auth-check');
    expect(help).toContain('list-locks');
    expect(help).toContain('unlock');
    expect(help).not.toContain('SCHLAGE_PASSWORD=');
  });

  it('establishes gitignored local secret and cache conventions', () => {
    expect(existsSync(join(repoRoot, '.env.example'))).toBe(true);
    expect(existsSync(join(repoRoot, 'config.example.yaml'))).toBe(true);

    const gitignore = readFileSync(join(repoRoot, '.gitignore'), 'utf8');
    expect(gitignore).toContain('.schlage-cache/');
    expect(gitignore).toContain('.env');
    expect(gitignore).toContain('config.yaml');
    expect(gitignore).toContain('!config.example.yaml');
  });

  it('exposes placeholder command names through the constructed program', () => {
    const commandNames = createCli({
      name: 'schlage-ts',
      version: '0.1.0',
    }).commands.map((command) => command.name());

    expect(commandNames).toEqual([
      'auth-check',
      'list-locks',
      'status',
      'lock',
      'unlock',
      'users',
      'access-codes',
      'logs',
      'diagnostics',
      'keypad-disabled',
      'last-changed-by',
      'add-access-code',
      'update-access-code',
      'delete-access-code',
      'set-beeper',
      'set-lock-and-leave',
      'set-auto-lock-time',
    ]);
  });
});
