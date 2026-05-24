import { execFileSync } from 'node:child_process';
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { afterEach, describe, expect, it } from 'vitest';

const repoRoot = join(import.meta.dirname, '..');
const scriptPath = join(repoRoot, 'scripts/verify-s07-live.sh');
const tempRoots: string[] = [];

interface ScriptResult {
  readonly status: number;
  readonly stdout: string;
  readonly stderr: string;
}

async function tempDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'schlage-live-verifier-test-'));
  tempRoots.push(dir);
  return dir;
}

function runVerifier(
  args: readonly string[] = [],
  env: NodeJS.ProcessEnv = {},
): ScriptResult {
  try {
    const stdout = execFileSync('bash', [scriptPath, ...args], {
      cwd: repoRoot,
      env: { PATH: process.env.PATH, SCHLAGE_S07_SKIP_DOTENV: '1', ...env },
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    return { status: 0, stdout, stderr: '' };
  } catch (error) {
    const failure = error as {
      status?: number;
      stdout?: Buffer | string;
      stderr?: Buffer | string;
    };
    return {
      status: failure.status ?? 1,
      stdout: failure.stdout?.toString() ?? '',
      stderr: failure.stderr?.toString() ?? '',
    };
  }
}

async function writeFakeCli(root: string): Promise<string> {
  const path = join(root, 'fake-cli.mjs');
  await writeFile(
    path,
    `#!/usr/bin/env node
import { appendFileSync, readFileSync, writeFileSync } from 'node:fs';
const [command, lockId] = process.argv.slice(2);
const scenario = process.env.FAKE_S07_SCENARIO ?? 'success';
if (process.env.FAKE_S07_CALL_LOG) appendFileSync(process.env.FAKE_S07_CALL_LOG, command + '\\n');
const statePath = process.env.FAKE_S07_STATE_FILE;
function readState() { if (!statePath) return 'unlocked'; try { return readFileSync(statePath, 'utf8').trim() || 'unlocked'; } catch { return 'unlocked'; } }
function writeState(state) { if (statePath) writeFileSync(statePath, state); }
function delayedStatusState() {
  const state = readState();
  const delay = Number(process.env.FAKE_S07_UNLOCK_STATUS_DELAY_COUNT ?? '0');
  const counterPath = process.env.FAKE_S07_UNLOCK_STATUS_COUNTER_FILE;
  if (state !== 'unlocked' || !counterPath || !Number.isInteger(delay) || delay <= 0) return state;
  let count = 0;
  try { count = Number(readFileSync(counterPath, 'utf8').trim() || '0'); } catch {}
  count += 1;
  writeFileSync(counterPath, String(count));
  return count <= delay ? 'locked' : 'unlocked';
}
function emit(payload, stream = process.stdout) { stream.write(JSON.stringify(payload, null, 2) + '\\n'); }
const base = { config: { hasCredentials: true, username: '[REDACTED_USERNAME]', lockIdConfigured: true, cacheDirConfigured: false, diagnosticsOutputConfigured: false, sources: { username: 'environment', password: 'environment', lockId: 'environment' } }, auth: { phase: 'authenticated', username: '[REDACTED_USERNAME]', authenticated: true, cache: { status: 'missing' } } };
if (scenario === 'malformed' && command === 'auth-check') { process.stdout.write('{not-json'); process.exit(0); }
if (scenario === 'nonzero' && command === 'list-locks') { emit({ ok: false, command, ...base, error: { name: 'SchlageError', code: 'SCHLAGE_PROTOCOL_TRANSPORT', message: 'safe failure', retryable: true } }, process.stderr); process.exit(9); }
if (scenario === 'leak' && command === 'auth-check') { process.stdout.write(process.env.SCHLAGE_PASSWORD ?? 'missing'); process.exit(0); }
if (command === 'auth-check') emit({ ok: true, command, ...base });
else if (command === 'list-locks') emit({ ok: true, command, ...base, data: { locks: [{ id: lockId ?? process.env.SCHLAGE_LOCK_ID, name: 'Front Door' }] } });
else if (command === 'status') emit({ ok: true, command, ...base, data: { status: { id: lockId, state: delayedStatusState(), batteryLevel: 91 } } });
else if (command === 'lock') { writeState('locked'); emit({ ok: true, command, ...base, data: { result: { id: lockId, accepted: true, observedState: 'locked' } } }); }
else if (command === 'unlock') { writeState('unlocked'); if (process.env.FAKE_S07_UNLOCK_STATUS_COUNTER_FILE) writeFileSync(process.env.FAKE_S07_UNLOCK_STATUS_COUNTER_FILE, '0'); emit({ ok: true, command, ...base, data: { result: { id: lockId, accepted: true, observedState: 'unlocked' } } }); }
else { emit({ ok: false, command, error: { name: 'SchlageError', code: 'SCHLAGE_UNKNOWN_ERROR', message: 'unknown command', retryable: false } }, process.stderr); process.exit(2); }
`,
    'utf8',
  );
  await chmod(path, 0o755);
  return path;
}

afterEach(async () => {
  await Promise.all(
    tempRoots.splice(0).map((dir) => rm(dir, { force: true, recursive: true })),
  );
});

describe('S07 live verifier harness', () => {
  it('prints help without requiring live credentials or secret examples', () => {
    const result = runVerifier(['--help']);

    expect(result.status).toBe(0);
    expect(result.stdout).toContain('verify-s07-live.sh');
    expect(result.stdout).toContain('SCHLAGE_USERNAME');
    expect(result.stdout).toContain('SCHLAGE_PASSWORD');
    expect(result.stdout).toContain('SCHLAGE_LOCK_ID');
    expect(result.stdout).not.toContain('SCHLAGE_PASSWORD=');
  });

  it('preflights missing required keys before guardrails, builds, or network-capable CLI calls', () => {
    const result = runVerifier(['--preflight']);

    expect(result.status).toBe(3);
    expect(result.stdout).toBe('');
    expect(result.stderr).toContain('SCHLAGE_USERNAME');
    expect(result.stderr).toContain('SCHLAGE_PASSWORD');
    expect(result.stderr).toContain('SCHLAGE_LOCK_ID');
    expect(result.stderr).not.toContain('password=');
  });

  it('accepts YAML env indirection during no-live preflight without printing values', async () => {
    const root = await tempDir();
    const configPath = join(root, 'config.yaml');
    await writeFile(
      configPath,
      'schlage:\n  usernameEnv: LIVE_USER\n  passwordEnv: LIVE_PASS\n  lockIdEnv: LIVE_LOCK\n',
      'utf8',
    );

    const result = runVerifier(['--preflight'], {
      SCHLAGE_CONFIG: configPath,
      LIVE_USER: 'operator@example.test',
      LIVE_PASS: 'password=live-secret',
      LIVE_LOCK: 'front-door',
    });

    expect(result.status).toBe(0);
    expect(result.stdout).toContain('S07 preflight passed');
    expect(result.stdout).not.toContain('operator@example.test');
    expect(result.stdout).not.toContain('live-secret');
    expect(result.stdout).not.toContain('front-door');
  });

  it('accepts local dotenv configuration during no-live preflight without printing values', async () => {
    const root = await tempDir();
    const dotenvPath = join(root, '.env');
    await writeFile(
      dotenvPath,
      "SCHLAGE_USERNAME=operator@example.test\nSCHLAGE_PASSWORD='password=live-secret'\nSCHLAGE_LOCK_ID=front-door\n",
      'utf8',
    );

    const result = runVerifier(['--preflight'], {
      SCHLAGE_S07_SKIP_DOTENV: '',
      SCHLAGE_S07_DOTENV_PATH: dotenvPath,
    });

    expect(result.status).toBe(0);
    expect(result.stdout).toContain('S07 preflight passed');
    expect(result.stdout).not.toContain('operator@example.test');
    expect(result.stdout).not.toContain('live-secret');
    expect(result.stdout).not.toContain('front-door');
  });

  it('runs the synthetic full sequence, validates envelopes, and writes a redacted phase summary', async () => {
    const root = await tempDir();
    const fakeCli = await writeFakeCli(root);
    const diagDir = join(root, 'diag');

    const result = runVerifier([], {
      SCHLAGE_USERNAME: 'operator@example.test',
      SCHLAGE_PASSWORD: 'password=live-secret',
      SCHLAGE_LOCK_ID: 'front-door',
      SCHLAGE_S07_CLI: fakeCli,
      SCHLAGE_S07_DIAGNOSTICS_DIR: diagDir,
      SCHLAGE_S07_SKIP_GUARDRAIL: '1',
      SCHLAGE_S07_SKIP_BUILD: '1',
      SCHLAGE_S07_STATUS_ATTEMPTS: '1',
      SCHLAGE_S07_STATUS_DELAY: '0',
      FAKE_S07_STATE_FILE: join(root, 'state.txt'),
    });

    expect(result.status).toBe(0);
    expect(result.stdout).toContain('S07 live verification passed');
    expect(result.stdout).toContain('Physical lock state will change');
    expect(result.stdout).not.toContain('live-secret');

    const summary = execFileSync(
      'node',
      [
        '-e',
        `process.stdout.write(require('node:fs').readFileSync(${JSON.stringify(join(diagDir, 'summary.tsv'))}, 'utf8'))`,
      ],
      { encoding: 'utf8' },
    );
    expect(summary).toContain('01-auth-check\tauth-check\t0');
    expect(summary).toContain('04-lock\tlock\t0');
    expect(summary).toContain('07-status-after-unlock-1\tstatus\t0');
    expect(summary).toContain('08-final-lock\tlock\t0');
    expect(summary).toContain('09-status-after-final-lock-1\tstatus\t0');
    expect(summary).not.toContain('operator@example.test');
    expect(summary).not.toContain('live-secret');
  }, 10_000);

  it('tolerates stale status reads after an accepted unlock command until bounded convergence', async () => {
    const root = await tempDir();
    const fakeCli = await writeFakeCli(root);

    const result = runVerifier([], {
      SCHLAGE_USERNAME: 'operator@example.test',
      SCHLAGE_PASSWORD: 'password=live-secret',
      SCHLAGE_LOCK_ID: 'front-door',
      SCHLAGE_S07_CLI: fakeCli,
      SCHLAGE_S07_SKIP_GUARDRAIL: '1',
      SCHLAGE_S07_SKIP_BUILD: '1',
      SCHLAGE_S07_STATUS_ATTEMPTS: '3',
      SCHLAGE_S07_STATUS_DELAY: '0',
      FAKE_S07_STATE_FILE: join(root, 'state.txt'),
      FAKE_S07_UNLOCK_STATUS_COUNTER_FILE: join(
        root,
        'unlock-status-count.txt',
      ),
      FAKE_S07_UNLOCK_STATUS_DELAY_COUNT: '2',
    });

    expect(result.status).toBe(0);
    expect(result.stdout).toContain(
      'S07 readback converged: phase=07-status-after-unlock, state=unlocked, attempt=3',
    );
    expect(result.stdout).toContain(
      'S07 readback converged: phase=09-status-after-final-lock, state=locked',
    );
    expect(result.stdout).not.toContain('live-secret');
  });

  it('fails on malformed CLI JSON capture', async () => {
    const root = await tempDir();
    const fakeCli = await writeFakeCli(root);

    const result = runVerifier([], {
      SCHLAGE_USERNAME: 'operator@example.test',
      SCHLAGE_PASSWORD: 'password=live-secret',
      SCHLAGE_LOCK_ID: 'front-door',
      SCHLAGE_S07_CLI: fakeCli,
      SCHLAGE_S07_SKIP_GUARDRAIL: '1',
      SCHLAGE_S07_SKIP_BUILD: '1',
      SCHLAGE_S07_STATUS_ATTEMPTS: '1',
      SCHLAGE_S07_STATUS_DELAY: '0',
      FAKE_S07_SCENARIO: 'malformed',
    });

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain('malformed JSON envelope');
    expect(result.stderr).not.toContain('live-secret');
  });

  it('stops subsequent state-changing commands after a nonzero command exit', async () => {
    const root = await tempDir();
    const fakeCli = await writeFakeCli(root);
    const callLog = join(root, 'calls.log');

    const result = runVerifier([], {
      SCHLAGE_USERNAME: 'operator@example.test',
      SCHLAGE_PASSWORD: 'password=live-secret',
      SCHLAGE_LOCK_ID: 'front-door',
      SCHLAGE_S07_CLI: fakeCli,
      SCHLAGE_S07_SKIP_GUARDRAIL: '1',
      SCHLAGE_S07_SKIP_BUILD: '1',
      SCHLAGE_S07_STATUS_ATTEMPTS: '1',
      SCHLAGE_S07_STATUS_DELAY: '0',
      FAKE_S07_SCENARIO: 'nonzero',
      FAKE_S07_CALL_LOG: callLog,
    });

    const calls = execFileSync(
      'node',
      [
        '-e',
        `process.stdout.write(require('node:fs').readFileSync(${JSON.stringify(callLog)}, 'utf8'))`,
      ],
      { encoding: 'utf8' },
    );
    expect(result.status).toBe(9);
    expect(calls.trim().split('\n')).toEqual(['auth-check', 'list-locks']);
    expect(result.stderr).toContain('S07 phase failed');
    expect(result.stderr).not.toContain('live-secret');
  });

  it('fails when redaction scanning finds configured secrets in captured output', async () => {
    const root = await tempDir();
    const fakeCli = await writeFakeCli(root);

    const result = runVerifier([], {
      SCHLAGE_USERNAME: 'operator@example.test',
      SCHLAGE_PASSWORD: 'password=live-secret',
      SCHLAGE_LOCK_ID: 'front-door',
      SCHLAGE_S07_CLI: fakeCli,
      SCHLAGE_S07_SKIP_GUARDRAIL: '1',
      SCHLAGE_S07_SKIP_BUILD: '1',
      SCHLAGE_S07_STATUS_ATTEMPTS: '1',
      SCHLAGE_S07_STATUS_DELAY: '0',
      FAKE_S07_SCENARIO: 'leak',
    });

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain('leaked configured secret or local path');
    expect(result.stderr).not.toContain('password=live-secret');
  });
});
