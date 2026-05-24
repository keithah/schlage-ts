import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  SchlageClient,
  SchlageError,
  SchlageNotImplementedError,
  createPublicSchlageAuthSnapshot,
  type SchlageClientAuthTransport,
  type SchlageClientProtocolTransport,
} from '../src/index.js';
import {
  createCli,
  main,
  type CliClient,
  type CliRuntime,
} from '../src/cli.js';

process.env.SCHLAGE_API_KEY ??= 'test-api-key';
process.env.SCHLAGE_CLIENT_ID ??= 'test-client-id';
process.env.SCHLAGE_CLIENT_SECRET ??= 'test-client-secret';
process.env.SCHLAGE_USER_POOL_ID ??= 'us-west-2_testpool';

const tempRoots: string[] = [];

interface CapturedRun {
  readonly stdout: string;
  readonly stderr: string;
  readonly exitCode: string | number | undefined;
  readonly createClient: ReturnType<typeof vi.fn>;
  readonly client: CliClient;
}

function activeAuth() {
  return createPublicSchlageAuthSnapshot({
    phase: 'authenticated',
    username: 'operator@example.test',
    session: {
      accessToken: 'cli-command-access-token-value-00000000000000000000',
      refreshToken: 'cli-command-refresh-token-value-00000000000000000000',
      expiresAt: new Date('2999-01-01T00:00:00.000Z'),
      refreshedAt: new Date('2025-01-01T00:00:00.000Z'),
      accountId: 'cli-command-account-secret-12345',
    },
  });
}

function signedOutAuth() {
  return createPublicSchlageAuthSnapshot({
    phase: 'signed-out',
    username: 'operator@example.test',
  });
}

function liveAccessToken(subject = 'cli-live-account-secret-12345'): string {
  const payload = Buffer.from(
    JSON.stringify({ sub: subject }),
    'utf8',
  ).toString('base64url');
  return `header.${payload}.signature-value-00000000000000000000`;
}

function liveSessionPayload(subject = 'cli-live-account-secret-12345') {
  return {
    AccessToken: liveAccessToken(subject),
    RefreshToken: 'cli-live-refresh-token-value-00000000000000000000',
    ExpiresIn: 3600,
  };
}

function jsonResponse(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function createLiveFetchMock(
  options: { readonly failApiStatus?: number } = {},
) {
  return vi.fn(async (url: URL | RequestInfo, init?: RequestInit) => {
    const target =
      typeof url === 'string'
        ? url
        : url instanceof URL
          ? url.toString()
          : url.url;
    const method = init?.method ?? 'GET';

    if (target.includes('cognito-idp')) {
      const body = JSON.parse(String(init?.body ?? '{}')) as {
        AuthFlow?: string;
        ChallengeName?: string;
      };
      if (body.AuthFlow === 'USER_SRP_AUTH') {
        return jsonResponse({
          ChallengeName: 'PASSWORD_VERIFIER',
          ChallengeParameters: {
            USER_ID_FOR_SRP: 'operator@example.test',
            SALT: '00',
            SRP_B: '02',
            SECRET_BLOCK: Buffer.from(
              'synthetic-secret-block',
              'utf8',
            ).toString('base64'),
          },
        });
      }

      if (
        body.ChallengeName === 'PASSWORD_VERIFIER' ||
        body.AuthFlow === 'REFRESH_TOKEN_AUTH'
      ) {
        return jsonResponse({ AuthenticationResult: liveSessionPayload() });
      }
    }

    if (target.includes('api.allegion.yonomi.cloud')) {
      if (options.failApiStatus !== undefined) {
        return jsonResponse(
          {
            message:
              'authorization=Bearer cli-live-api-failure-token-00000000000000000000 operator@example.test',
          },
          options.failApiStatus,
        );
      }

      if (method === 'GET' && target.endsWith('/devices?archetype=lock')) {
        return jsonResponse([
          {
            deviceId: 'front-door',
            name: 'Front Door',
            attributes: { lockState: 1, batteryLevel: 91 },
            lastUpdated: '2025-01-02T03:04:05.000Z',
          },
        ]);
      }

      if (method === 'GET' && target.endsWith('/devices/front-door')) {
        return jsonResponse({
          deviceId: 'front-door',
          name: 'Front Door',
          attributes: { lockState: 1, batteryLevel: 91 },
          lastUpdated: '2025-01-02T03:04:05.000Z',
        });
      }

      if (method === 'PUT' && target.endsWith('/devices/front-door')) {
        const body = JSON.parse(String(init?.body ?? '{}')) as {
          attributes?: { lockState?: number };
        };
        return jsonResponse({
          deviceId: 'front-door',
          name: 'Front Door',
          attributes: {
            lockState: body.attributes?.lockState ?? 1,
            batteryLevel: 91,
          },
          lastUpdated: '2025-01-02T03:04:05.000Z',
        });
      }
    }

    return jsonResponse({ message: 'unexpected live mock request' }, 500);
  });
}

async function runMainWithDefaultRuntime(
  args: readonly string[],
  options: { readonly env?: CliRuntime['env'] } = {},
): Promise<Omit<CapturedRun, 'createClient' | 'client'>> {
  const originalExitCode = process.exitCode;
  process.exitCode = undefined;

  let stdout = '';
  let stderr = '';

  await main(['node', 'schlage-ts', ...args], {
    env: options.env ?? {},
    stdout: {
      write: (value: string | Uint8Array) => {
        stdout += value.toString();
        return true;
      },
    },
    stderr: {
      write: (value: string | Uint8Array) => {
        stderr += value.toString();
        return true;
      },
    },
  });

  const exitCode = process.exitCode;
  process.exitCode = originalExitCode;

  return { stdout, stderr, exitCode };
}

function commandAuthTransport(): SchlageClientAuthTransport {
  return {
    signIn: vi.fn(async () => ({
      accessToken: 'cli-command-real-access-token-value-00000000000000000000',
      refreshToken: 'cli-command-real-refresh-token-value-00000000000000000000',
      expiresAt: new Date('2999-01-01T00:00:00.000Z'),
      refreshedAt: new Date('2025-01-01T00:00:00.000Z'),
      accountId: 'cli-command-real-account-secret-12345',
    })),
    refresh: vi.fn(async () => ({
      accessToken: 'cli-command-real-access-token-value-00000000000000000000',
      refreshToken: 'cli-command-real-refresh-token-value-00000000000000000000',
      expiresAt: new Date('2999-01-01T00:00:00.000Z'),
      refreshedAt: new Date('2025-01-01T00:00:00.000Z'),
      accountId: 'cli-command-real-account-secret-12345',
    })),
  };
}

function commandProtocolTransport(
  overrides: Partial<SchlageClientProtocolTransport> = {},
): SchlageClientProtocolTransport {
  return {
    listLocks: vi.fn(async () => []),
    getStatus: vi.fn(async () => ({ state: 'locked' })),
    lock: vi.fn(async () => ({ accepted: true, observedState: 'LOCKED' })),
    unlock: vi.fn(async () => ({ accepted: true, observedState: 'UNLOCKED' })),
    ...overrides,
  };
}

function createRealCommandClient(
  protocol: SchlageClientProtocolTransport,
  auth: SchlageClientAuthTransport = commandAuthTransport(),
): SchlageClient {
  return new SchlageClient({
    username: 'operator@example.test',
    password: 'password=real-command-secret',
    authTransport: auth,
    protocolTransport: protocol,
  });
}

function createMockClient(overrides: Partial<CliClient> = {}): CliClient {
  const auth = activeAuth();

  return {
    authCheck: vi.fn(async () => auth),
    getAuthSnapshot: vi.fn(() => signedOutAuth()),
    listLocks: vi.fn(async () => [{ id: 'front-door', name: 'Front Door' }]),
    getStatus: vi.fn(async (id) => ({ id, state: 'locked' })),
    lock: vi.fn(async (id) => ({
      id,
      accepted: true,
      observedState: 'locked',
    })),
    unlock: vi.fn(async (id) => ({
      id,
      accepted: true,
      observedState: 'unlocked',
    })),
    listUsers: vi.fn(async () => [
      { id: 'user-1', name: 'Operator', email: 'operator@example.test' },
    ]),
    listAccessCodes: vi.fn(async (id) => [
      {
        id: 'code-1',
        lockId: id.trim(),
        name: 'Cleaner',
        code: '0042',
        disabled: false,
      },
    ]),
    listLogs: vi.fn(async (id) => [
      {
        lockId: id.trim(),
        createdAt: new Date('2025-01-02T03:04:05.000Z'),
        message: 'Unlocked by keypad',
        eventCode: 2,
        accessorId: 'user-1',
        accessCodeId: 'code-1',
      },
    ]),
    getDiagnostics: vi.fn(async () => ({
      deviceId: '<REDACTED>',
      name: 'Front Door',
      attributes: { batteryLevel: 91 },
    })),
    keypadDisabled: vi.fn(async () => false),
    lastChangedBy: vi.fn(async () => 'mobile device - Operator'),
    addAccessCode: vi.fn(async (id) => ({
      lockId: id.trim(),
      accepted: true,
      accessCodeId: 'code-2',
    })),
    updateAccessCode: vi.fn(async (id, accessCodeId) => ({
      lockId: id.trim(),
      accepted: true,
      accessCodeId: accessCodeId.trim(),
    })),
    deleteAccessCode: vi.fn(async (id, accessCodeId) => ({
      lockId: id.trim(),
      accepted: true,
      accessCodeId: accessCodeId.trim(),
    })),
    setBeeper: vi.fn(async (id) => ({ lockId: id.trim(), accepted: true })),
    setLockAndLeave: vi.fn(async (id) => ({
      lockId: id.trim(),
      accepted: true,
    })),
    setAutoLockTime: vi.fn(async (id) => ({
      lockId: id.trim(),
      accepted: true,
    })),
    ...overrides,
  };
}

async function tempDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'schlage-cli-commands-test-'));
  tempRoots.push(dir);
  return dir;
}

async function runMain(
  args: readonly string[],
  options: {
    readonly env?: CliRuntime['env'];
    readonly client?: CliClient;
  } = {},
): Promise<CapturedRun> {
  const originalExitCode = process.exitCode;
  process.exitCode = undefined;

  let stdout = '';
  let stderr = '';
  const client = options.client ?? createMockClient();
  const createClient = vi.fn(() => client);

  await main(['node', 'schlage-ts', ...args], {
    env: options.env ?? {},
    stdout: {
      write: (value: string | Uint8Array) => {
        stdout += value.toString();
        return true;
      },
    },
    stderr: {
      write: (value: string | Uint8Array) => {
        stderr += value.toString();
        return true;
      },
    },
    createClient,
  });

  const exitCode = process.exitCode;
  process.exitCode = originalExitCode;

  return { stdout, stderr, exitCode, createClient, client };
}

function parseJson<T>(text: string): T {
  return JSON.parse(text) as T;
}

afterEach(async () => {
  vi.unstubAllGlobals();
  await Promise.all(
    tempRoots.splice(0).map((dir) => rm(dir, { force: true, recursive: true })),
  );
});

describe('CLI command envelope seam', () => {
  it('keeps constructed command names available for command-surface smoke tests', () => {
    const stdout = { write: vi.fn(() => true) };
    const stderr = { write: vi.fn(() => true) };
    const program = createCli(
      { name: 'schlage-ts', version: '0.1.0' },
      { stdout, stderr },
    );

    expect(program.commands.map((command) => command.name())).toEqual([
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

  it('includes command names in stdout envelopes for every operator command', async () => {
    const commands: ReadonlyArray<{
      readonly args: readonly string[];
      readonly expected: string;
    }> = [
      { args: ['auth-check'], expected: 'auth-check' },
      { args: ['list-locks'], expected: 'list-locks' },
      { args: ['status', 'front-door'], expected: 'status' },
      { args: ['lock', 'front-door'], expected: 'lock' },
      { args: ['unlock', 'front-door'], expected: 'unlock' },
      { args: ['users'], expected: 'users' },
      { args: ['access-codes', 'front-door'], expected: 'access-codes' },
      { args: ['logs', 'front-door'], expected: 'logs' },
      { args: ['diagnostics', 'front-door'], expected: 'diagnostics' },
      {
        args: ['keypad-disabled', 'front-door'],
        expected: 'keypad-disabled',
      },
      {
        args: ['last-changed-by', 'front-door'],
        expected: 'last-changed-by',
      },
    ];
    const client = createMockClient({
      listUsers: vi.fn(async () => [
        { id: 'user-1', name: 'Member', email: 'member@example.test' },
      ]),
    });

    for (const { args, expected } of commands) {
      const result = await runMain(
        [
          ...args,
          '--username',
          'operator@example.test',
          '--password',
          'password=command-name-secret',
        ],
        {
          client,
        },
      );
      const payload = parseJson<{ ok: true; command: string }>(result.stdout);

      expect(result.exitCode).toBeUndefined();
      expect(result.stderr).toBe('');
      expect(payload).toMatchObject({ ok: true, command: expected });
      expect(JSON.stringify(payload)).not.toContain('operator@example.test');
      expect(JSON.stringify(payload)).not.toContain('command-name-secret');
    }
  });

  it('prints auth-check success envelopes to stdout with redacted config and auth snapshots', async () => {
    const result = await runMain(['auth-check'], {
      env: {
        SCHLAGE_USERNAME: 'operator@example.test',
        SCHLAGE_PASSWORD: 'password=cli-command-secret',
        SCHLAGE_CACHE_DIR: './.schlage-cache',
      },
    });
    const payload = parseJson<{
      ok: true;
      config: {
        username: string;
        sources: Record<string, string>;
        cacheDirConfigured: boolean;
      };
      auth: { phase: string; username: string; authenticated: boolean };
    }>(result.stdout);
    const rendered = JSON.stringify(payload);

    expect(result.exitCode).toBeUndefined();
    expect(result.stderr).toBe('');
    expect(result.createClient).toHaveBeenCalledExactlyOnceWith({
      username: 'operator@example.test',
      password: 'password=cli-command-secret',
      cacheDir: './.schlage-cache',
    });
    expect(result.client.authCheck).toHaveBeenCalledTimes(1);
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
        phase: 'authenticated',
        username: '[REDACTED_USERNAME]',
        authenticated: true,
      },
    });
    expect(rendered).not.toContain('operator@example.test');
    expect(rendered).not.toContain('cli-command-secret');
    expect(rendered).not.toContain('cli-command-access-token-value');
    expect(rendered).not.toContain('cli-command-refresh-token-value');
    expect(rendered).not.toContain('cli-command-account-secret');
  });

  it('uses the default live-backed client runtime for auth-check, list-locks, status, lock, and unlock envelopes', async () => {
    const cases: ReadonlyArray<{
      readonly args: readonly string[];
      readonly command: string;
      readonly expectedData?: unknown;
    }> = [
      { args: ['auth-check'], command: 'auth-check' },
      {
        args: ['list-locks'],
        command: 'list-locks',
        expectedData: { locks: [{ id: 'front-door', name: 'Front Door' }] },
      },
      {
        args: ['status', 'front-door'],
        command: 'status',
        expectedData: {
          status: {
            id: 'front-door',
            state: 'locked',
            batteryLevel: 91,
            updatedAt: '2025-01-02T03:04:05.000Z',
          },
        },
      },
      {
        args: ['lock', 'front-door'],
        command: 'lock',
        expectedData: {
          result: { id: 'front-door', accepted: true, observedState: 'locked' },
        },
      },
      {
        args: ['unlock', 'front-door'],
        command: 'unlock',
        expectedData: {
          result: {
            id: 'front-door',
            accepted: true,
            observedState: 'unlocked',
          },
        },
      },
    ];

    for (const { args, command, expectedData } of cases) {
      const fetch = createLiveFetchMock();
      vi.stubGlobal('fetch', fetch);

      const result = await runMainWithDefaultRuntime(args, {
        env: {
          SCHLAGE_USERNAME: 'operator@example.test',
          SCHLAGE_PASSWORD: 'password=live-runtime-secret',
        },
      });
      const payload = parseJson<{
        ok: true;
        command: string;
        config: { username: string };
        auth: { authenticated: boolean };
        data?: unknown;
      }>(result.stdout);
      const rendered = JSON.stringify(payload);

      expect(result.exitCode).toBeUndefined();
      expect(result.stderr).toBe('');
      expect(payload).toMatchObject({
        ok: true,
        command,
        config: { username: '[REDACTED_USERNAME]' },
        auth: { authenticated: true },
      });
      if (expectedData !== undefined) {
        expect(payload.data).toMatchObject(expectedData);
      }
      expect(fetch).toHaveBeenCalled();
      expect(rendered).not.toContain('operator@example.test');
      expect(rendered).not.toContain('live-runtime-secret');
      expect(rendered).not.toContain('cli-live-refresh-token-value');
      expect(rendered).not.toContain('cli-live-account-secret');
    }
  });

  it('reuses the CLI token cache with the default live runtime instead of re-authenticating', async () => {
    const cacheDir = await tempDir();
    const firstFetch = createLiveFetchMock();
    vi.stubGlobal('fetch', firstFetch);

    const first = await runMainWithDefaultRuntime(
      ['auth-check', '--cache-dir', cacheDir],
      {
        env: {
          SCHLAGE_USERNAME: 'operator@example.test',
          SCHLAGE_PASSWORD: 'password=cache-live-secret',
        },
      },
    );
    expect(first.exitCode).toBeUndefined();
    expect(first.stderr).toBe('');
    expect(
      firstFetch.mock.calls.some(([url]) =>
        String(url).includes('cognito-idp'),
      ),
    ).toBe(true);

    const secondFetch = createLiveFetchMock();
    vi.stubGlobal('fetch', secondFetch);
    const second = await runMainWithDefaultRuntime(
      ['list-locks', '--cache-dir', cacheDir],
      {
        env: {
          SCHLAGE_USERNAME: 'operator@example.test',
          SCHLAGE_PASSWORD: 'password=cache-live-secret',
        },
      },
    );
    const payload = parseJson<{
      ok: true;
      auth: { cache: { status: string } };
      data: { locks: unknown[] };
    }>(second.stdout);
    const rendered = JSON.stringify(payload);

    expect(second.exitCode).toBeUndefined();
    expect(second.stderr).toBe('');
    expect(payload).toMatchObject({
      ok: true,
      auth: { cache: { status: 'hit' } },
      data: { locks: [{ id: 'front-door', name: 'Front Door' }] },
    });
    expect(
      secondFetch.mock.calls.some(([url]) =>
        String(url).includes('cognito-idp'),
      ),
    ).toBe(false);
    expect(
      secondFetch.mock.calls.some(([url]) =>
        String(url).includes('api.allegion.yonomi.cloud'),
      ),
    ).toBe(true);
    expect(rendered).not.toContain('operator@example.test');
    expect(rendered).not.toContain('cache-live-secret');
    expect(rendered).not.toContain(cacheDir);
  });

  it('emits typed redacted live transport failures from the default CLI runtime', async () => {
    const fetch = createLiveFetchMock({ failApiStatus: 500 });
    vi.stubGlobal('fetch', fetch);

    const result = await runMainWithDefaultRuntime(['list-locks'], {
      env: {
        SCHLAGE_USERNAME: 'operator@example.test',
        SCHLAGE_PASSWORD: 'password=live-failure-secret',
      },
    });
    const payload = parseJson<{
      ok: false;
      command: string;
      error: { code: string; retryable: boolean };
      auth: { username: string };
    }>(result.stderr);
    const rendered = JSON.stringify(payload);

    expect(result.exitCode).toBe(1);
    expect(result.stdout).toBe('');
    expect(payload).toMatchObject({
      ok: false,
      command: 'list-locks',
      auth: { username: '[REDACTED_USERNAME]' },
      error: { code: 'SCHLAGE_PROTOCOL_TRANSPORT', retryable: true },
    });
    expect(rendered).not.toContain('cli-live-api-failure-token');
    expect(rendered).not.toContain('operator@example.test');
    expect(rendered).not.toContain('live-failure-secret');
  });

  it('validates blank lock IDs in the default CLI runtime before live network use', async () => {
    const fetch = createLiveFetchMock();
    vi.stubGlobal('fetch', fetch);

    const result = await runMainWithDefaultRuntime(['lock', '   '], {
      env: {
        SCHLAGE_USERNAME: 'operator@example.test',
        SCHLAGE_PASSWORD: 'password=blank-live-secret',
      },
    });
    const payload = parseJson<{
      ok: false;
      error: { code: string; retryable: boolean };
    }>(result.stderr);
    const rendered = JSON.stringify(payload);

    expect(result.exitCode).toBe(1);
    expect(result.stdout).toBe('');
    expect(fetch).not.toHaveBeenCalled();
    expect(payload).toMatchObject({
      ok: false,
      error: { code: 'SCHLAGE_LOCK_ID_INVALID', retryable: false },
    });
    expect(rendered).not.toContain('operator@example.test');
    expect(rendered).not.toContain('blank-live-secret');
  });

  it('prints missing credential failures to stderr without creating a client', async () => {
    const result = await runMain(['auth-check']);
    const payload = parseJson<{
      ok: false;
      error: { code: string; retryable: boolean };
    }>(result.stderr);

    expect(result.exitCode).toBe(1);
    expect(result.stdout).toBe('');
    expect(result.createClient).not.toHaveBeenCalled();
    expect(payload).toEqual({
      ok: false,
      command: 'auth-check',
      error: {
        name: 'SchlageError',
        code: 'SCHLAGE_CONFIG_MISSING_CREDENTIALS',
        message: 'Schlage username and password are required.',
        retryable: false,
      },
    });
  });

  it('prints malformed config failures to stderr as redacted SCHLAGE_CONFIG_MALFORMED envelopes', async () => {
    const root = await tempDir();
    const configPath = join(root, 'config.yaml');
    await writeFile(
      configPath,
      'schlage:\n  token: token-shaped-config-secret-00000000000000000000\n',
      'utf8',
    );

    const result = await runMain(['auth-check', '--config', configPath]);
    const payload = parseJson<{ ok: false; error: { code: string } }>(
      result.stderr,
    );
    const rendered = JSON.stringify(payload);

    expect(result.exitCode).toBe(1);
    expect(result.stdout).toBe('');
    expect(payload.error.code).toBe('SCHLAGE_CONFIG_MALFORMED');
    expect(rendered).not.toContain('token-shaped-config-secret');
    expect(rendered).not.toContain(configPath);
  });

  it('redacts secret-shaped unexpected throws and includes only public auth snapshots', async () => {
    const client = createMockClient({
      authCheck: vi.fn(async () => {
        throw new Error(
          'access_token=unexpected-command-token-00000000000000000000 operator@example.test',
        );
      }),
      getAuthSnapshot: vi.fn(() => signedOutAuth()),
    });

    const result = await runMain(
      [
        'auth-check',
        '--username',
        'operator@example.test',
        '--password',
        'password=unsafe-secret',
      ],
      {
        client,
      },
    );
    const payload = parseJson<{
      ok: false;
      config: { username: string };
      auth: { phase: string; username: string };
      error: { code: string; message: string };
    }>(result.stderr);
    const rendered = JSON.stringify(payload);

    expect(result.exitCode).toBe(1);
    expect(result.stdout).toBe('');
    expect(payload).toMatchObject({
      ok: false,
      config: { username: '[REDACTED_USERNAME]' },
      auth: { phase: 'signed-out', username: '[REDACTED_USERNAME]' },
      error: {
        code: 'SCHLAGE_UNKNOWN_ERROR',
        message:
          'Schlage operation failed. See the error code for a safe diagnostic category.',
      },
    });
    expect(rendered).not.toContain('unexpected-command-token');
    expect(rendered).not.toContain('operator@example.test');
    expect(rendered).not.toContain('unsafe-secret');
  });

  it('prints list-locks success envelopes with stable data.locks and no stderr output', async () => {
    const client = createMockClient({
      listLocks: vi.fn(async () => [
        { id: 'front-door', name: 'Front Door' },
        { id: 'garage-entry', name: 'Garage Entry' },
      ]),
    });

    const result = await runMain(
      [
        'list-locks',
        '--username',
        'operator@example.test',
        '--password',
        'password=list-secret',
      ],
      {
        client,
      },
    );
    const payload = parseJson<{
      ok: true;
      config: { username: string; sources: Record<string, string> };
      auth: { phase: string; username: string; authenticated: boolean };
      data: { locks: Array<{ id: string; name: string }> };
    }>(result.stdout);
    const rendered = JSON.stringify(payload);

    expect(result.exitCode).toBeUndefined();
    expect(result.stderr).toBe('');
    expect(result.createClient).toHaveBeenCalledExactlyOnceWith({
      username: 'operator@example.test',
      password: 'password=list-secret',
      cacheDir: undefined,
    });
    expect(client.listLocks).toHaveBeenCalledTimes(1);
    expect(client.authCheck).not.toHaveBeenCalled();
    expect(client.getStatus).not.toHaveBeenCalled();
    expect(client.lock).not.toHaveBeenCalled();
    expect(client.unlock).not.toHaveBeenCalled();
    expect(payload).toMatchObject({
      ok: true,
      config: {
        username: '[REDACTED_USERNAME]',
        sources: { username: 'explicit', password: 'explicit' },
      },
      auth: {
        phase: 'signed-out',
        username: '[REDACTED_USERNAME]',
        authenticated: false,
      },
      data: {
        locks: [
          { id: 'front-door', name: 'Front Door' },
          { id: 'garage-entry', name: 'Garage Entry' },
        ],
      },
    });
    expect(rendered).not.toContain('operator@example.test');
    expect(rendered).not.toContain('list-secret');
    expect(rendered).not.toContain('cli-command-access-token-value');
    expect(rendered).not.toContain('cli-command-refresh-token-value');
    expect(rendered).not.toContain('cli-command-account-secret');
  });

  it('prints empty list-locks results as data.locks without treating the response as a failure', async () => {
    const client = createMockClient({ listLocks: vi.fn(async () => []) });

    const result = await runMain(
      [
        'list-locks',
        '--username',
        'operator@example.test',
        '--password',
        'password=list-secret',
      ],
      {
        client,
      },
    );
    const payload = parseJson<{ ok: true; data: { locks: unknown[] } }>(
      result.stdout,
    );

    expect(result.exitCode).toBeUndefined();
    expect(result.stderr).toBe('');
    expect(client.listLocks).toHaveBeenCalledTimes(1);
    expect(payload).toMatchObject({ ok: true, data: { locks: [] } });
  });

  it('prints users, access-codes, logs, and helper success envelopes with stable read-only data', async () => {
    const client = createMockClient();

    const usersResult = await runMain(
      [
        'users',
        '--username',
        'operator@example.test',
        '--password',
        'password=read-secret',
      ],
      {
        client,
      },
    );
    const codesResult = await runMain(
      [
        'access-codes',
        ' front-door ',
        '--username',
        'operator@example.test',
        '--password',
        'password=read-secret',
      ],
      {
        client,
      },
    );
    const logsResult = await runMain(
      [
        'logs',
        'front-door',
        '--limit',
        '10',
        '--desc',
        '--username',
        'operator@example.test',
        '--password',
        'password=read-secret',
      ],
      {
        client,
      },
    );
    const diagnosticsResult = await runMain(
      [
        'diagnostics',
        'front-door',
        '--username',
        'operator@example.test',
        '--password',
        'password=read-secret',
      ],
      { client },
    );
    const keypadDisabledResult = await runMain(
      [
        'keypad-disabled',
        'front-door',
        '--username',
        'operator@example.test',
        '--password',
        'password=read-secret',
      ],
      { client },
    );
    const lastChangedByResult = await runMain(
      [
        'last-changed-by',
        'front-door',
        '--username',
        'operator@example.test',
        '--password',
        'password=read-secret',
      ],
      { client },
    );
    const usersPayload = parseJson<{ ok: true; data: { users: unknown[] } }>(
      usersResult.stdout,
    );
    const codesPayload = parseJson<{
      ok: true;
      data: { accessCodes: unknown[] };
    }>(codesResult.stdout);
    const logsPayload = parseJson<{ ok: true; data: { logs: unknown[] } }>(
      logsResult.stdout,
    );
    const diagnosticsPayload = parseJson<{
      ok: true;
      data: { diagnostics: unknown };
    }>(diagnosticsResult.stdout);
    const keypadDisabledPayload = parseJson<{
      ok: true;
      data: { keypadDisabled: boolean };
    }>(keypadDisabledResult.stdout);
    const lastChangedByPayload = parseJson<{
      ok: true;
      data: { lastChangedBy: string };
    }>(lastChangedByResult.stdout);
    const rendered = JSON.stringify([
      usersPayload,
      codesPayload,
      logsPayload,
      diagnosticsPayload,
      keypadDisabledPayload,
      lastChangedByPayload,
    ]);

    expect(usersResult.exitCode).toBeUndefined();
    expect(codesResult.exitCode).toBeUndefined();
    expect(logsResult.exitCode).toBeUndefined();
    expect(diagnosticsResult.exitCode).toBeUndefined();
    expect(keypadDisabledResult.exitCode).toBeUndefined();
    expect(lastChangedByResult.exitCode).toBeUndefined();
    expect(usersResult.stderr).toBe('');
    expect(codesResult.stderr).toBe('');
    expect(logsResult.stderr).toBe('');
    expect(diagnosticsResult.stderr).toBe('');
    expect(keypadDisabledResult.stderr).toBe('');
    expect(lastChangedByResult.stderr).toBe('');
    expect(client.listUsers).toHaveBeenCalledTimes(1);
    expect(client.listAccessCodes).toHaveBeenCalledExactlyOnceWith(
      ' front-door ',
    );
    expect(client.listLogs).toHaveBeenCalledExactlyOnceWith('front-door', {
      limit: 10,
      sortDesc: true,
    });
    expect(client.getDiagnostics).toHaveBeenCalledExactlyOnceWith('front-door');
    expect(client.keypadDisabled).toHaveBeenCalledExactlyOnceWith('front-door');
    expect(client.lastChangedBy).toHaveBeenCalledExactlyOnceWith('front-door');
    expect(usersPayload).toMatchObject({
      ok: true,
      data: {
        users: [
          { id: 'user-1', name: 'Operator', email: 'operator@example.test' },
        ],
      },
    });
    expect(codesPayload).toMatchObject({
      ok: true,
      data: {
        accessCodes: [
          {
            id: 'code-1',
            lockId: 'front-door',
            name: 'Cleaner',
            code: '0042',
            disabled: false,
          },
        ],
      },
    });
    expect(logsPayload).toMatchObject({
      ok: true,
      data: {
        logs: [
          {
            lockId: 'front-door',
            createdAt: '2025-01-02T03:04:05.000Z',
            message: 'Unlocked by keypad',
            eventCode: 2,
            accessorId: 'user-1',
            accessCodeId: 'code-1',
          },
        ],
      },
    });
    expect(diagnosticsPayload).toMatchObject({
      ok: true,
      data: {
        diagnostics: {
          deviceId: '<REDACTED>',
          name: 'Front Door',
          attributes: { batteryLevel: 91 },
        },
      },
    });
    expect(keypadDisabledPayload).toMatchObject({
      ok: true,
      data: { keypadDisabled: false },
    });
    expect(lastChangedByPayload).toMatchObject({
      ok: true,
      data: { lastChangedBy: 'mobile device - Operator' },
    });
    expect(rendered).not.toContain('read-secret');
  });

  it('prints write API success envelopes with stable data.write results', async () => {
    const client = createMockClient();

    const addResult = await runMain(
      [
        'add-access-code',
        ' front-door ',
        '--name',
        'Cleaner',
        '--code',
        '0042',
        '--username',
        'operator@example.test',
        '--password',
        'password=write-secret',
      ],
      { client },
    );
    const updateResult = await runMain(
      [
        'update-access-code',
        'front-door',
        ' code-1 ',
        '--name',
        'Cleaner Updated',
        '--code',
        '0043',
        '--disabled',
        '--notify',
        '--username',
        'operator@example.test',
        '--password',
        'password=write-secret',
      ],
      { client },
    );
    const deleteResult = await runMain(
      [
        'delete-access-code',
        'front-door',
        'code-1',
        '--username',
        'operator@example.test',
        '--password',
        'password=write-secret',
      ],
      { client },
    );
    const beeperResult = await runMain(
      [
        'set-beeper',
        'front-door',
        'on',
        '--username',
        'operator@example.test',
        '--password',
        'password=write-secret',
      ],
      { client },
    );
    const lockAndLeaveResult = await runMain(
      [
        'set-lock-and-leave',
        'front-door',
        'off',
        '--username',
        'operator@example.test',
        '--password',
        'password=write-secret',
      ],
      { client },
    );
    const autoLockResult = await runMain(
      [
        'set-auto-lock-time',
        'front-door',
        '60',
        '--username',
        'operator@example.test',
        '--password',
        'password=write-secret',
      ],
      { client },
    );

    const addPayload = parseJson<{ ok: true; data: { write: unknown } }>(
      addResult.stdout,
    );
    const updatePayload = parseJson<{ ok: true; data: { write: unknown } }>(
      updateResult.stdout,
    );
    const deletePayload = parseJson<{ ok: true; data: { write: unknown } }>(
      deleteResult.stdout,
    );
    const beeperPayload = parseJson<{ ok: true; data: { write: unknown } }>(
      beeperResult.stdout,
    );
    const lockAndLeavePayload = parseJson<{
      ok: true;
      data: { write: unknown };
    }>(lockAndLeaveResult.stdout);
    const autoLockPayload = parseJson<{ ok: true; data: { write: unknown } }>(
      autoLockResult.stdout,
    );
    const rendered = JSON.stringify([
      addPayload,
      updatePayload,
      deletePayload,
      beeperPayload,
      lockAndLeavePayload,
      autoLockPayload,
    ]);

    expect(client.addAccessCode).toHaveBeenCalledExactlyOnceWith(
      ' front-door ',
      {
        name: 'Cleaner',
        code: '0042',
      },
    );
    expect(client.updateAccessCode).toHaveBeenCalledExactlyOnceWith(
      'front-door',
      ' code-1 ',
      {
        name: 'Cleaner Updated',
        code: '0043',
        disabled: true,
        notifyOnUse: true,
      },
    );
    expect(client.deleteAccessCode).toHaveBeenCalledExactlyOnceWith(
      'front-door',
      'code-1',
    );
    expect(client.setBeeper).toHaveBeenCalledExactlyOnceWith(
      'front-door',
      true,
    );
    expect(client.setLockAndLeave).toHaveBeenCalledExactlyOnceWith(
      'front-door',
      false,
    );
    expect(client.setAutoLockTime).toHaveBeenCalledExactlyOnceWith(
      'front-door',
      60,
    );
    expect(addPayload).toMatchObject({
      ok: true,
      data: {
        write: { lockId: 'front-door', accepted: true, accessCodeId: 'code-2' },
      },
    });
    expect(updatePayload).toMatchObject({
      ok: true,
      data: {
        write: { lockId: 'front-door', accepted: true, accessCodeId: 'code-1' },
      },
    });
    expect(deletePayload).toMatchObject({
      ok: true,
      data: {
        write: { lockId: 'front-door', accepted: true, accessCodeId: 'code-1' },
      },
    });
    expect(beeperPayload).toMatchObject({
      ok: true,
      data: { write: { lockId: 'front-door', accepted: true } },
    });
    expect(lockAndLeavePayload).toMatchObject({
      ok: true,
      data: { write: { lockId: 'front-door', accepted: true } },
    });
    expect(autoLockPayload).toMatchObject({
      ok: true,
      data: { write: { lockId: 'front-door', accepted: true } },
    });
    expect(rendered).not.toContain('write-secret');
  });

  it('prints status success envelopes with stable data.status, ISO dates, and no stderr output', async () => {
    const client = createMockClient({
      getStatus: vi.fn(async (id) => ({
        id: id.trim(),
        state: 'locked',
        batteryLevel: 87,
        updatedAt: new Date('2025-01-02T03:04:05.000Z'),
      })),
    });

    const result = await runMain(
      [
        'status',
        ' front-door ',
        '--username',
        'operator@example.test',
        '--password',
        'password=status-secret',
      ],
      {
        client,
      },
    );
    const payload = parseJson<{
      ok: true;
      data: {
        status: {
          id: string;
          state: string;
          batteryLevel: number;
          updatedAt: string;
        };
      };
    }>(result.stdout);
    const rendered = JSON.stringify(payload);

    expect(result.exitCode).toBeUndefined();
    expect(result.stderr).toBe('');
    expect(client.getStatus).toHaveBeenCalledExactlyOnceWith(' front-door ');
    expect(client.authCheck).not.toHaveBeenCalled();
    expect(client.listLocks).not.toHaveBeenCalled();
    expect(client.lock).not.toHaveBeenCalled();
    expect(client.unlock).not.toHaveBeenCalled();
    expect(payload).toMatchObject({
      ok: true,
      data: {
        status: {
          id: 'front-door',
          state: 'locked',
          batteryLevel: 87,
          updatedAt: '2025-01-02T03:04:05.000Z',
        },
      },
    });
    expect(rendered).not.toContain('operator@example.test');
    expect(rendered).not.toContain('status-secret');
    expect(rendered).not.toContain('cli-command-access-token-value');
    expect(rendered).not.toContain('cli-command-refresh-token-value');
    expect(rendered).not.toContain('cli-command-account-secret');
  });

  it('routes blank status lock IDs through the client validation path and emits a redacted stderr envelope', async () => {
    const client = createMockClient({
      getStatus: vi.fn(async () => {
        throw new SchlageError({
          code: 'SCHLAGE_LOCK_ID_INVALID',
          message: 'Schlage lock ID is required.',
          retryable: false,
        });
      }),
    });

    const result = await runMain(
      [
        'status',
        '   ',
        '--username',
        'operator@example.test',
        '--password',
        'password=blank-secret',
      ],
      {
        client,
      },
    );
    const payload = parseJson<{
      ok: false;
      error: { code: string; retryable: boolean };
    }>(result.stderr);
    const rendered = JSON.stringify(payload);

    expect(result.exitCode).toBe(1);
    expect(result.stdout).toBe('');
    expect(client.getStatus).toHaveBeenCalledExactlyOnceWith('   ');
    expect(payload).toMatchObject({
      ok: false,
      error: { code: 'SCHLAGE_LOCK_ID_INVALID', retryable: false },
    });
    expect(rendered).not.toContain('operator@example.test');
    expect(rendered).not.toContain('blank-secret');
  });

  it('maps list-locks missing protocol transport to SCHLAGE_NOT_IMPLEMENTED without leaking config inputs', async () => {
    const client = createMockClient({
      listLocks: vi.fn(async () => {
        throw new SchlageNotImplementedError('SchlageClient.listLocks');
      }),
    });

    const result = await runMain(
      [
        'list-locks',
        '--username',
        'operator@example.test',
        '--password',
        'password=missing-transport',
      ],
      {
        client,
      },
    );
    const payload = parseJson<{
      ok: false;
      config: { username: string; sources: Record<string, string> };
      auth: { phase: string; username: string };
      error: { code: string; message: string };
    }>(result.stderr);
    const rendered = JSON.stringify(payload);

    expect(result.exitCode).toBe(1);
    expect(result.stdout).toBe('');
    expect(client.listLocks).toHaveBeenCalledTimes(1);
    expect(payload).toMatchObject({
      ok: false,
      config: {
        username: '[REDACTED_USERNAME]',
        sources: { username: 'explicit', password: 'explicit' },
      },
      auth: { phase: 'signed-out', username: '[REDACTED_USERNAME]' },
      error: { code: 'SCHLAGE_NOT_IMPLEMENTED' },
    });
    expect(rendered).not.toContain('operator@example.test');
    expect(rendered).not.toContain('missing-transport');
  });

  it('emits auth failures before protocol use as SCHLAGE_AUTH_FAILED and redacts thrown token-shaped messages', async () => {
    const protocolUse = vi.fn();
    const client = createMockClient({
      listLocks: vi.fn(async () => {
        throw new SchlageError({
          code: 'SCHLAGE_AUTH_FAILED',
          message:
            'Schlage authenticate operation failed access_token=auth-cli-token-00000000000000000000 operator@example.test.',
          retryable: true,
        });
      }),
      getStatus: protocolUse,
    });

    const result = await runMain(
      [
        'list-locks',
        '--username',
        'operator@example.test',
        '--password',
        'password=auth-secret',
      ],
      {
        client,
      },
    );
    const payload = parseJson<{
      ok: false;
      error: { code: string; message: string; retryable: boolean };
    }>(result.stderr);
    const rendered = JSON.stringify(payload);

    expect(result.exitCode).toBe(1);
    expect(result.stdout).toBe('');
    expect(client.listLocks).toHaveBeenCalledTimes(1);
    expect(protocolUse).not.toHaveBeenCalled();
    expect(payload).toMatchObject({
      ok: false,
      error: { code: 'SCHLAGE_AUTH_FAILED', retryable: true },
    });
    expect(rendered).not.toContain('auth-cli-token');
    expect(rendered).not.toContain('operator@example.test');
    expect(rendered).not.toContain('auth-secret');
  });

  it('emits malformed status protocol failures as SCHLAGE_PROTOCOL_MALFORMED with redacted snapshots', async () => {
    const client = createMockClient({
      getStatus: vi.fn(async () => {
        throw new SchlageError({
          code: 'SCHLAGE_PROTOCOL_MALFORMED',
          message:
            'Schlage protocol response was malformed token=malformed-status-token-00000000000000000000.',
          retryable: true,
        });
      }),
    });

    const result = await runMain(
      [
        'status',
        'front-door',
        '--username',
        'operator@example.test',
        '--password',
        'password=malformed-secret',
      ],
      {
        client,
      },
    );
    const payload = parseJson<{
      ok: false;
      error: { code: string; retryable: boolean };
    }>(result.stderr);
    const rendered = JSON.stringify(payload);

    expect(result.exitCode).toBe(1);
    expect(result.stdout).toBe('');
    expect(client.getStatus).toHaveBeenCalledExactlyOnceWith('front-door');
    expect(payload).toMatchObject({
      ok: false,
      error: { code: 'SCHLAGE_PROTOCOL_MALFORMED', retryable: true },
    });
    expect(rendered).not.toContain('malformed-status-token');
    expect(rendered).not.toContain('operator@example.test');
    expect(rendered).not.toContain('malformed-secret');
  });

  it('emits transport failures as SCHLAGE_PROTOCOL_TRANSPORT and redacts token-shaped messages', async () => {
    const client = createMockClient({
      getStatus: vi.fn(async () => {
        throw new SchlageError({
          code: 'SCHLAGE_PROTOCOL_TRANSPORT',
          message:
            'Schlage getStatus operation failed authorization=Bearer transport-token-00000000000000000000 operator@example.test.',
          retryable: true,
        });
      }),
    });

    const result = await runMain(
      [
        'status',
        'front-door',
        '--username',
        'operator@example.test',
        '--password',
        'password=transport-secret',
      ],
      {
        client,
      },
    );
    const payload = parseJson<{
      ok: false;
      error: { code: string; message: string; retryable: boolean };
    }>(result.stderr);
    const rendered = JSON.stringify(payload);

    expect(result.exitCode).toBe(1);
    expect(result.stdout).toBe('');
    expect(payload).toMatchObject({
      ok: false,
      error: { code: 'SCHLAGE_PROTOCOL_TRANSPORT', retryable: true },
    });
    expect(rendered).not.toContain('transport-token');
    expect(rendered).not.toContain('operator@example.test');
    expect(rendered).not.toContain('transport-secret');
  });

  it('redacts token-shaped unexpected status throws as unknown public errors', async () => {
    const client = createMockClient({
      getStatus: vi.fn(async () => {
        throw new Error(
          'session=raw-status-session-token-00000000000000000000 operator@example.test',
        );
      }),
    });

    const result = await runMain(
      [
        'status',
        'front-door',
        '--username',
        'operator@example.test',
        '--password',
        'password=unexpected-secret',
      ],
      {
        client,
      },
    );
    const payload = parseJson<{
      ok: false;
      error: { code: string; message: string; retryable: boolean };
    }>(result.stderr);
    const rendered = JSON.stringify(payload);

    expect(result.exitCode).toBe(1);
    expect(result.stdout).toBe('');
    expect(payload).toMatchObject({
      ok: false,
      error: {
        code: 'SCHLAGE_UNKNOWN_ERROR',
        message:
          'Schlage operation failed. See the error code for a safe diagnostic category.',
        retryable: false,
      },
    });
    expect(rendered).not.toContain('raw-status-session-token');
    expect(rendered).not.toContain('operator@example.test');
    expect(rendered).not.toContain('unexpected-secret');
  });

  it('prints accepted lock and unlock results as stable data.result envelopes with no stderr output', async () => {
    const client = createMockClient({
      lock: vi.fn(async (id) => ({
        id: id.trim(),
        accepted: true,
        observedState: 'locked',
      })),
      unlock: vi.fn(async (id) => ({
        id: id.trim(),
        accepted: true,
        observedState: 'unlocked',
      })),
    });

    const lockResult = await runMain(
      [
        'lock',
        ' front-door ',
        '--username',
        'operator@example.test',
        '--password',
        'password=command-secret',
      ],
      {
        client,
      },
    );
    const unlockResult = await runMain(
      [
        'unlock',
        'front-door',
        '--username',
        'operator@example.test',
        '--password',
        'password=command-secret',
      ],
      {
        client,
      },
    );
    const lockPayload = parseJson<{
      ok: true;
      data: {
        result: { id: string; accepted: boolean; observedState: string };
      };
    }>(lockResult.stdout);
    const unlockPayload = parseJson<{
      ok: true;
      data: {
        result: { id: string; accepted: boolean; observedState: string };
      };
    }>(unlockResult.stdout);
    const rendered = JSON.stringify([lockPayload, unlockPayload]);

    expect(lockResult.exitCode).toBeUndefined();
    expect(unlockResult.exitCode).toBeUndefined();
    expect(lockResult.stderr).toBe('');
    expect(unlockResult.stderr).toBe('');
    expect(client.lock).toHaveBeenCalledExactlyOnceWith(' front-door ');
    expect(client.unlock).toHaveBeenCalledExactlyOnceWith('front-door');
    expect(client.authCheck).not.toHaveBeenCalled();
    expect(client.listLocks).not.toHaveBeenCalled();
    expect(client.getStatus).not.toHaveBeenCalled();
    expect(lockPayload).toMatchObject({
      ok: true,
      data: {
        result: { id: 'front-door', accepted: true, observedState: 'locked' },
      },
    });
    expect(unlockPayload).toMatchObject({
      ok: true,
      data: {
        result: { id: 'front-door', accepted: true, observedState: 'unlocked' },
      },
    });
    expect(rendered).not.toContain('operator@example.test');
    expect(rendered).not.toContain('command-secret');
    expect(rendered).not.toContain('cli-command-access-token-value');
    expect(rendered).not.toContain('cli-command-refresh-token-value');
    expect(rendered).not.toContain('cli-command-account-secret');
  });

  it('treats rejected command results as successful lock and unlock envelopes without raw reason fields', async () => {
    const protocol = commandProtocolTransport({
      lock: vi.fn(async () => ({
        accepted: false,
        observedState: 'LOCKED',
        reason: 'policy-rejected-secret-token-00000000000000000000',
      })),
      unlock: vi.fn(async () => ({
        accepted: false,
        observedState: 'jammed-protocol-value',
        failureCode: 'transport-specific-failure-code',
      })),
    });
    const client = createRealCommandClient(protocol);

    const lockResult = await runMain(
      [
        'lock',
        'front-door',
        '--username',
        'operator@example.test',
        '--password',
        'password=rejected-secret',
      ],
      {
        client,
      },
    );
    const unlockResult = await runMain(
      [
        'unlock',
        'front-door',
        '--username',
        'operator@example.test',
        '--password',
        'password=rejected-secret',
      ],
      {
        client,
      },
    );
    const lockPayload = parseJson<{
      ok: true;
      data: { result: { accepted: boolean; observedState: string } };
    }>(lockResult.stdout);
    const unlockPayload = parseJson<{
      ok: true;
      data: { result: { accepted: boolean; observedState: string } };
    }>(unlockResult.stdout);
    const rendered = JSON.stringify([lockPayload, unlockPayload]);

    expect(lockResult.exitCode).toBeUndefined();
    expect(unlockResult.exitCode).toBeUndefined();
    expect(lockResult.stderr).toBe('');
    expect(unlockResult.stderr).toBe('');
    expect(protocol.lock).toHaveBeenCalledTimes(1);
    expect(protocol.unlock).toHaveBeenCalledTimes(1);
    expect(lockPayload).toMatchObject({
      ok: true,
      data: { result: { accepted: false, observedState: 'locked' } },
    });
    expect(unlockPayload).toMatchObject({
      ok: true,
      data: { result: { accepted: false, observedState: 'unknown' } },
    });
    expect(rendered).not.toContain('reason');
    expect(rendered).not.toContain('failureCode');
    expect(rendered).not.toContain('policy-rejected-secret-token');
    expect(rendered).not.toContain('transport-specific-failure-code');
  });

  it('prints unknown observed command state as a successful public result', async () => {
    const client = createMockClient({
      unlock: vi.fn(async (id) => ({
        id,
        accepted: true,
        observedState: 'unknown',
      })),
    });

    const result = await runMain(
      [
        'unlock',
        'front-door',
        '--username',
        'operator@example.test',
        '--password',
        'password=unknown-state-secret',
      ],
      {
        client,
      },
    );
    const payload = parseJson<{
      ok: true;
      data: { result: { accepted: boolean; observedState: string } };
    }>(result.stdout);

    expect(result.exitCode).toBeUndefined();
    expect(result.stderr).toBe('');
    expect(client.unlock).toHaveBeenCalledExactlyOnceWith('front-door');
    expect(payload).toMatchObject({
      ok: true,
      data: { result: { accepted: true, observedState: 'unknown' } },
    });
    expect(JSON.stringify(payload)).not.toContain('unknown-state-secret');
  });

  it('emits blank lock and unlock lock IDs as non-retryable failures before auth or protocol command calls', async () => {
    const auth = commandAuthTransport();
    const protocol = commandProtocolTransport();
    const client = createRealCommandClient(protocol, auth);

    const lockResult = await runMain(
      [
        'lock',
        '   ',
        '--username',
        'operator@example.test',
        '--password',
        'password=blank-command-secret',
      ],
      {
        client,
      },
    );
    const unlockResult = await runMain(
      [
        'unlock',
        '   ',
        '--username',
        'operator@example.test',
        '--password',
        'password=blank-command-secret',
      ],
      {
        client,
      },
    );
    const lockPayload = parseJson<{
      ok: false;
      error: { code: string; retryable: boolean };
    }>(lockResult.stderr);
    const unlockPayload = parseJson<{
      ok: false;
      error: { code: string; retryable: boolean };
    }>(unlockResult.stderr);
    const rendered = JSON.stringify([lockPayload, unlockPayload]);

    expect(lockResult.exitCode).toBe(1);
    expect(unlockResult.exitCode).toBe(1);
    expect(lockResult.stdout).toBe('');
    expect(unlockResult.stdout).toBe('');
    expect(auth.signIn).not.toHaveBeenCalled();
    expect(auth.refresh).not.toHaveBeenCalled();
    expect(protocol.lock).not.toHaveBeenCalled();
    expect(protocol.unlock).not.toHaveBeenCalled();
    expect(lockPayload).toMatchObject({
      ok: false,
      error: { code: 'SCHLAGE_LOCK_ID_INVALID', retryable: false },
    });
    expect(unlockPayload).toMatchObject({
      ok: false,
      error: { code: 'SCHLAGE_LOCK_ID_INVALID', retryable: false },
    });
    expect(rendered).not.toContain('operator@example.test');
    expect(rendered).not.toContain('blank-command-secret');
  });

  it('maps missing lock and unlock command transports to SCHLAGE_NOT_IMPLEMENTED envelopes', async () => {
    const client = createMockClient({
      lock: vi.fn(async () => {
        throw new SchlageNotImplementedError('SchlageClient.lock');
      }),
      unlock: vi.fn(async () => {
        throw new SchlageNotImplementedError('SchlageClient.unlock');
      }),
    });

    const lockResult = await runMain(
      [
        'lock',
        'front-door',
        '--username',
        'operator@example.test',
        '--password',
        'password=missing-command-transport',
      ],
      {
        client,
      },
    );
    const unlockResult = await runMain(
      [
        'unlock',
        'front-door',
        '--username',
        'operator@example.test',
        '--password',
        'password=missing-command-transport',
      ],
      {
        client,
      },
    );
    const lockPayload = parseJson<{
      ok: false;
      error: { code: string; message: string };
    }>(lockResult.stderr);
    const unlockPayload = parseJson<{
      ok: false;
      error: { code: string; message: string };
    }>(unlockResult.stderr);
    const rendered = JSON.stringify([lockPayload, unlockPayload]);

    expect(lockResult.exitCode).toBe(1);
    expect(unlockResult.exitCode).toBe(1);
    expect(lockResult.stdout).toBe('');
    expect(unlockResult.stdout).toBe('');
    expect(lockPayload.error.code).toBe('SCHLAGE_NOT_IMPLEMENTED');
    expect(unlockPayload.error.code).toBe('SCHLAGE_NOT_IMPLEMENTED');
    expect(rendered).not.toContain('operator@example.test');
    expect(rendered).not.toContain('missing-command-transport');
  });

  it('emits command auth failures before opposite command use and redacts token-shaped messages', async () => {
    const client = createMockClient({
      lock: vi.fn(async () => {
        throw new SchlageError({
          code: 'SCHLAGE_AUTH_FAILED',
          message:
            'Schlage authenticate operation failed access_token=command-auth-token-00000000000000000000 operator@example.test.',
          retryable: true,
        });
      }),
    });

    const result = await runMain(
      [
        'lock',
        'front-door',
        '--username',
        'operator@example.test',
        '--password',
        'password=command-auth-secret',
      ],
      {
        client,
      },
    );
    const payload = parseJson<{
      ok: false;
      error: { code: string; retryable: boolean };
    }>(result.stderr);
    const rendered = JSON.stringify(payload);

    expect(result.exitCode).toBe(1);
    expect(result.stdout).toBe('');
    expect(client.lock).toHaveBeenCalledExactlyOnceWith('front-door');
    expect(client.unlock).not.toHaveBeenCalled();
    expect(payload).toMatchObject({
      ok: false,
      error: { code: 'SCHLAGE_AUTH_FAILED', retryable: true },
    });
    expect(rendered).not.toContain('command-auth-token');
    expect(rendered).not.toContain('operator@example.test');
    expect(rendered).not.toContain('command-auth-secret');
  });

  it('emits malformed command protocol failures as SCHLAGE_PROTOCOL_MALFORMED with redacted snapshots', async () => {
    const client = createMockClient({
      unlock: vi.fn(async () => {
        throw new SchlageError({
          code: 'SCHLAGE_PROTOCOL_MALFORMED',
          message:
            'Schlage protocol response was malformed token=malformed-command-token-00000000000000000000.',
          retryable: true,
        });
      }),
    });

    const result = await runMain(
      [
        'unlock',
        'front-door',
        '--username',
        'operator@example.test',
        '--password',
        'password=malformed-command-secret',
      ],
      {
        client,
      },
    );
    const payload = parseJson<{
      ok: false;
      error: { code: string; retryable: boolean };
    }>(result.stderr);
    const rendered = JSON.stringify(payload);

    expect(result.exitCode).toBe(1);
    expect(result.stdout).toBe('');
    expect(client.unlock).toHaveBeenCalledExactlyOnceWith('front-door');
    expect(payload).toMatchObject({
      ok: false,
      error: { code: 'SCHLAGE_PROTOCOL_MALFORMED', retryable: true },
    });
    expect(rendered).not.toContain('malformed-command-token');
    expect(rendered).not.toContain('operator@example.test');
    expect(rendered).not.toContain('malformed-command-secret');
  });

  it('maps rate-limit-like command transport failures to retryable SCHLAGE_RATE_LIMITED envelopes', async () => {
    const protocol = commandProtocolTransport({
      lock: vi.fn(async () => {
        throw {
          statusCode: 429,
          message:
            'rate limited for access_token=rate-limit-command-token-00000000000000000000 operator@example.test',
        };
      }),
    });
    const client = createRealCommandClient(protocol);

    const result = await runMain(
      [
        'lock',
        'front-door',
        '--username',
        'operator@example.test',
        '--password',
        'password=rate-limit-secret',
      ],
      {
        client,
      },
    );
    const payload = parseJson<{
      ok: false;
      command: string;
      error: { code: string; message: string; retryable: boolean };
    }>(result.stderr);
    const rendered = JSON.stringify(payload);

    expect(result.exitCode).toBe(1);
    expect(result.stdout).toBe('');
    expect(protocol.lock).toHaveBeenCalledTimes(1);
    expect(payload).toMatchObject({
      ok: false,
      command: 'lock',
      error: {
        code: 'SCHLAGE_RATE_LIMITED',
        message: 'Schlage lock operation failed.',
        retryable: true,
      },
    });
    expect(rendered).not.toContain('rate-limit-command-token');
    expect(rendered).not.toContain('operator@example.test');
    expect(rendered).not.toContain('rate-limit-secret');
  });

  it('emits malformed command responses as retryable SCHLAGE_PROTOCOL_MALFORMED envelopes', async () => {
    const protocol = commandProtocolTransport({
      lock: vi.fn(async () => ({ observedState: 'LOCKED' })),
    });
    const client = createRealCommandClient(protocol);

    const result = await runMain(
      [
        'lock',
        'front-door',
        '--username',
        'operator@example.test',
        '--password',
        'password=malformed-response-secret',
      ],
      {
        client,
      },
    );
    const payload = parseJson<{
      ok: false;
      command: string;
      error: { code: string; retryable: boolean };
    }>(result.stderr);
    const rendered = JSON.stringify(payload);

    expect(result.exitCode).toBe(1);
    expect(result.stdout).toBe('');
    expect(protocol.lock).toHaveBeenCalledTimes(1);
    expect(payload).toMatchObject({
      ok: false,
      command: 'lock',
      error: { code: 'SCHLAGE_PROTOCOL_MALFORMED', retryable: true },
    });
    expect(rendered).not.toContain('operator@example.test');
    expect(rendered).not.toContain('malformed-response-secret');
    expect(rendered).not.toContain('observedState');
  });

  it('redacts token-shaped thrown command transport errors as typed protocol transport failures', async () => {
    const client = createMockClient({
      lock: vi.fn(async () => {
        throw new SchlageError({
          code: 'SCHLAGE_PROTOCOL_TRANSPORT',
          message:
            'Schlage lock operation failed authorization=Bearer command-transport-token-00000000000000000000 operator@example.test.',
          retryable: true,
        });
      }),
    });

    const result = await runMain(
      [
        'lock',
        'front-door',
        '--username',
        'operator@example.test',
        '--password',
        'password=command-transport-secret',
      ],
      {
        client,
      },
    );
    const payload = parseJson<{
      ok: false;
      error: { code: string; message: string; retryable: boolean };
    }>(result.stderr);
    const rendered = JSON.stringify(payload);

    expect(result.exitCode).toBe(1);
    expect(result.stdout).toBe('');
    expect(payload).toMatchObject({
      ok: false,
      error: { code: 'SCHLAGE_PROTOCOL_TRANSPORT', retryable: true },
    });
    expect(rendered).not.toContain('command-transport-token');
    expect(rendered).not.toContain('operator@example.test');
    expect(rendered).not.toContain('command-transport-secret');
  });
});
