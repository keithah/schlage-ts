#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Command, type CommandUnknownOpts } from '@commander-js/extra-typings';
import {
  SchlageClient,
  SchlageError,
  createPublicSchlageConfigSnapshot,
  resolveSchlageConfig,
  toPublicSchlageError,
  type PublicSchlageAuthSnapshot,
  type PublicSchlageConfigSnapshot,
  type PublicSchlageErrorSnapshot,
  type SchlageAccessCode,
  type SchlageAccessCodeInput,
  type SchlageClientOptions,
  type SchlageCommandResult,
  type SchlageConfigEnvironment,
  type SchlageListLogsOptions,
  type SchlageLockDiagnostics,
  type SchlageLockLog,
  type SchlageLockStatus,
  type SchlageLockSummary,
  type SchlageUser,
  type SchlageWriteResult,
} from './index.js';

interface PackageMetadata {
  readonly name: string;
  readonly version: string;
  readonly description?: string;
}

interface CliConfigFlags {
  readonly config?: string;
  readonly username?: string;
  readonly password?: string;
  readonly cacheDir?: string;
}

interface AccessCodeCliOptions {
  readonly name: string;
  readonly code: string;
  readonly disabled?: true;
  readonly notify?: true;
  readonly temporaryStartsAt?: string;
  readonly temporaryEndsAt?: string;
}

export interface CliClient {
  readonly authCheck: () => Promise<PublicSchlageAuthSnapshot>;
  readonly getAuthSnapshot: () => PublicSchlageAuthSnapshot;
  readonly listLocks: () => Promise<readonly SchlageLockSummary[]>;
  readonly getStatus: (lockId: string) => Promise<SchlageLockStatus>;
  readonly lock: (lockId: string) => Promise<SchlageCommandResult>;
  readonly unlock: (lockId: string) => Promise<SchlageCommandResult>;
  readonly listUsers: () => Promise<readonly SchlageUser[]>;
  readonly listAccessCodes: (
    lockId: string,
  ) => Promise<readonly SchlageAccessCode[]>;
  readonly listLogs: (
    lockId: string,
    options?: SchlageListLogsOptions,
  ) => Promise<readonly SchlageLockLog[]>;
  readonly getDiagnostics: (lockId: string) => Promise<SchlageLockDiagnostics>;
  readonly keypadDisabled: (lockId: string) => Promise<boolean>;
  readonly lastChangedBy: (lockId: string) => Promise<string | null>;
  readonly addAccessCode: (
    lockId: string,
    input: SchlageAccessCodeInput,
  ) => Promise<SchlageWriteResult>;
  readonly updateAccessCode: (
    lockId: string,
    accessCodeId: string,
    input: SchlageAccessCodeInput,
  ) => Promise<SchlageWriteResult>;
  readonly deleteAccessCode: (
    lockId: string,
    accessCodeId: string,
  ) => Promise<SchlageWriteResult>;
  readonly setBeeper: (
    lockId: string,
    enabled: boolean,
  ) => Promise<SchlageWriteResult>;
  readonly setLockAndLeave: (
    lockId: string,
    enabled: boolean,
  ) => Promise<SchlageWriteResult>;
  readonly setAutoLockTime: (
    lockId: string,
    seconds: number,
  ) => Promise<SchlageWriteResult>;
}

export interface CliRuntime {
  readonly env: SchlageConfigEnvironment;
  readonly stdout: Pick<typeof process.stdout, 'write'>;
  readonly stderr: Pick<typeof process.stderr, 'write'>;
  readonly createClient: (options: SchlageClientOptions) => CliClient;
}

export interface CliSuccessPayload {
  readonly ok: true;
  readonly command: string;
  readonly config: PublicSchlageConfigSnapshot;
  readonly auth: PublicSchlageAuthSnapshot;
  readonly data?: {
    readonly locks?: readonly SchlageLockSummary[];
    readonly status?: SchlageLockStatus;
    readonly result?: SchlageCommandResult;
    readonly users?: readonly SchlageUser[];
    readonly accessCodes?: readonly SchlageAccessCode[];
    readonly logs?: readonly SchlageLockLog[];
    readonly diagnostics?: SchlageLockDiagnostics;
    readonly keypadDisabled?: boolean;
    readonly lastChangedBy?: string | null;
    readonly write?: SchlageWriteResult;
  };
}

export interface CliFailurePayload {
  readonly ok: false;
  readonly command?: string;
  readonly config?: PublicSchlageConfigSnapshot;
  readonly auth?: PublicSchlageAuthSnapshot;
  readonly error: PublicSchlageErrorSnapshot;
}

interface CliCommandContext {
  readonly config: PublicSchlageConfigSnapshot;
  readonly client: CliClient;
}

type CliCommandData = {
  readonly auth?: PublicSchlageAuthSnapshot;
  readonly data?: CliSuccessPayload['data'];
};

const DEFAULT_RUNTIME: CliRuntime = {
  env: process.env,
  stdout: process.stdout,
  stderr: process.stderr,
  createClient: (options) => new SchlageClient(options),
};

class CliPublicError extends Error {
  readonly payload: CliFailurePayload;

  constructor(payload: CliFailurePayload) {
    super(payload.error.message);
    this.name = 'CliPublicError';
    this.payload = payload;
  }
}

export function readPackageMetadata(): PackageMetadata {
  const packageJsonPath = join(
    dirname(fileURLToPath(import.meta.url)),
    '..',
    'package.json',
  );
  return JSON.parse(readFileSync(packageJsonPath, 'utf8')) as PackageMetadata;
}

export function createCli(
  metadata: PackageMetadata = readPackageMetadata(),
  runtime: Partial<CliRuntime> = {},
): Command {
  const effectiveRuntime: CliRuntime = { ...DEFAULT_RUNTIME, ...runtime };
  const program = new Command();

  program
    .name('schlage-ts')
    .description(
      metadata.description ??
        'Native TypeScript Schlage client and smoke-test CLI',
    )
    .version(metadata.version)
    .showHelpAfterError()
    .showSuggestionAfterError()
    .configureOutput({
      writeOut: (value) => effectiveRuntime.stdout.write(value),
      writeErr: (value) => effectiveRuntime.stderr.write(value),
    });

  addConfigOptions(
    program
      .command('auth-check')
      .description(
        'Resolve Schlage config and validate/reuse a local auth session.',
      ),
  ).action(async (options) => {
    await runCliCommand(
      'auth-check',
      options,
      effectiveRuntime,
      async ({ client }) => ({ auth: await client.authCheck() }),
    );
  });

  addConfigOptions(
    program
      .command('list-locks')
      .description('List locks visible to the authenticated Schlage account.'),
  ).action(async (options) => {
    await runCliCommand(
      'list-locks',
      options,
      effectiveRuntime,
      async ({ client }) => ({ data: { locks: await client.listLocks() } }),
    );
  });

  addConfigOptions(
    program
      .command('status')
      .description('Read current status for a Schlage lock.')
      .argument('<lock-id>', 'Schlage lock identifier'),
  ).action(async (lockId, options) => {
    await runCliCommand(
      'status',
      options,
      effectiveRuntime,
      async ({ client }) => ({
        data: { status: await client.getStatus(lockId) },
      }),
    );
  });

  addConfigOptions(
    program
      .command('lock')
      .description('Lock a Schlage lock.')
      .argument('<lock-id>', 'Schlage lock identifier'),
  ).action(async (lockId, options) => {
    await runCliCommand(
      'lock',
      options,
      effectiveRuntime,
      async ({ client }) => ({ data: { result: await client.lock(lockId) } }),
    );
  });

  addConfigOptions(
    program
      .command('unlock')
      .description('Unlock a Schlage lock.')
      .argument('<lock-id>', 'Schlage lock identifier'),
  ).action(async (lockId, options) => {
    await runCliCommand(
      'unlock',
      options,
      effectiveRuntime,
      async ({ client }) => ({ data: { result: await client.unlock(lockId) } }),
    );
  });

  addConfigOptions(
    program
      .command('users')
      .description(
        'List users associated with the authenticated Schlage account.',
      ),
  ).action(async (options) => {
    await runCliCommand(
      'users',
      options,
      effectiveRuntime,
      async ({ client }) => ({ data: { users: await client.listUsers() } }),
    );
  });

  addConfigOptions(
    program
      .command('access-codes')
      .description('List access codes for a Schlage lock.')
      .argument('<lock-id>', 'Schlage lock identifier'),
  ).action(async (lockId, options) => {
    await runCliCommand(
      'access-codes',
      options,
      effectiveRuntime,
      async ({ client }) => ({
        data: { accessCodes: await client.listAccessCodes(lockId) },
      }),
    );
  });

  addConfigOptions(
    program
      .command('logs')
      .description('List activity logs for a Schlage lock.')
      .argument('<lock-id>', 'Schlage lock identifier')
      .option('--limit <n>', 'Maximum number of log entries to request')
      .option('--desc', 'Request newest logs first'),
  ).action(async (lockId, options) => {
    const logOptions = options as CliConfigFlags & {
      readonly limit?: string;
      readonly desc?: true;
    };
    await runCliCommand(
      'logs',
      logOptions,
      effectiveRuntime,
      async ({ client }) => ({
        data: {
          logs: await client.listLogs(lockId, {
            ...(logOptions.limit === undefined
              ? {}
              : {
                  limit: parsePositiveIntegerOption(
                    logOptions.limit,
                    '--limit',
                  ),
                }),
            ...(logOptions.desc === true ? { sortDesc: true } : {}),
          }),
        },
      }),
    );
  });

  addConfigOptions(
    program
      .command('diagnostics')
      .description('Read redacted diagnostics for a Schlage lock.')
      .argument('<lock-id>', 'Schlage lock identifier'),
  ).action(async (lockId, options) => {
    await runCliCommand(
      'diagnostics',
      options,
      effectiveRuntime,
      async ({ client }) => ({
        data: { diagnostics: await client.getDiagnostics(lockId) },
      }),
    );
  });

  addConfigOptions(
    program
      .command('keypad-disabled')
      .description('Check whether the newest lock log indicates disabled keypad.')
      .argument('<lock-id>', 'Schlage lock identifier'),
  ).action(async (lockId, options) => {
    await runCliCommand(
      'keypad-disabled',
      options,
      effectiveRuntime,
      async ({ client }) => ({
        data: { keypadDisabled: await client.keypadDisabled(lockId) },
      }),
    );
  });

  addConfigOptions(
    program
      .command('last-changed-by')
      .description('Read the last actor that changed the lock state.')
      .argument('<lock-id>', 'Schlage lock identifier'),
  ).action(async (lockId, options) => {
    await runCliCommand(
      'last-changed-by',
      options,
      effectiveRuntime,
      async ({ client }) => ({
        data: { lastChangedBy: await client.lastChangedBy(lockId) },
      }),
    );
  });

  addConfigOptions(
    program
      .command('add-access-code')
      .description('Add an access code to a Schlage lock.')
      .argument('<lock-id>', 'Schlage lock identifier')
      .requiredOption('--name <name>', 'Access code name')
      .requiredOption('--code <code>', 'Numeric access code')
      .option('--disabled', 'Create the access code disabled')
      .option('--notify', 'Enable Schlage notification for access-code use')
      .option(
        '--temporary-starts-at <iso>',
        'Temporary access-code start time as an ISO timestamp',
      )
      .option(
        '--temporary-ends-at <iso>',
        'Temporary access-code end time as an ISO timestamp',
      ),
  ).action(async (lockId, options) => {
    const writeOptions = options as CliConfigFlags & AccessCodeCliOptions;
    await runCliCommand(
      'add-access-code',
      writeOptions,
      effectiveRuntime,
      async ({ client }) => ({
        data: {
          write: await client.addAccessCode(
            lockId,
            accessCodeInputFromOptions(writeOptions),
          ),
        },
      }),
    );
  });

  addConfigOptions(
    program
      .command('update-access-code')
      .description('Update an access code on a Schlage lock.')
      .argument('<lock-id>', 'Schlage lock identifier')
      .argument('<access-code-id>', 'Schlage access-code identifier')
      .requiredOption('--name <name>', 'Access code name')
      .requiredOption('--code <code>', 'Numeric access code')
      .option('--disabled', 'Disable the access code')
      .option('--notify', 'Enable Schlage notification for access-code use')
      .option(
        '--temporary-starts-at <iso>',
        'Temporary access-code start time as an ISO timestamp',
      )
      .option(
        '--temporary-ends-at <iso>',
        'Temporary access-code end time as an ISO timestamp',
      ),
  ).action(async (lockId, accessCodeId, options) => {
    const writeOptions = options as CliConfigFlags & AccessCodeCliOptions;
    await runCliCommand(
      'update-access-code',
      writeOptions,
      effectiveRuntime,
      async ({ client }) => ({
        data: {
          write: await client.updateAccessCode(
            lockId,
            accessCodeId,
            accessCodeInputFromOptions(writeOptions),
          ),
        },
      }),
    );
  });

  addConfigOptions(
    program
      .command('delete-access-code')
      .description('Delete an access code from a Schlage lock.')
      .argument('<lock-id>', 'Schlage lock identifier')
      .argument('<access-code-id>', 'Schlage access-code identifier'),
  ).action(async (lockId, accessCodeId, options) => {
    await runCliCommand(
      'delete-access-code',
      options,
      effectiveRuntime,
      async ({ client }) => ({
        data: { write: await client.deleteAccessCode(lockId, accessCodeId) },
      }),
    );
  });

  addConfigOptions(
    program
      .command('set-beeper')
      .description('Enable or disable the lock beeper.')
      .argument('<lock-id>', 'Schlage lock identifier')
      .argument('<on-off>', 'on or off'),
  ).action(async (lockId, onOff, options) => {
    await runCliCommand(
      'set-beeper',
      options,
      effectiveRuntime,
      async ({ client }) => ({
        data: { write: await client.setBeeper(lockId, parseOnOff(onOff)) },
      }),
    );
  });

  addConfigOptions(
    program
      .command('set-lock-and-leave')
      .description('Enable or disable lock-and-leave.')
      .argument('<lock-id>', 'Schlage lock identifier')
      .argument('<on-off>', 'on or off'),
  ).action(async (lockId, onOff, options) => {
    await runCliCommand(
      'set-lock-and-leave',
      options,
      effectiveRuntime,
      async ({ client }) => ({
        data: {
          write: await client.setLockAndLeave(lockId, parseOnOff(onOff)),
        },
      }),
    );
  });

  addConfigOptions(
    program
      .command('set-auto-lock-time')
      .description('Set auto-lock time in seconds; use 0 to disable.')
      .argument('<lock-id>', 'Schlage lock identifier')
      .argument('<seconds>', 'Supported auto-lock time in seconds'),
  ).action(async (lockId, seconds, options) => {
    await runCliCommand(
      'set-auto-lock-time',
      options,
      effectiveRuntime,
      async ({ client }) => ({
        data: {
          write: await client.setAutoLockTime(
            lockId,
            parsePositiveIntegerOrZeroOption(seconds, '<seconds>'),
          ),
        },
      }),
    );
  });

  return program;
}

export async function main(
  argv: readonly string[] = process.argv,
  runtime: Partial<CliRuntime> = {},
): Promise<void> {
  const effectiveRuntime: CliRuntime = { ...DEFAULT_RUNTIME, ...runtime };

  try {
    await createCli(readPackageMetadata(), effectiveRuntime).parseAsync(argv);
  } catch (error) {
    writeJson(effectiveRuntime.stderr, toCliFailurePayload(error));
    process.exitCode = 1;
  }
}

export async function runCliCommand(
  command: string,
  options: CliConfigFlags,
  runtime: CliRuntime,
  execute: (context: CliCommandContext) => Promise<CliCommandData>,
): Promise<void> {
  let configSnapshot: PublicSchlageConfigSnapshot | undefined;
  let client: CliClient | undefined;

  try {
    const config = resolveSchlageConfig({
      configPath: options.config,
      username: options.username,
      password: options.password,
      cacheDir: options.cacheDir,
      env: runtime.env,
    });
    configSnapshot = createPublicSchlageConfigSnapshot(config);
    client = runtime.createClient({
      username: config.credentials.username,
      password: config.credentials.password,
      cacheDir: config.cacheDir,
      ...(runtime.env.SCHLAGE_TS_DISABLE_LIVE_TRANSPORT === '1'
        ? { liveTransport: false }
        : {}),
    });

    const data = await execute({ config: configSnapshot, client });
    const auth = data.auth ?? client.getAuthSnapshot();
    writeJson(runtime.stdout, {
      ok: true,
      command,
      config: configSnapshot,
      auth,
      ...data,
    });
  } catch (error) {
    throw new CliPublicError({
      ok: false,
      command,
      ...(configSnapshot === undefined ? {} : { config: configSnapshot }),
      ...(client === undefined ? {} : { auth: client.getAuthSnapshot() }),
      error: toPublicSchlageError(error),
    });
  }
}

function addConfigOptions<T extends CommandUnknownOpts>(command: T): T {
  return command
    .option('-c, --config <path>', 'Path to YAML config file')
    .option(
      '--username <username>',
      'Schlage username; prefer SCHLAGE_USERNAME or YAML env indirection for local use',
    )
    .option(
      '--password <password>',
      'Schlage password; prefer SCHLAGE_PASSWORD or YAML env indirection for local use',
    )
    .option(
      '--cache-dir <path>',
      'Directory for the local Schlage token/session cache',
    ) as T;
}

function toCliFailurePayload(error: unknown): CliFailurePayload {
  if (error instanceof CliPublicError) {
    return error.payload;
  }

  return {
    ok: false,
    error: toPublicSchlageError(error),
  };
}

function writeJson(
  stream: Pick<typeof process.stdout, 'write'>,
  payload: CliSuccessPayload | CliFailurePayload,
): void {
  stream.write(`${JSON.stringify(payload, null, 2)}\n`);
}

function parsePositiveIntegerOption(value: string, optionName: string): number {
  const parsed = Number.parseInt(value, 10);
  if (
    !Number.isInteger(parsed) ||
    parsed <= 0 ||
    String(parsed) !== value.trim()
  ) {
    throw new SchlageError({
      code: 'SCHLAGE_CONFIG_MALFORMED',
      message: `${optionName} must be a positive integer.`,
      retryable: false,
    });
  }
  return parsed;
}

function parsePositiveIntegerOrZeroOption(
  value: string,
  optionName: string,
): number {
  if (value.trim() === '0') {
    return 0;
  }
  return parsePositiveIntegerOption(value, optionName);
}

function parseOnOff(value: string): boolean {
  const normalized = value.trim().toLowerCase();
  if (normalized === 'on') {
    return true;
  }
  if (normalized === 'off') {
    return false;
  }
  throw new SchlageError({
    code: 'SCHLAGE_CONFIG_MALFORMED',
    message: 'Expected on or off.',
    retryable: false,
  });
}

function accessCodeInputFromOptions(
  options: AccessCodeCliOptions,
): SchlageAccessCodeInput {
  const schedule = temporaryScheduleFromOptions(options);
  return {
    name: options.name,
    code: options.code,
    ...(options.disabled === true ? { disabled: true } : {}),
    ...(options.notify === true ? { notifyOnUse: true } : {}),
    ...(schedule === undefined ? {} : { schedule }),
  };
}

function temporaryScheduleFromOptions(
  options: AccessCodeCliOptions,
): SchlageAccessCodeInput['schedule'] {
  if (
    options.temporaryStartsAt === undefined &&
    options.temporaryEndsAt === undefined
  ) {
    return undefined;
  }

  if (
    options.temporaryStartsAt === undefined ||
    options.temporaryEndsAt === undefined
  ) {
    throw new SchlageError({
      code: 'SCHLAGE_CONFIG_MALFORMED',
      message:
        '--temporary-starts-at and --temporary-ends-at must be provided together.',
      retryable: false,
    });
  }

  const startsAt = parseIsoDateOption(
    options.temporaryStartsAt,
    '--temporary-starts-at',
  );
  const endsAt = parseIsoDateOption(
    options.temporaryEndsAt,
    '--temporary-ends-at',
  );
  if (endsAt.getTime() <= startsAt.getTime()) {
    throw new SchlageError({
      code: 'SCHLAGE_CONFIG_MALFORMED',
      message: '--temporary-ends-at must be after --temporary-starts-at.',
      retryable: false,
    });
  }

  return { type: 'temporary', startsAt, endsAt };
}

function parseIsoDateOption(value: string, optionName: string): Date {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    throw new SchlageError({
      code: 'SCHLAGE_CONFIG_MALFORMED',
      message: `${optionName} must be a valid ISO timestamp.`,
      retryable: false,
    });
  }

  return date;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  void main();
}
