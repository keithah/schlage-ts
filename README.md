# schlage-ts

Native TypeScript client and JSON-first CLI for Schlage Encode WiFi locks.

`schlage-ts` is an unofficial Schlage/Allegion cloud client inspired by the API shape and protocol research in [`pyschlage`](https://github.com/dknowles2/pyschlage). It is built for automation, local tooling, and typed Node.js applications that need to inspect or control compatible Schlage WiFi locks.

This project is not affiliated with Schlage or Allegion. Use it at your own risk, especially for commands that change a physical lock state.

## Features

- Sign in with a Schlage account using the live cloud transport.
- Reuse local token/session cache between commands.
- List locks visible to the account.
- Read lock status, battery level, timestamps, model metadata, and supported settings.
- Lock and unlock a lock.
- List account users.
- List access codes for a lock.
- Add, update, and delete access codes.
- List lock activity logs.
- Read redacted lock diagnostics for troubleshooting.
- Check keypad-disabled state from the latest lock log.
- Resolve who last changed the lock state from Schlage lock metadata.
- Update supported lock settings: beeper, lock-and-leave, and auto-lock time.
- Use either a TypeScript library API or a JSON-first CLI.
- Get stable redacted error objects for automation.

## Requirements

- Node.js 22 or newer.
- A Schlage account with access to a compatible Schlage Encode WiFi lock.

## Installation

```sh
npm install schlage-ts
```

After install, the package provides:

- `SchlageClient` for TypeScript/JavaScript applications.
- `schlage-ts` for command-line use.

## Configuration

The client needs a Schlage username and password. The CLI can read configuration from flags, environment variables, or a YAML file.

Environment variables:

```sh
export SCHLAGE_USERNAME="you@example.com"
export SCHLAGE_PASSWORD="your-password"
export SCHLAGE_CACHE_DIR="./.schlage-cache"
export SCHLAGE_API_KEY="..."
export SCHLAGE_CLIENT_ID="..."
export SCHLAGE_CLIENT_SECRET="..."
export SCHLAGE_USER_POOL_ID="..."
```

YAML config:

```yaml
schlage:
  usernameEnv: SCHLAGE_USERNAME
  passwordEnv: SCHLAGE_PASSWORD
  cacheDir: ./.schlage-cache
```

Then point the CLI at it:

```sh
export SCHLAGE_CONFIG=./config.yaml
```

Prefer environment variables or YAML environment indirection over putting secrets directly in shell history or committed files. `.env`, local YAML config, and `.schlage-cache/` are ignored by this repository.

The live transport also needs the Schlage mobile-app API key, Cognito client ID, Cognito client secret, and Cognito user pool ID. They can be passed to `createLiveSchlageTransports()` as options or provided through the four `SCHLAGE_*` environment variables above.

## CLI

The CLI writes one JSON object to stdout on success and one JSON object to stderr on failure. This makes it usable from scripts without scraping human-oriented text.

```sh
schlage-ts auth-check
schlage-ts list-locks
schlage-ts status <lock-id>
schlage-ts lock <lock-id>
schlage-ts unlock <lock-id>
schlage-ts users
schlage-ts access-codes <lock-id>
schlage-ts logs <lock-id> [--limit <n>] [--desc]
schlage-ts diagnostics <lock-id>
schlage-ts keypad-disabled <lock-id>
schlage-ts last-changed-by <lock-id>
schlage-ts add-access-code <lock-id> --name <name> --code <code> [--disabled] [--notify] [--temporary-starts-at <iso> --temporary-ends-at <iso>]
schlage-ts update-access-code <lock-id> <access-code-id> --name <name> --code <code> [--disabled] [--notify] [--temporary-starts-at <iso> --temporary-ends-at <iso>]
schlage-ts delete-access-code <lock-id> <access-code-id>
schlage-ts set-beeper <lock-id> <on|off>
schlage-ts set-lock-and-leave <lock-id> <on|off>
schlage-ts set-auto-lock-time <lock-id> <seconds>
```

Shared config flags:

- `--config <path>`: YAML config file. If omitted, `SCHLAGE_CONFIG` is used when present.
- `--username <username>`: Schlage username.
- `--password <password>`: Schlage password.
- `--cache-dir <path>`: local token/session cache directory.

Example:

```sh
schlage-ts list-locks
schlage-ts status front-door
schlage-ts logs front-door --limit 25 --desc
schlage-ts last-changed-by front-door
schlage-ts add-access-code front-door --name Cleaner --code 0042
schlage-ts set-auto-lock-time front-door 60
```

Example success shape:

```json
{
  "ok": true,
  "command": "status",
  "config": {
    "username": "[REDACTED_USERNAME]",
    "cacheDirConfigured": true,
    "sources": {
      "username": "environment",
      "password": "environment",
      "cacheDir": "environment"
    }
  },
  "auth": {
    "phase": "authenticated",
    "username": "[REDACTED_USERNAME]",
    "authenticated": true,
    "cache": { "status": "hit" }
  },
  "data": {
    "status": {
      "id": "front-door",
      "state": "locked",
      "batteryLevel": 87,
      "updatedAt": "2025-01-02T03:04:05.000Z"
    }
  }
}
```

Example failure shape:

```json
{
  "ok": false,
  "command": "status",
  "config": {
    "username": "[REDACTED_USERNAME]",
    "cacheDirConfigured": true,
    "sources": {
      "username": "environment",
      "password": "environment",
      "cacheDir": "environment"
    }
  },
  "auth": {
    "phase": "signed-out",
    "username": "[REDACTED_USERNAME]",
    "authenticated": false
  },
  "error": {
    "name": "SchlageError",
    "code": "SCHLAGE_LOCK_ID_INVALID",
    "message": "Schlage lock ID is required.",
    "retryable": false
  }
}
```

Access-code values are intentionally returned by `access-codes`, because that is the requested data. They are not included in auth snapshots, failure envelopes, lock status, or diagnostics.

## Library API

```ts
import { SchlageClient } from 'schlage-ts';

const client = new SchlageClient({
  username: process.env.SCHLAGE_USERNAME,
  password: process.env.SCHLAGE_PASSWORD,
  cacheDir: process.env.SCHLAGE_CACHE_DIR,
});

const locks = await client.listLocks();
const lockId = locks[0]?.id;

if (lockId !== undefined) {
  const status = await client.getStatus(lockId);
  const users = await client.listUsers();
  const accessCodes = await client.listAccessCodes(lockId);
  const logs = await client.listLogs(lockId, { limit: 25, sortDesc: true });
  const diagnostics = await client.getDiagnostics(lockId);
  const keypadDisabled = await client.keypadDisabled(lockId, logs);
  const lastChangedBy = await client.lastChangedBy(lockId);

  console.log({
    status,
    users,
    accessCodes,
    logs,
    diagnostics,
    keypadDisabled,
    lastChangedBy,
  });
}
```

Lock and unlock:

```ts
await client.lock('front-door');
await client.unlock('front-door');
```

Access-code writes and lock settings:

```ts
await client.addAccessCode('front-door', { name: 'Cleaner', code: '0042' });
await client.addAccessCode('front-door', {
  name: 'Temporary Cleaner',
  code: '0044',
  schedule: {
    type: 'temporary',
    startsAt: new Date('2026-01-02T03:04:05.000Z'),
    endsAt: new Date('2026-01-03T03:04:05.000Z'),
  },
});
await client.updateAccessCode('front-door', 'code-1', {
  name: 'Cleaner',
  code: '0043',
  disabled: true,
});
await client.deleteAccessCode('front-door', 'code-1');

await client.setBeeper('front-door', true);
await client.setLockAndLeave('front-door', false);
await client.setAutoLockTime('front-door', 60);
```

## Public Data Shapes

Lock summaries:

```ts
[{ id: 'front-door', name: 'Front Door', subtitle: 'Entry' }];
```

Lock status:

```ts
{
  id: 'front-door',
  state: 'locked',
  batteryLevel: 91,
  updatedAt: new Date('2025-01-02T03:04:05.000Z'),
  connected: true,
  beeperEnabled: true,
  lockAndLeaveEnabled: false,
  autoLockTime: 60,
  lockStateMetadata: {
    actionType: 'virtualKey',
    uuid: 'user-1'
  }
}
```

Command result:

```ts
{ id: 'front-door', accepted: true, observedState: 'locked' }
```

Access code:

```ts
{
  id: 'code-1',
  lockId: 'front-door',
  name: 'Cleaner',
  code: '0042',
  disabled: false
}
```

Activity log:

```ts
{
  lockId: 'front-door',
  createdAt: new Date('2025-01-02T03:04:05.000Z'),
  message: 'Unlocked by keypad',
  eventCode: 2,
  accessorId: 'user-1'
}
```

Diagnostics:

```ts
{
  deviceId: '<REDACTED>',
  name: 'Front Door',
  connected: true,
  attributes: {
    batteryLevel: 91,
    lockState: 1,
    lockStateMetadata: {
      actionType: 'virtualKey',
      UUID: 'user-1'
    }
  }
}
```

## Errors And Redaction

Public failures use `SchlageError` snapshots with stable `code` and `retryable` fields. Prefer branching on those fields instead of parsing error messages.

Common codes:

- `SCHLAGE_CONFIG_MISSING_CREDENTIALS`: credentials were not provided.
- `SCHLAGE_CONFIG_MALFORMED`: config file or CLI input was invalid.
- `SCHLAGE_AUTH_FAILED`: authentication failed.
- `SCHLAGE_RATE_LIMITED`: the Schlage API returned a rate-limit response.
- `SCHLAGE_LOCK_ID_INVALID`: a lock ID argument was blank or invalid.
- `SCHLAGE_PROTOCOL_MALFORMED`: the cloud response did not match the expected shape.
- `SCHLAGE_PROTOCOL_TRANSPORT`: network or API transport failure.
- `SCHLAGE_UNKNOWN_ERROR`: unexpected untyped failure.

The package is designed not to expose credentials, passwords, access tokens, refresh tokens, account IDs, cache paths, raw protocol payloads, stack traces, or transport-specific rejection reasons through public snapshots or CLI failure envelopes.

## Live Lock Safety

`lock` and `unlock` can change the state of a real lock. Run them only when the door state is safe and a local operator can confirm the result.

The live verifier also performs lock and unlock operations, then sends a final lock command and polls for a locked readback. It should not be run casually or in parallel with other lock automations.

```sh
npm run verify:live:preflight
npm run verify:live
```

## Development

Install dependencies:

```sh
npm install
```

Run the normal local checks:

```sh
npm test
npm run typecheck
npm run lint
npm run build
npm run verify:local
```

Check the package contents before publishing:

```sh
npm pack --dry-run
```

`verify:local` is a no-hardware guardrail. It exercises tests, type declarations, CLI smoke checks, failure redaction, and local cache behavior without requiring live credentials, network access, or physical locks.

`verify:live:preflight` checks live configuration without making Schlage API calls or changing a lock. `verify:live` runs the full live sequence against a configured lock: authenticate, list locks, read status, lock/unlock with bounded readbacks, toggle and restore supported settings, add/update/delete a temporary access code, final lock, and poll for locked. Set `SCHLAGE_S07_VERIFY_SCHEDULES=1` to also run an opt-in temporary schedule write/delete probe.

Live cloud behavior observed during verification:

- Fresh GET status reads can lag an accepted lock/unlock command for a few seconds. `SchlageClient` reconciles immediate `getStatus()` calls with the last accepted command state while the cloud read catches up. When `cacheDir`/`SCHLAGE_CACHE_DIR` is configured, separate CLI invocations share that short-lived command state too.
- Access-code schedule writes can be accepted while subsequent access-code list responses omit schedule fields.

## Status

This package is early and unofficial. The current public surface covers live auth, lock discovery, status reads, lock/unlock, users, access-code reads and writes, logs, diagnostics, keypad-disabled and last-changed-by helpers, supported lock settings, local cache, typed errors, and CLI automation.
