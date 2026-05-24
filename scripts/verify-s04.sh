#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

npm test
npm run typecheck
npm run lint
npm run build

node dist/cli.js --version >/dev/null
node dist/cli.js --help >/dev/null
node dist/cli.js auth-check --help >/dev/null
node dist/cli.js list-locks --help >/dev/null
node dist/cli.js status --help >/dev/null
node dist/cli.js lock --help >/dev/null
node dist/cli.js unlock --help >/dev/null

tmp_root="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp_root"
}
trap cleanup EXIT

cache_dir="$tmp_root/cache"
mkdir -p "$cache_dir"
cat >"$cache_dir/schlage-session-cache.json" <<'JSON'
{
  "accessToken": "verify-s04-access-token-value-00000000000000000000",
  "refreshToken": "verify-s04-refresh-token-value-00000000000000000000",
  "expiresAt": "2999-01-01T00:00:00.000Z",
  "refreshedAt": "2025-01-01T00:00:00.000Z",
  "accountId": "verify-s04-account-secret-12345"
}
JSON

success_json="$tmp_root/auth-success.json"
SCHLAGE_USERNAME="operator@example.test" \
SCHLAGE_PASSWORD="password=verify-s04-secret" \
SCHLAGE_CACHE_DIR="$cache_dir" \
  node dist/cli.js auth-check >"$success_json"

node -e '
const fs = require("node:fs");
const payload = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
const rendered = JSON.stringify(payload);
if (payload.ok !== true) throw new Error("auth-check cache smoke did not succeed");
if (payload.auth?.cache?.status !== "hit") throw new Error("auth-check did not report a cache hit");
for (const forbidden of ["operator@example.test", "verify-s04-secret", "verify-s04-access-token", "verify-s04-refresh-token", "verify-s04-account-secret"]) {
  if (rendered.includes(forbidden)) throw new Error(`auth-check leaked ${forbidden}`);
}
' "$success_json"

missing_json="$tmp_root/auth-missing.json"
if node dist/cli.js auth-check >"$tmp_root/missing.stdout" 2>"$missing_json"; then
  echo "auth-check without credentials unexpectedly succeeded" >&2
  exit 1
fi
node -e '
const fs = require("node:fs");
const payload = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
if (payload.ok !== false) throw new Error("missing credentials did not produce failure payload");
if (payload.error?.code !== "SCHLAGE_CONFIG_MISSING_CREDENTIALS") throw new Error("missing credentials used the wrong error code");
' "$missing_json"

corrupt_dir="$tmp_root/corrupt-cache"
mkdir -p "$corrupt_dir"
printf '{"accessToken":"verify-s04-corrupt-token-value-00000000000000000000"' >"$corrupt_dir/schlage-session-cache.json"
corrupt_json="$tmp_root/auth-corrupt.json"
if node dist/cli.js auth-check --username operator@example.test --password password=verify-s04-secret --cache-dir "$corrupt_dir" >"$tmp_root/corrupt.stdout" 2>"$corrupt_json"; then
  echo "auth-check with corrupt cache and no transport unexpectedly succeeded" >&2
  exit 1
fi
node -e '
const fs = require("node:fs");
const payload = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
const rendered = JSON.stringify(payload);
if (payload.auth?.cache?.status !== "malformed") throw new Error("corrupt cache did not surface malformed cache status");
if (payload.auth?.cache?.error?.code !== "SCHLAGE_CACHE_MALFORMED") throw new Error("corrupt cache used the wrong cache error code");
if (payload.error?.code !== "SCHLAGE_NOT_IMPLEMENTED") throw new Error("missing auth transport used the wrong error code");
for (const forbidden of ["verify-s04-corrupt-token", "verify-s04-secret", process.argv[2]]) {
  if (rendered.includes(forbidden)) throw new Error(`corrupt cache output leaked ${forbidden}`);
}
' "$corrupt_json" "$corrupt_dir"

required_outputs=(
  "dist/index.js"
  "dist/index.d.ts"
  "dist/config.js"
  "dist/config.d.ts"
  "dist/token-cache.js"
  "dist/token-cache.d.ts"
  "dist/auth.js"
  "dist/auth.d.ts"
  "dist/errors.js"
  "dist/errors.d.ts"
  "dist/protocol.js"
  "dist/protocol.d.ts"
  "dist/cli.js"
  "dist/cli.d.ts"
)

for output in "${required_outputs[@]}"; do
  if [[ ! -f "$output" ]]; then
    echo "Missing build output: $output" >&2
    exit 1
  fi
done

required_index_declarations=(
  "SchlageLockSummary"
  "SchlageLockStatus"
  "SchlageCommandResult"
  "SchlageClientProtocolTransport"
  "listLocks"
  "getStatus"
  "lock"
  "unlock"
  "PublicSchlageErrorSnapshot"
)

for declaration in "${required_index_declarations[@]}"; do
  grep -q "$declaration" dist/index.d.ts || {
    echo "Missing S04 public declaration/export in dist/index.d.ts: $declaration" >&2
    exit 1
  }
done

required_protocol_declarations=(
  "normalizeLockListPayload"
  "normalizeLockStatusPayload"
  "normalizeCommandPayload"
  "mapProtocolOperationError"
)

for declaration in "${required_protocol_declarations[@]}"; do
  grep -q "$declaration" dist/protocol.d.ts || {
    echo "Missing S04 internal protocol declaration in dist/protocol.d.ts: $declaration" >&2
    exit 1
  }
done

required_error_codes=(
  "SCHLAGE_LOCK_ID_INVALID"
  "SCHLAGE_PROTOCOL_MALFORMED"
  "SCHLAGE_PROTOCOL_TRANSPORT"
  "SCHLAGE_AUTH_FAILED"
  "SCHLAGE_UNKNOWN_ERROR"
)

for code in "${required_error_codes[@]}"; do
  grep -q "$code" dist/errors.d.ts || {
    echo "Missing safe S04 error code declaration in dist/errors.d.ts: $code" >&2
    exit 1
  }
done

if grep -R "verify-s04-secret\|verify-s04-access-token\|verify-s04-refresh-token\|verify-s04-account-secret\|verify-s04-corrupt-token" dist README.md >/dev/null; then
  echo "Secret-shaped S04 verification fixture leaked into build output or README" >&2
  exit 1
fi

if grep -R "client-protocol-access-token-value\|client-protocol-refresh-token-value\|client-protocol-account-secret\|raw-list-token-value\|raw-status-refresh-token\|raw-lock-command-token\|raw-unlock-command-token\|malformed-protocol-token\|protocol-failure-token\|command-failure-token" dist README.md >/dev/null; then
  echo "Protocol test fixture secret leaked into build output or README" >&2
  exit 1
fi

echo "S04 verification passed."
