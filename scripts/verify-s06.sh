#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
export SCHLAGE_TS_DISABLE_LIVE_TRANSPORT=1

npx vitest run tests/failure-visibility.test.ts tests/cli-commands.test.ts tests/cli-config.test.ts
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
  "accessToken": "verify-s06-access-token-value-00000000000000000000",
  "refreshToken": "verify-s06-refresh-token-value-00000000000000000000",
  "expiresAt": "2999-01-01T00:00:00.000Z",
  "refreshedAt": "2025-01-01T00:00:00.000Z",
  "accountId": "verify-s06-account-secret-12345"
}
JSON

assert_json_failure() {
  local json_path="$1"
  local expected_command="$2"
  local expected_code="$3"
  local expected_retryable="$4"
  local expected_cache_status="${5:-}"
  shift 5 || true

  node -e '
const fs = require("node:fs");
const [path, expectedCommand, expectedCode, expectedRetryableText, expectedCacheStatus, ...forbidden] = process.argv.slice(1);
const payload = JSON.parse(fs.readFileSync(path, "utf8"));
const rendered = JSON.stringify(payload);
const expectedRetryable = expectedRetryableText === "true";
if (payload.ok !== false) throw new Error("failure payload did not set ok=false");
if (payload.command !== expectedCommand) throw new Error(`expected command ${expectedCommand}, got ${payload.command}`);
if (payload.error?.code !== expectedCode) throw new Error(`expected ${expectedCode}, got ${payload.error?.code}`);
if (payload.error?.retryable !== expectedRetryable) throw new Error(`expected retryable=${expectedRetryable}, got ${payload.error?.retryable}`);
if (typeof payload.error?.message !== "string" || payload.error.message.length === 0) throw new Error("failure payload omitted safe message");
if (expectedCacheStatus && payload.auth?.cache?.status !== expectedCacheStatus) {
  throw new Error(`expected auth.cache.status=${expectedCacheStatus}, got ${payload.auth?.cache?.status}`);
}
if (rendered.includes("Error:") || rendered.includes("stack")) throw new Error("failure payload exposed stack-shaped diagnostics");
for (const value of forbidden) {
  if (value && rendered.includes(value)) throw new Error(`failure payload leaked ${value}`);
}
' "$json_path" "$expected_command" "$expected_code" "$expected_retryable" "$expected_cache_status" "$@"
}

assert_json_success() {
  local json_path="$1"
  local expected_command="$2"
  shift 2

  node -e '
const fs = require("node:fs");
const [path, expectedCommand, ...forbidden] = process.argv.slice(1);
const payload = JSON.parse(fs.readFileSync(path, "utf8"));
const rendered = JSON.stringify(payload);
if (payload.ok !== true) throw new Error("success payload did not set ok=true");
if (payload.command !== expectedCommand) throw new Error(`expected command ${expectedCommand}, got ${payload.command}`);
if (!payload.config) throw new Error("success payload omitted redacted config snapshot");
if (!payload.auth) throw new Error("success payload omitted redacted auth snapshot");
if (rendered.includes("Error:") || rendered.includes("stack")) throw new Error("success payload exposed stack-shaped diagnostics");
for (const value of forbidden) {
  if (value && rendered.includes(value)) throw new Error(`success payload leaked ${value}`);
}
' "$json_path" "$expected_command" "$@"
}

success_json="$tmp_root/auth-success.json"
SCHLAGE_USERNAME="operator@example.test" \
SCHLAGE_PASSWORD="password=verify-s06-secret" \
SCHLAGE_CACHE_DIR="$cache_dir" \
  node dist/cli.js auth-check >"$success_json"

node -e '
const fs = require("node:fs");
const payload = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
if (payload.auth?.cache?.status !== "hit") throw new Error("auth-check did not report a cache hit");
if (payload.auth?.phase !== "authenticated") throw new Error("auth-check did not report authenticated phase");
' "$success_json"
assert_json_success "$success_json" "auth-check" \
  "operator@example.test" \
  "verify-s06-secret" \
  "verify-s06-access-token" \
  "verify-s06-refresh-token" \
  "verify-s06-account-secret" \
  "$cache_dir"

missing_json="$tmp_root/auth-missing.json"
if env -u SCHLAGE_USERNAME \
       -u SCHLAGE_PASSWORD \
       -u SCHLAGE_CONFIG \
       -u SCHLAGE_CACHE_DIR \
       -u SCHLAGE_LOCK_ID \
       node dist/cli.js auth-check >"$tmp_root/missing.stdout" 2>"$missing_json"; then
  echo "auth-check without credentials unexpectedly succeeded" >&2
  exit 1
fi
assert_json_failure "$missing_json" "auth-check" "SCHLAGE_CONFIG_MISSING_CREDENTIALS" "false" "" \
  "operator@example.test" \
  "verify-s06-secret" \
  "verify-s06-access-token" \
  "verify-s06-refresh-token" \
  "$cache_dir"

corrupt_dir="$tmp_root/corrupt-cache"
mkdir -p "$corrupt_dir"
printf '{"accessToken":"verify-s06-corrupt-token-value-00000000000000000000"' >"$corrupt_dir/schlage-session-cache.json"
corrupt_json="$tmp_root/auth-corrupt.json"
if node dist/cli.js auth-check --username operator@example.test --password password=verify-s06-secret --cache-dir "$corrupt_dir" >"$tmp_root/corrupt.stdout" 2>"$corrupt_json"; then
  echo "auth-check with corrupt cache and no transport unexpectedly succeeded" >&2
  exit 1
fi
assert_json_failure "$corrupt_json" "auth-check" "SCHLAGE_NOT_IMPLEMENTED" "false" "malformed" \
  "operator@example.test" \
  "verify-s06-secret" \
  "verify-s06-corrupt-token" \
  "$corrupt_dir"

run_no_transport_failure() {
  local command_name="$1"
  local expected_code="$2"
  shift 2
  local stdout_path="$tmp_root/${command_name}.stdout"
  local stderr_path="$tmp_root/${command_name}.stderr"

  if SCHLAGE_USERNAME="operator@example.test" \
     SCHLAGE_PASSWORD="password=verify-s06-secret" \
     SCHLAGE_CACHE_DIR="$cache_dir" \
       node dist/cli.js "$command_name" "$@" >"$stdout_path" 2>"$stderr_path"; then
    echo "$command_name with cache hit and no transport unexpectedly succeeded" >&2
    exit 1
  fi

  if [[ -s "$stdout_path" ]]; then
    echo "$command_name failure wrote stdout" >&2
    exit 1
  fi

  assert_json_failure "$stderr_path" "$command_name" "$expected_code" "false" "hit" \
    "operator@example.test" \
    "verify-s06-secret" \
    "verify-s06-access-token" \
    "verify-s06-refresh-token" \
    "verify-s06-account-secret" \
    "$cache_dir"
}

run_no_transport_failure "list-locks" "SCHLAGE_NOT_IMPLEMENTED"
run_no_transport_failure "status" "SCHLAGE_NOT_IMPLEMENTED" "front-door"
run_no_transport_failure "lock" "SCHLAGE_NOT_IMPLEMENTED" "front-door"
run_no_transport_failure "unlock" "SCHLAGE_NOT_IMPLEMENTED" "front-door"

blank_lock_json="$tmp_root/blank-lock.stderr"
if node dist/cli.js lock "   " --username operator@example.test --password password=verify-s06-secret >"$tmp_root/blank-lock.stdout" 2>"$blank_lock_json"; then
  echo "lock with blank lock id unexpectedly succeeded" >&2
  exit 1
fi
assert_json_failure "$blank_lock_json" "lock" "SCHLAGE_LOCK_ID_INVALID" "false" "" \
  "operator@example.test" \
  "verify-s06-secret" \
  "$cache_dir"

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
  "SchlageClient"
  "SchlageClientOptions"
  "SchlageLockSummary"
  "SchlageLockStatus"
  "SchlageCommandResult"
  "PublicSchlageConfigSnapshot"
  "PublicSchlageAuthSnapshot"
  "PublicSchlageErrorSnapshot"
  "SchlageErrorCode"
  "SchlageFailureClassification"
  "classifySchlageFailure"
  "toPublicSchlageError"
  "wrapUnknownSchlageError"
  "listLocks"
  "getStatus"
  "lock"
  "unlock"
)

for declaration in "${required_index_declarations[@]}"; do
  grep -q "$declaration" dist/index.d.ts || {
    echo "Missing S06 public declaration/export in dist/index.d.ts: $declaration" >&2
    exit 1
  }
done

required_cli_declarations=(
  "CliClient"
  "CliRuntime"
  "CliSuccessPayload"
  "CliFailurePayload"
  "createCli"
  "main"
  "runCliCommand"
)

for declaration in "${required_cli_declarations[@]}"; do
  grep -q "$declaration" dist/cli.d.ts || {
    echo "Missing S06 CLI declaration in dist/cli.d.ts: $declaration" >&2
    exit 1
  }
done

required_error_declarations=(
  "SCHLAGE_CONFIG_MISSING_CREDENTIALS"
  "SCHLAGE_CONFIG_MALFORMED"
  "SCHLAGE_CONFIG_READ_FAILED"
  "SCHLAGE_CACHE_MALFORMED"
  "SCHLAGE_CACHE_REJECTED"
  "SCHLAGE_CACHE_READ_FAILED"
  "SCHLAGE_CACHE_WRITE_FAILED"
  "SCHLAGE_AUTH_FAILED"
  "SCHLAGE_AUTH_PROTOCOL"
  "SCHLAGE_RATE_LIMITED"
  "SCHLAGE_LOCK_ID_INVALID"
  "SCHLAGE_PROTOCOL_MALFORMED"
  "SCHLAGE_PROTOCOL_TRANSPORT"
  "SCHLAGE_UNKNOWN_ERROR"
  "SCHLAGE_NOT_IMPLEMENTED"
  "SchlageFailureClassification"
  "classifySchlageFailure"
)

for declaration in "${required_error_declarations[@]}"; do
  grep -q "$declaration" dist/errors.d.ts || {
    echo "Missing S06 error declaration in dist/errors.d.ts: $declaration" >&2
    exit 1
  }
done

if grep -R "verify-s06-secret\|verify-s06-access-token\|verify-s06-refresh-token\|verify-s06-account-secret\|verify-s06-corrupt-token" dist README.md >/dev/null; then
  echo "Secret-shaped S06 verification fixture leaked into build output or README" >&2
  exit 1
fi

if find "$tmp_root" -maxdepth 1 -type f -print0 | xargs -0 grep -H "verify-s06-secret\|verify-s06-access-token\|verify-s06-refresh-token\|verify-s06-account-secret\|verify-s06-corrupt-token" >/dev/null; then
  echo "Secret-shaped S06 verification fixture leaked into CLI outputs" >&2
  exit 1
fi

if grep -R "operator@example.test\|password=verify-s06\|$cache_dir\|$corrupt_dir" "$tmp_root" >/dev/null; then
  echo "S06 CLI output leaked credentials or cache paths" >&2
  exit 1
fi

if grep -R "cli-command-access-token-value\|cli-command-refresh-token-value\|cli-command-account-secret\|cli-command-real-access-token-value\|cli-command-real-refresh-token-value\|cli-command-real-account-secret\|raw-status-session-token\|malformed-status-token\|transport-token\|command-transport-token\|malformed-command-token\|unexpected-command-token" dist README.md >/dev/null; then
  echo "CLI command test fixture secret leaked into build output or README" >&2
  exit 1
fi

if grep -R "raw-access-token-value\|raw-refresh-token-value\|bearer-session-secret\|account-12345\|hunter2" dist README.md >/dev/null; then
  echo "Failure visibility test fixture secret leaked into build output or README" >&2
  exit 1
fi

echo "S06 verification passed."
