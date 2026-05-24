#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

load_dotenv_if_present() {
  if [[ -n "${SCHLAGE_S07_SKIP_DOTENV:-}" ]]; then
    return
  fi

  local env_file="${SCHLAGE_S07_DOTENV_PATH:-$repo_root/.env}"
  if [[ ! -f "$env_file" ]]; then
    return
  fi

  local line key value
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    if [[ "$line" =~ ^[[:space:]]*$ || "$line" =~ ^[[:space:]]*# ]]; then
      continue
    fi
    if [[ "$line" =~ ^[[:space:]]*export[[:space:]]+(.+)$ ]]; then
      line="${BASH_REMATCH[1]}"
    fi
    if [[ ! "$line" =~ ^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
      continue
    fi

    key="${BASH_REMATCH[1]}"
    value="${BASH_REMATCH[2]}"
    if [[ -n "${!key+x}" ]]; then
      continue
    fi
    if [[ ${#value} -ge 2 ]]; then
      if [[ "${value:0:1}" == "'" && "${value: -1}" == "'" ]]; then
        value="${value:1:${#value}-2}"
      elif [[ "${value:0:1}" == '"' && "${value: -1}" == '"' ]]; then
        value="${value:1:${#value}-2}"
      fi
    fi
    export "$key=$value"
  done < "$env_file"
}

load_dotenv_if_present

print_help() {
  cat <<'EOF'
Usage: bash scripts/verify-s07-live.sh [--preflight] [--help]

Runs the S07 live Schlage Encode Plus verification sequence with redacted diagnostics:
  1. npm run verify:s06 guardrail
  2. npm run build
  3. auth-check
  4. list-locks
  5. status <configured-lock-id>
  6. lock <configured-lock-id>
  7. status readback until locked or bounded retry exhaustion
  8. unlock <configured-lock-id>
  9. status readback until unlocked or bounded retry exhaustion
 10. lock <configured-lock-id> to leave the device locked
 11. status readback until locked or bounded retry exhaustion

Required live configuration, provided either by environment defaults or YAML indirection:
  SCHLAGE_USERNAME
  SCHLAGE_PASSWORD
  SCHLAGE_LOCK_ID

Optional configuration:
  SCHLAGE_CONFIG                 Path to config YAML with usernameEnv/passwordEnv/lockIdEnv or direct local values.
  SCHLAGE_CACHE_DIR              Local token cache directory. Keep it gitignored.
  SCHLAGE_S07_DIAGNOSTICS_DIR    Redacted transcript output directory. Defaults to a temp directory.
  SCHLAGE_S07_STATUS_ATTEMPTS    Readback attempts after lock/unlock. Defaults to 12.
  SCHLAGE_S07_STATUS_DELAY       Seconds between readback attempts. Defaults to 5.

Test/development overrides:
  SCHLAGE_S07_CLI                CLI executable path. Defaults to dist/cli.js through node.
  SCHLAGE_S07_SKIP_GUARDRAIL=1   Skip verify:s06. Intended only for verifier self-tests.
  SCHLAGE_S07_SKIP_BUILD=1       Skip npm run build. Intended only for verifier self-tests.

The verifier prints key names, phases, exit codes, and diagnostics file names only. It must not print
credential values, tokens, account IDs, cache paths, raw protocol payloads, or stack traces.
EOF
}

usage_error() {
  echo "$1" >&2
  echo "Run with --help for usage." >&2
  exit 2
}

mode="run"
while (($#)); do
  case "$1" in
    --help|-h)
      print_help
      exit 0
      ;;
    --preflight)
      mode="preflight"
      shift
      ;;
    *)
      usage_error "Unknown argument: $1"
      ;;
  esac
done

helper() {
  local helper_mode="$1"
  shift
  node --input-type=module - "$helper_mode" "$@" <<'NODE'
import { existsSync, readFileSync } from 'node:fs';
import { parse as parseYaml } from 'yaml';

const [mode, ...args] = process.argv.slice(2);
const secretShapePatterns = [
  /AccessToken/i,
  /RefreshToken/i,
  /accessToken/i,
  /refreshToken/i,
  /accountId/i,
  /Bearer\s+[A-Za-z0-9._~+\/-]+=*/i,
  /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/,
  /password\s*[:=]/i,
  /Error:\s+/,
  /\n\s+at\s+[^\n]+/,
  /stack/i,
];

function trim(value) {
  return typeof value === 'string' && value.trim().length > 0 ? value.trim() : undefined;
}

function readYamlConfig() {
  const path = trim(process.env.SCHLAGE_CONFIG);
  if (!path) return {};
  try {
    if (!existsSync(path)) return { error: 'SCHLAGE_CONFIG' };
    const parsed = parseYaml(readFileSync(path, 'utf8')) ?? {};
    return typeof parsed === 'object' && parsed !== null ? parsed : {};
  } catch {
    return { error: 'SCHLAGE_CONFIG' };
  }
}

function resolveValue(yaml, key, defaultEnvName) {
  const schlage = typeof yaml.schlage === 'object' && yaml.schlage !== null ? yaml.schlage : {};
  const direct = trim(schlage[key]);
  if (direct) return { value: direct, source: 'yaml' };
  const envRef = trim(schlage[`${key}Env`]);
  if (envRef) {
    const value = trim(process.env[envRef]);
    if (value) return { value, source: 'environment', keyName: envRef };
  }
  const envValue = trim(process.env[defaultEnvName]);
  if (envValue) return { value: envValue, source: 'environment', keyName: defaultEnvName };
  return { missing: defaultEnvName };
}

function configValues() {
  const yaml = readYamlConfig();
  return {
    yamlError: yaml.error,
    username: resolveValue(yaml, 'username', 'SCHLAGE_USERNAME'),
    password: resolveValue(yaml, 'password', 'SCHLAGE_PASSWORD'),
    lockId: resolveValue(yaml, 'lockId', 'SCHLAGE_LOCK_ID'),
    cacheDir: resolveValue(yaml, 'cacheDir', 'SCHLAGE_CACHE_DIR'),
  };
}

function parseEnvelope(path) {
  try {
    const text = readFileSync(path, 'utf8');
    return JSON.parse(text);
  } catch (error) {
    throw new Error(`malformed JSON envelope at ${path}`);
  }
}

function stateOf(envelope) {
  return envelope?.data?.status?.state ?? envelope?.data?.result?.observedState;
}

if (mode === 'preflight') {
  const values = configValues();
  const missing = [];
  if (values.yamlError) missing.push(values.yamlError);
  for (const [name, result] of [
    ['SCHLAGE_USERNAME', values.username],
    ['SCHLAGE_PASSWORD', values.password],
    ['SCHLAGE_LOCK_ID', values.lockId],
  ]) {
    if (result.missing) missing.push(name);
  }
  if (missing.length > 0) {
    console.error(`Missing required Schlage live verifier configuration keys: ${[...new Set(missing)].join(', ')}`);
    process.exit(3);
  }
  console.log(JSON.stringify({ ok: true, lockId: values.lockId.value, sources: { username: values.username.source, password: values.password.source, lockId: values.lockId.source, ...(values.cacheDir.value ? { cacheDir: values.cacheDir.source } : {}) } }));
} else if (mode === 'assert-envelope') {
  const [path, expectedCommand, expectedOk] = args;
  const envelope = parseEnvelope(path);
  const ok = expectedOk === 'true';
  if (envelope.ok !== ok) throw new Error(`${path} expected ok=${ok}, got ${envelope.ok}`);
  if (envelope.command !== expectedCommand) throw new Error(`${path} expected command ${expectedCommand}, got ${envelope.command}`);
  if (ok) {
    if (!envelope.config) throw new Error(`${path} omitted redacted config snapshot`);
    if (!envelope.auth) throw new Error(`${path} omitted redacted auth snapshot`);
  } else if (!envelope.error?.code || typeof envelope.error.retryable !== 'boolean') {
    throw new Error(`${path} omitted typed public error code or retryable flag`);
  }
} else if (mode === 'assert-state') {
  const [path, expectedState] = args;
  const envelope = parseEnvelope(path);
  const actual = stateOf(envelope);
  if (actual !== expectedState) throw new Error(`${path} expected state ${expectedState}, got ${actual ?? '<missing>'}`);
} else if (mode === 'leak-scan') {
  const [path] = args;
  const text = readFileSync(path, 'utf8');
  const values = configValues();
  const forbidden = [
    values.username.value,
    values.password.value,
    values.cacheDir.value,
  ].filter(Boolean);
  for (const value of forbidden) {
    if (text.includes(value)) throw new Error(`${path} leaked configured secret or local path`);
  }
  for (const pattern of secretShapePatterns) {
    if (pattern.test(text)) throw new Error(`${path} matched forbidden diagnostic pattern ${pattern}`);
  }
} else {
  throw new Error(`unknown helper mode ${mode}`);
}
NODE
}

preflight_output="$(helper preflight)"
lock_id="$(node --input-type=module -e 'const payload = JSON.parse(process.argv[1]); process.stdout.write(payload.lockId);' "$preflight_output")"

if [[ "$mode" == "preflight" ]]; then
  echo "S07 preflight passed: required key names are configured. No live network calls were made."
  exit 0
fi

status_attempts="${SCHLAGE_S07_STATUS_ATTEMPTS:-12}"
status_delay="${SCHLAGE_S07_STATUS_DELAY:-5}"
if ! [[ "$status_attempts" =~ ^[1-9][0-9]*$ ]]; then
  usage_error "SCHLAGE_S07_STATUS_ATTEMPTS must be a positive integer"
fi
if ! [[ "$status_delay" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
  usage_error "SCHLAGE_S07_STATUS_DELAY must be a non-negative number"
fi

diag_dir="${SCHLAGE_S07_DIAGNOSTICS_DIR:-}"
if [[ -z "$diag_dir" ]]; then
  diag_dir="$(mktemp -d "${TMPDIR:-/tmp}/schlage-s07-live.XXXXXX")"
else
  mkdir -p "$diag_dir"
fi
summary_path="$diag_dir/summary.tsv"
printf 'phase\tcommand\texit_code\tstdout\tstderr\n' >"$summary_path"

run_cli() {
  if [[ -n "${SCHLAGE_S07_CLI:-}" ]]; then
    "$SCHLAGE_S07_CLI" "$@"
  else
    node dist/cli.js "$@"
  fi
}

scan_phase_files() {
  local stdout_path="$1"
  local stderr_path="$2"
  helper leak-scan "$stdout_path"
  helper leak-scan "$stderr_path"
}

record_summary() {
  local phase="$1"
  local command_name="$2"
  local exit_code="$3"
  local stdout_path="$4"
  local stderr_path="$5"
  printf '%s\t%s\t%s\t%s\t%s\n' "$phase" "$command_name" "$exit_code" "$(basename "$stdout_path")" "$(basename "$stderr_path")" >>"$summary_path"
}

run_json_phase() {
  local phase="$1"
  local command_name="$2"
  shift 2
  local stdout_path="$diag_dir/${phase}.stdout.json"
  local stderr_path="$diag_dir/${phase}.stderr.json"
  local exit_code=0

  set +e
  run_cli "$command_name" "$@" >"$stdout_path" 2>"$stderr_path"
  exit_code=$?
  set -e

  scan_phase_files "$stdout_path" "$stderr_path"
  record_summary "$phase" "$command_name" "$exit_code" "$stdout_path" "$stderr_path"

  if [[ "$exit_code" -ne 0 ]]; then
    if [[ -s "$stderr_path" ]]; then
      helper assert-envelope "$stderr_path" "$command_name" false
    fi
    echo "S07 phase failed: $phase (command=$command_name, exit=$exit_code). Redacted diagnostics: $diag_dir" >&2
    exit "$exit_code"
  fi

  helper assert-envelope "$stdout_path" "$command_name" true
  printf '%s' "$stdout_path"
}

readback_until() {
  local phase_prefix="$1"
  local expected_state="$2"
  local attempt=1
  local status_path=""

  while (( attempt <= status_attempts )); do
    status_path="$(run_json_phase "${phase_prefix}-${attempt}" status "$lock_id")"
    if helper assert-state "$status_path" "$expected_state" >/dev/null 2>&1; then
      echo "S07 readback converged: phase=${phase_prefix}, state=${expected_state}, attempt=${attempt}"
      return 0
    fi
    if (( attempt < status_attempts )); then
      sleep "$status_delay"
    fi
    attempt=$((attempt + 1))
  done

  helper assert-state "$status_path" "$expected_state"
}

if [[ "${SCHLAGE_S07_SKIP_GUARDRAIL:-0}" != "1" ]]; then
  echo "S07: running S06 guardrail before live hardware operations."
  npm run verify:s06
else
  echo "S07: skipping S06 guardrail because SCHLAGE_S07_SKIP_GUARDRAIL=1."
fi

if [[ "${SCHLAGE_S07_SKIP_BUILD:-0}" != "1" ]]; then
  echo "S07: building package."
  npm run build
else
  echo "S07: skipping build because SCHLAGE_S07_SKIP_BUILD=1."
fi

echo "S07: diagnostics directory is $diag_dir"
echo "S07: executing live verifier sequence. Physical lock state will change."

run_json_phase "01-auth-check" auth-check >/dev/null
run_json_phase "02-list-locks" list-locks >/dev/null
run_json_phase "03-status-before" status "$lock_id" >/dev/null
lock_path="$(run_json_phase "04-lock" lock "$lock_id")"
if helper assert-state "$lock_path" locked >/dev/null 2>&1; then
  echo "S07: lock command reported observedState=locked."
fi
readback_until "05-status-after-lock" locked
unlock_path="$(run_json_phase "06-unlock" unlock "$lock_id")"
if helper assert-state "$unlock_path" unlocked >/dev/null 2>&1; then
  echo "S07: unlock command reported observedState=unlocked."
fi
if readback_until "07-status-after-unlock" unlocked; then
  :
fi
final_lock_path="$(run_json_phase "08-final-lock" lock "$lock_id")"
if helper assert-state "$final_lock_path" locked >/dev/null 2>&1; then
  echo "S07: final lock command reported observedState=locked."
fi
readback_until "09-status-after-final-lock" locked

if grep -R . "$diag_dir" >/dev/null; then
  while IFS= read -r -d '' file; do
    helper leak-scan "$file"
  done < <(find "$diag_dir" -type f -print0)
fi

echo "S07 live verification passed. Redacted diagnostics: $diag_dir"
