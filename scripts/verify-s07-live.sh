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
  1. scripts/verify-s06.sh guardrail
  2. npm run build
  3. auth-check
  4. list-locks
  5. status <configured-lock-id>
  6. lock <configured-lock-id>
  7. status readback until locked or bounded retry exhaustion
  8. unlock <configured-lock-id>
  9. status readback until unlocked or bounded retry exhaustion
 10. supported settings toggle/restore verification
 11. access-code add/update/delete verification
 12. optional temporary schedule write probe when SCHLAGE_S07_VERIFY_SCHEDULES=1
 13. lock <configured-lock-id> to leave the device locked
 14. status readback until locked or bounded retry exhaustion

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
  SCHLAGE_S07_VERIFY_SCHEDULES   Set to 1 for an opt-in temporary schedule write/delete probe.

Test/development overrides:
  SCHLAGE_S07_CLI                CLI executable path. Defaults to dist/cli.js through node.
  SCHLAGE_S07_SKIP_GUARDRAIL=1   Skip the local S06 guardrail. Intended only for verifier self-tests.
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

function statusFieldOf(envelope, field) {
  return envelope?.data?.status?.[field];
}

function writeAcceptedOf(envelope) {
  return envelope?.data?.write?.accepted;
}

function accessCodeByName(envelope, name) {
  return envelope?.data?.accessCodes?.find((entry) => entry?.name === name);
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
} else if (mode === 'status-field') {
  const [path, field] = args;
  const envelope = parseEnvelope(path);
  const value = statusFieldOf(envelope, field);
  if (value === undefined) throw new Error(`${path} omitted status field ${field}`);
  process.stdout.write(String(value));
} else if (mode === 'assert-status-field') {
  const [path, field, expectedValue] = args;
  const envelope = parseEnvelope(path);
  const actual = statusFieldOf(envelope, field);
  if (String(actual) !== expectedValue) throw new Error(`${path} expected status.${field}=${expectedValue}, got ${actual ?? '<missing>'}`);
} else if (mode === 'assert-write-accepted') {
  const [path] = args;
  const envelope = parseEnvelope(path);
  if (writeAcceptedOf(envelope) !== true) throw new Error(`${path} expected accepted write result`);
} else if (mode === 'write-access-code-id') {
  const [path] = args;
  const envelope = parseEnvelope(path);
  const id = envelope?.data?.write?.accessCodeId;
  if (typeof id !== 'string' || id.trim().length === 0) throw new Error(`${path} omitted write accessCodeId`);
  process.stdout.write(id);
} else if (mode === 'access-code-id-by-name') {
  const [path, name] = args;
  const envelope = parseEnvelope(path);
  const entry = accessCodeByName(envelope, name);
  if (typeof entry?.id !== 'string' || entry.id.trim().length === 0) throw new Error(`${path} omitted access code named ${name}`);
  process.stdout.write(entry.id);
} else if (mode === 'assert-access-code') {
  const [path, name, expectedCode, expectedDisabled] = args;
  const envelope = parseEnvelope(path);
  const entry = accessCodeByName(envelope, name);
  if (!entry) throw new Error(`${path} expected access code named ${name}`);
  if (entry.code !== expectedCode) throw new Error(`${path} expected access code ${name} to have requested code`);
  if (String(entry.disabled) !== expectedDisabled) throw new Error(`${path} expected access code ${name} disabled=${expectedDisabled}, got ${entry.disabled}`);
} else if (mode === 'assert-no-access-code') {
  const [path, name] = args;
  const envelope = parseEnvelope(path);
  if (accessCodeByName(envelope, name)) throw new Error(`${path} still includes access code named ${name}`);
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

cleanup_needed=0
baseline_beeper=""
baseline_lock_and_leave=""
baseline_auto_lock_time=""
temp_access_id=""

cleanup_on_exit() {
  local exit_code=$?
  if [[ "$cleanup_needed" != "1" || "$exit_code" -eq 0 ]]; then
    return
  fi

  set +e
  if [[ -n "$temp_access_id" ]]; then
    run_cli delete-access-code "$lock_id" "$temp_access_id" >/dev/null 2>&1
  fi
  if [[ -n "$baseline_beeper" ]]; then
    run_cli set-beeper "$lock_id" "$(on_off_for_boolean "$baseline_beeper")" >/dev/null 2>&1
  fi
  if [[ -n "$baseline_lock_and_leave" ]]; then
    run_cli set-lock-and-leave "$lock_id" "$(on_off_for_boolean "$baseline_lock_and_leave")" >/dev/null 2>&1
  fi
  if [[ -n "$baseline_auto_lock_time" ]]; then
    run_cli set-auto-lock-time "$lock_id" "$baseline_auto_lock_time" >/dev/null 2>&1
  fi
  run_cli lock "$lock_id" >/dev/null 2>&1
}

trap cleanup_on_exit EXIT

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

on_off_for_boolean() {
  case "$1" in
    true) printf 'on' ;;
    false) printf 'off' ;;
    *) usage_error "Expected boolean setting value, got $1" ;;
  esac
}

opposite_on_off_for_boolean() {
  case "$1" in
    true) printf 'off' ;;
    false) printf 'on' ;;
    *) usage_error "Expected boolean setting value, got $1" ;;
  esac
}

opposite_boolean_string() {
  case "$1" in
    true) printf 'false' ;;
    false) printf 'true' ;;
    *) usage_error "Expected boolean setting value, got $1" ;;
  esac
}

alternate_auto_lock_time() {
  if [[ "$1" == "60" ]]; then
    printf '30'
  else
    printf '60'
  fi
}

run_write_phase() {
  local phase="$1"
  local command_name="$2"
  shift 2
  local path
  path="$(run_json_phase "$phase" "$command_name" "$@")"
  helper assert-write-accepted "$path"
  printf '%s' "$path"
}

verify_setting_field() {
  local phase="$1"
  local field="$2"
  local expected_value="$3"
  local path
  path="$(run_json_phase "$phase" status "$lock_id")"
  helper assert-status-field "$path" "$field" "$expected_value"
}

readback_setting_until() {
  local phase_prefix="$1"
  local field="$2"
  local expected_value="$3"
  local attempt=1
  local status_path=""

  while (( attempt <= status_attempts )); do
    status_path="$(run_json_phase "${phase_prefix}-${attempt}" status "$lock_id")"
    if helper assert-status-field "$status_path" "$field" "$expected_value" >/dev/null 2>&1; then
      echo "S07 setting readback converged: phase=${phase_prefix}, field=${field}, value=${expected_value}, attempt=${attempt}"
      return 0
    fi
    if (( attempt < status_attempts )); then
      sleep "$status_delay"
    fi
    attempt=$((attempt + 1))
  done

  helper assert-status-field "$status_path" "$field" "$expected_value"
}

if [[ "${SCHLAGE_S07_SKIP_GUARDRAIL:-0}" != "1" ]]; then
  echo "S07: running S06 guardrail before live hardware operations."
  bash scripts/verify-s06.sh
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

cleanup_needed=1
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

settings_baseline_path="$(run_json_phase "08-settings-baseline" status "$lock_id")"
baseline_beeper="$(helper status-field "$settings_baseline_path" beeperEnabled)"
baseline_lock_and_leave="$(helper status-field "$settings_baseline_path" lockAndLeaveEnabled)"
baseline_auto_lock_time="$(helper status-field "$settings_baseline_path" autoLockTime)"

target_beeper="$(opposite_on_off_for_boolean "$baseline_beeper")"
target_beeper_value="$(opposite_boolean_string "$baseline_beeper")"
run_write_phase "09-set-beeper" set-beeper "$lock_id" "$target_beeper" >/dev/null
readback_setting_until "10-status-after-set-beeper" beeperEnabled "$target_beeper_value"
verify_setting_field "11-status-after-set-beeper-confirm" beeperEnabled "$target_beeper_value"
run_write_phase "12-restore-beeper" set-beeper "$lock_id" "$(on_off_for_boolean "$baseline_beeper")" >/dev/null
readback_setting_until "13-status-after-restore-beeper" beeperEnabled "$baseline_beeper"

target_lock_and_leave="$(opposite_on_off_for_boolean "$baseline_lock_and_leave")"
target_lock_and_leave_value="$(opposite_boolean_string "$baseline_lock_and_leave")"
run_write_phase "14-set-lock-and-leave" set-lock-and-leave "$lock_id" "$target_lock_and_leave" >/dev/null
readback_setting_until "15-status-after-set-lock-and-leave" lockAndLeaveEnabled "$target_lock_and_leave_value"
run_write_phase "16-restore-lock-and-leave" set-lock-and-leave "$lock_id" "$(on_off_for_boolean "$baseline_lock_and_leave")" >/dev/null
readback_setting_until "17-status-after-restore-lock-and-leave" lockAndLeaveEnabled "$baseline_lock_and_leave"

target_auto_lock_time="$(alternate_auto_lock_time "$baseline_auto_lock_time")"
run_write_phase "18-set-auto-lock-time" set-auto-lock-time "$lock_id" "$target_auto_lock_time" >/dev/null
readback_setting_until "19-status-after-set-auto-lock-time" autoLockTime "$target_auto_lock_time"
verify_setting_field "20-status-after-set-auto-lock-time-confirm" autoLockTime "$target_auto_lock_time"
run_write_phase "21-restore-auto-lock-time" set-auto-lock-time "$lock_id" "$baseline_auto_lock_time" >/dev/null
readback_setting_until "22-status-after-restore-auto-lock-time" autoLockTime "$baseline_auto_lock_time"

temp_suffix="$(date +%s)-$$"
temp_access_name="schlage-ts-live-$temp_suffix"
updated_access_name="schlage-ts-live-updated-$temp_suffix"
current_second="$(date +%S)"
current_minute="$(date +%M)"
temp_access_code="$(printf '9%03d' "$(( ($$ + 10#$current_second) % 1000 ))")"
updated_access_code="$(printf '8%03d' "$(( ($$ + 10#$current_minute) % 1000 ))")"
if [[ "$temp_access_code" == "$updated_access_code" ]]; then
  updated_access_code="7001"
fi

access_before_path="$(run_json_phase "23-access-codes-before" access-codes "$lock_id")"
helper assert-no-access-code "$access_before_path" "$temp_access_name"
helper assert-no-access-code "$access_before_path" "$updated_access_name"
run_json_phase "24-access-codes-before-confirm" access-codes "$lock_id" >/dev/null
add_access_path="$(run_write_phase "25-add-access-code" add-access-code "$lock_id" --name "$temp_access_name" --code "$temp_access_code")"
temp_access_id="$(helper write-access-code-id "$add_access_path")"
access_after_add_path="$(run_json_phase "26-access-codes-after-add" access-codes "$lock_id")"
helper assert-access-code "$access_after_add_path" "$temp_access_name" "$temp_access_code" false
access_id_from_list="$(helper access-code-id-by-name "$access_after_add_path" "$temp_access_name")"
if [[ "$access_id_from_list" != "$temp_access_id" ]]; then
  temp_access_id="$access_id_from_list"
fi
run_json_phase "27-access-codes-after-add-confirm" access-codes "$lock_id" >/dev/null
run_write_phase "28-update-access-code" update-access-code "$lock_id" "$temp_access_id" --name "$updated_access_name" --code "$updated_access_code" --disabled >/dev/null
access_after_update_path="$(run_json_phase "29-access-codes-after-update" access-codes "$lock_id")"
helper assert-access-code "$access_after_update_path" "$updated_access_name" "$updated_access_code" true
run_json_phase "30-access-codes-after-update-confirm" access-codes "$lock_id" >/dev/null
run_write_phase "31-delete-access-code" delete-access-code "$lock_id" "$temp_access_id" >/dev/null
access_after_delete_path="$(run_json_phase "32-access-codes-after-delete" access-codes "$lock_id")"
helper assert-no-access-code "$access_after_delete_path" "$temp_access_name"
helper assert-no-access-code "$access_after_delete_path" "$updated_access_name"
run_json_phase "33-access-codes-after-delete-confirm" access-codes "$lock_id" >/dev/null

final_lock_phase="34-final-lock"
final_lock_status_phase="35-status-after-final-lock"
if [[ "${SCHLAGE_S07_VERIFY_SCHEDULES:-0}" == "1" ]]; then
  scheduled_access_name="schlage-ts-live-scheduled-$temp_suffix"
  current_hour="$(date +%H)"
  scheduled_access_code="$(printf '7%03d' "$(( ($$ + 10#$current_hour) % 1000 ))")"
  scheduled_starts_at="$(date -u -d '+10 minutes' '+%Y-%m-%dT%H:%M:%S.000Z')"
  scheduled_ends_at="$(date -u -d '+40 minutes' '+%Y-%m-%dT%H:%M:%S.000Z')"
  scheduled_add_path="$(run_write_phase "34-add-scheduled-access-code" add-access-code "$lock_id" --name "$scheduled_access_name" --code "$scheduled_access_code" --temporary-starts-at "$scheduled_starts_at" --temporary-ends-at "$scheduled_ends_at")"
  temp_access_id="$(helper write-access-code-id "$scheduled_add_path")"
  echo "S07 temporary schedule write accepted."
  run_write_phase "35-delete-scheduled-access-code" delete-access-code "$lock_id" "$temp_access_id" >/dev/null
  temp_access_id=""
  scheduled_after_delete_path="$(run_json_phase "36-access-codes-after-scheduled-delete" access-codes "$lock_id")"
  helper assert-no-access-code "$scheduled_after_delete_path" "$scheduled_access_name"
  run_json_phase "37-access-codes-after-scheduled-delete-confirm" access-codes "$lock_id" >/dev/null
  final_lock_phase="38-final-lock"
  final_lock_status_phase="39-status-after-final-lock"
fi

final_lock_path="$(run_json_phase "$final_lock_phase" lock "$lock_id")"
if helper assert-state "$final_lock_path" locked >/dev/null 2>&1; then
  echo "S07: final lock command reported observedState=locked."
fi
readback_until "$final_lock_status_phase" locked

if grep -R . "$diag_dir" >/dev/null; then
  while IFS= read -r -d '' file; do
    helper leak-scan "$file"
  done < <(find "$diag_dir" -type f -print0)
fi

echo "S07 live verification passed. Redacted diagnostics: $diag_dir"
