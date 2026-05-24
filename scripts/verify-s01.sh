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

required_outputs=(
  "dist/index.js"
  "dist/index.d.ts"
  "dist/cli.js"
  "dist/cli.d.ts"
)

for output in "${required_outputs[@]}"; do
  if [[ ! -f "$output" ]]; then
    echo "Missing build output: $output" >&2
    exit 1
  fi
done

echo "S01 verification passed."
