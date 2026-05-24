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
  "dist/auth.js"
  "dist/auth.d.ts"
  "dist/errors.js"
  "dist/errors.d.ts"
  "dist/cli.js"
  "dist/cli.d.ts"
)

for output in "${required_outputs[@]}"; do
  if [[ ! -f "$output" ]]; then
    echo "Missing build output: $output" >&2
    exit 1
  fi
done

grep -q "PublicSchlageAuthSnapshot" dist/auth.d.ts || {
  echo "Missing auth snapshot declaration in dist/auth.d.ts" >&2
  exit 1
}

grep -q "SchlageErrorCode" dist/errors.d.ts || {
  echo "Missing Schlage error code declaration in dist/errors.d.ts" >&2
  exit 1
}

grep -q "SchlageClientAuthTransport" dist/index.d.ts || {
  echo "Missing client auth transport declaration in dist/index.d.ts" >&2
  exit 1
}

echo "S02 verification passed."
