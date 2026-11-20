#!/bin/sh
set -eu
compiler=tools/fastly/node_modules/.bin/js-compute-runtime
[ -x "$compiler" ] || { echo 'Install the optional compiler with npm run setup:fastly' >&2; exit 2; }
# Allow a separately verified platform-specific compiler on developer hosts.
if [ -z "${WEVAL_BIN:-}" ]; then
  [ "$(uname -sm)" = 'Linux x86_64' ] || { echo 'set WEVAL_BIN to a verified weval 0.5.1 executable' >&2; exit 2; }
  tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
  sh scripts/ci-tool.sh weval "$tmp"
  WEVAL_BIN=$tmp/weval
fi
"$compiler" --weval-bin "$WEVAL_BIN" dist/fastly.js dist/fastly.wasm
