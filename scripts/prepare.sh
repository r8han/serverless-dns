#!/bin/sh
set -eu
if command -v node >/dev/null; then exec node scripts/metadata.mjs "$@"; fi
if command -v bun >/dev/null; then exec bun scripts/metadata.mjs "$@"; fi
exec deno run --allow-env --allow-net --allow-read --allow-write scripts/metadata.mjs "$@"
