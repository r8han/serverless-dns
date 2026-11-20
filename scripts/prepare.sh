#!/bin/sh
set -eu
if command -v node >/dev/null; then exec node scripts/metadata.mjs "$@"; fi
if command -v bun >/dev/null; then exec bun scripts/metadata.mjs "$@"; fi
echo 'node or bun is required to prepare blocklists' >&2
exit 2
