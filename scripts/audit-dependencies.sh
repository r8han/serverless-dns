#!/bin/sh
# npm audit needs a resolution. CI audits the lock made by its own install;
# a lock-free checkout uses a disposable resolution without modifying source.
set -eu
registry=https://registry.npmjs.org
if [ ! -f package-lock.json ]; then
  work=$(mktemp -d)
  trap 'rm -rf "$work"' EXIT
  cp package.json "$work/"
  cd "$work"
  npm install --package-lock --package-lock-only --ignore-scripts --no-audit --no-fund --registry="$registry"
fi
npm audit --package-lock-only --include=dev --include=optional --audit-level=low --registry="$registry"
npm audit --package-lock-only --omit=dev --omit=optional --audit-level=low --registry="$registry"
