#!/bin/sh
# Audit the same reviewed resolution used by test and release builds.
set -eu
registry=https://registry.npmjs.org
npm audit --package-lock-only --include=dev --include=optional --audit-level=low --registry="$registry"
npm audit --package-lock-only --omit=dev --omit=optional --audit-level=low --registry="$registry"
