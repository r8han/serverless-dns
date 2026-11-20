#!/bin/sh
# Verify the actual final image before its archive is scanned and promoted.
set -eu
runtime=$1
image=$2
user=$(docker image inspect --format '{{.Config.User}}' "$image")
case "$user" in ''|0|0:*|root|root:*) echo 'image runs as root' >&2; exit 1;; esac
name="sdns-check-$runtime"
trap 'docker rm -f "$name" >/dev/null 2>&1 || :' EXIT
# With no network and a read-only root, listening implies verified assets
# were usable without downloading, repairing or populating a writable cache.
docker run -d --name "$name" --network none --read-only --tmpfs /tmp:rw,nosuid,nodev \
  --cap-drop ALL --security-opt no-new-privileges -e CLOUD_PLATFORM=standalone \
  -e DISABLE_BLOCKLISTS=false -e TLS_MODE=offload -e OFFLOAD_BIND=127.0.0.1 "$image"
docker exec "$name" sh -ec '
  test "$(id -u)" != 0
  test ! -w /app
  test ! -w /app/blocklists__
  unexpected=$(find /app \( -type l -o -name node_modules -o -name .git -o -name ".env*" -o -name ".dev.vars*" -o -name .npmrc -o -name "*.key" -o -name "*.pem" \) -print -quit)
  test -z "$unexpected"
'
case "$runtime" in node|bun) set -- "$runtime" -e;; deno) set -- deno eval;; *) exit 2;; esac
# dntouint requires an installed filter and performs a trie lookup; it does
# not forward DNS or need to know which names the production policy blocks.
docker exec "$name" "$@" '(async () => {
  for (let i = 0; i < 60; i++) {
    try {
      const r = await fetch("http://127.0.0.1:8055/dntouint?dn=image-check.invalid", { signal: AbortSignal.timeout(2000) });
      if (r.status === 200 && r.headers.get("cache-control") === "private, no-store" && (await r.json()).domainName === "image-check.invalid") return;
    } catch {}
    await new Promise(ok => setTimeout(ok,1000));
  }
  throw new Error("read-only image did not become ready");
})()'
