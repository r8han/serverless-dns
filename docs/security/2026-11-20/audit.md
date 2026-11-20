# Security audit: pre-merge review of `arena/8bffd245-serverless-dns`

**20 November 2026 · Recommendation: safe to merge; not yet safe to deploy publicly without the operator gates in the [rollout guide](../rollout.md).**

This review covers the whole working tree at `275ebfe` ("Keep gateway answer addresses out of
request diagnostics") on branch `arena/8bffd245-serverless-dns`. There are no branch-only commits
above the described base commit, so the branch content *is* the change under review. It re-tests
the remediations described in the [18 November audit](../2026-11-18/audit.md) and looks for new
issues in the code that replaced the old paths.

Nothing here is evidence about a live deployment. No provider account, customer data, production
cache, production blocklist, or deployed endpoint was accessed. Findings describe code and
preconditions, not a compromise.

## Findings

| ID | Severity | Area | Summary |
|---|---|---|---|
| MEM-01 | **Medium · fixed** | Answer cache | Cache capacity is counted in entries, not bytes: 30 000 × 4 KiB ≈ 145 MB of retained memory (measured). Remotely fillable → OOM on Workers and on small standalone machines. |
| DEP-01 | Info | Supply chain | `@serverless-dns/trie` declares a **mutable git tag** for `lfu-cache`; the pin is only enforced by the root npm `overrides`. All release paths happen to use npm, but the invariant is tool-specific. |
| SRV-01 | Low · fixed | Standalone offload listener | The cleartext offload front (`httpx-server`) selected HTTP/2 vs HTTP/1.1 by scanning the first TCP chunk for the literal `HTTP/2.0`. Fails closed, but is fragile for a documented production mode. |
| ASY-01 | Low · fixed | Workers cold-start fallback | A promise from `BlocklistWrapper.init()` is passed to `waitUntil` with no local rejection handler. |
| OPS-01 | Info | Rate limits | No in-process per-client quota; concurrency is capped per process only. Documented as an edge responsibility — keep it as a release gate. |
| OPS-02 | Info | Profiling | `PROFILE_DNS_RESOLVES` accumulates timing samples without trimming (process is stopped after 60 s, so bounded in practice). |
| OPS-03 | Info | Interop | DoH `GET ?dns=` rejects base64url **padding** (`=`); only the unpadded form is accepted. |
| RES-01 | Info | Synthetic answers | The HTTPS/SVCB sinkhole emits its second answer (A `0.0.0.0`) with TTL 0 and a defaulted class. Harmless, inconsistent with the first record. |
| DOC-01 | Info | Documentation | The reads section of the rollout guide lists `f=type\|result` but not `f=country`, which the same document later describes. |
| CFG-01 | Info | Deploy footgun | The top-level (default) `wrangler.toml` environment is deployable with `WORKER_ENV="development"`, `workers_dev=true` and no `ACCESS_KEYS`, i.e. a public resolver, if someone runs a plain `wrangler deploy`. |

No Critical or High issue was found. Every High/Critical finding from the 18 November audit is
fixed in this tree, including the two release blockers (client packets can no longer enter the
answer cache; the untrusted DNS decode path is gone).

MEM-01, SRV-01 and ASY-01 were fixed on the branch after this review; see
[Fixes applied](#fixes-applied) for the change and the measurements. The remaining entries are
informational and need no code change before merge.

## MEM-01 · Medium — the answer cache is bounded by entry count only · **fixed**

`src/commons/dnsutil.js:23,28-30` fixes the cache at 30 000 entries and `src/core/svc.js:72`
creates one `DnsCache` with that number. `src/plugins/dns-op/cache.js:12-16` builds two LFU caches
of that capacity. Each answer entry stores the full upstream wire response (`≤ 4096` bytes,
`src/plugins/dns-op/resolver.js:326`) plus its stamps (`cache.js:26-40`). The LFU implementation
evicts on **count**, never on bytes (`node_modules/@serverless-dns/lfu-cache/strat/o1.js`,
`capacity` is an entry count).

**Measured (this audit):** filling `answers` with 30 000 entries of exactly 4 KiB each raised
process RSS from 42 MB to 187 MB (**+145 MB**) in a Node 22 process.

**Impact.** Any admitted client can force this. It needs ~30 000 cacheable questions within one
isolate/process lifetime, each with a large, positive-TTL answer (DNSSEC-signed TXT, big RRsets).
That is ordinary resolver traffic, not a protocol abuse:

- **Workers:** the isolate memory limit is 128 MB, so the attacker hits the limit *before* the
  entry cap is reached — the cap provides no protection and the isolate is killed, making every
  user on it see 5xx until replacement. Repeats are cheap (fresh, never-cached names).
- **Node/Bun/Deno standalone (Fly):** the process is long-lived, so 145 MB is a *permanent*
  floor on top of the trie and TLS state. On 256–512 MB machines this materially reduces the
  headroom `adjustMaxConns` uses to shed load (`src/server-node.js:1139-1215`).

The cached content is validated (`cache-util.js:20-33`), so this is availability, not integrity.

**Fixed in this branch.** `src/commons/dnsutil.js` adds `cacheBytes()` (16 MiB) beside
`cacheSize()`, and `src/plugins/dns-op/answer-cache.js` replaces the LFU store for answers with an
LRU that is bounded by entries *and* by charged bytes, charges each entry its wire bytes plus the
key and its stamps, and refuses an entry that cannot fit the whole budget. `DnsCache` keeps the
LFU for policy stamps, which are per-question and small. `test/unit/answer-cache.test.js` asserts
both ceilings, LRU order and single-charge replacement.

## DEP-01 · Info — one mutable reference in an otherwise pinned graph

`node_modules/@serverless-dns/trie/package.json` depends on
`@serverless-dns/lfu-cache: github:serverless-dns/lfu-cache#v3.5.2` — a **tag**, not a commit.
The invariant holds only because the root `package.json` overrides it:

```json
"overrides": { "@serverless-dns/lfu-cache": "$@serverless-dns/lfu-cache" }
```

`npm ls --omit=dev` confirms the override is applied ("lfu-cache@3.4.1 overridden"), the Deno
import map pins the same commit by URL, and all three container images install with **npm**
before building, so the shipped artifacts are pinned today. The risk is that any future
bun/pnpm/yarn-resolved release install (or a tool that ignores `overrides`) would fetch a moving
tag *and* run the dependency's `prepare: husky install` lifecycle script.

**Fix.** Keep this in the review checklist, or vendor a `trie` build whose dependency spec is a
commit URL, so the pin does not depend on a tool-specific override.

## SRV-01 · Low — protocol sniffing in front of the offloaded listener · **fixed**

When `TLS_MODE=offload`, non-Bun Node uses `httpx-server@2.0.0` (`src/server-node.js:355-375`).
That 102-line module reads the first TCP chunk and dispatches the socket to an HTTP/2, TLS, or
HTTP/1.1 server depending on `buffer[0] === 22` / `buffer.includes('HTTP/2.0')`.

Consequences:

- A valid HTTP/1.1 request whose *first segment* contains the literal `HTTP/2.0` (a header value,
  a long URL, a body sent early) is handed to the h2c parser and fails. This **fails closed**
  (connection error), but it is request-loss on a documented production path and it means the
  behaviour depends on how the fronting proxy segments writes.
- It is an unaudited third-party HTTP front on the private backend interface. The module is
  otherwise small and the rest of the release tooling is digest-verified and scanned; this one
  dependency is not.

**Fixed in this branch.** `httpx-server` is gone. `src/core/node/cleartext-http.js` serves the
offload port from a `net.Server` that selects the parser on the RFC 9113 §3.4 connection preface
at offset 0, waits while the bytes received so far are still a prefix of it (so a preface split
across writes is not misread as HTTP/1.1), refuses a TLS handshake on a listener that has no
certificate, and re-injects the peeked bytes in order. `test/unit/cleartext-http.test.js` covers
HTTP/1.1, HTTP/1.1 carrying `HTTP/2.0` in a header and path, h2c, a split preface, a TLS
ClientHello and event forwarding. `test/listener-smoke.mjs node` still passes, which exercises the
real offload port over HTTP/1.1. The remaining dependency risk is removed with the package.

## ASY-01 · Low — unhandled rejection on the Workers cold-start fallback · **fixed**

`src/plugins/dns-op/resolver.js:206`:

```js
dispatcher(this.bw.init(rxid));      // MAX_DNS_RESOLVER_URL path
```

`init()` re-throws the download failure. The request path attaches a handler, but this call site
hands the raw promise to `waitUntil`. On Cloudflare the runtime reports the rejection as an
uncaught error; a host that stores the promise without settling it would raise an
`unhandledRejection`. The branch is Workers-only (`envutil.bgDownloadBlocklistWrapper()` requires
`onCloudflare()`), so it is a diagnostics/noise issue rather than an outage.

**Fixed in this branch.** `dispatcher(this.bw.init(rxid).catch(() => {}))` at
`src/plugins/dns-op/resolver.js:206`.

## Verified remediations from the 18 November audit

| Old ID | Status | Evidence in this tree |
|---|---|---|
| DNS-01 (client packet → answer cache) | **Fixed** | `cache-util.js:20-33` makes `UpstreamAnswer` (ID + question + opcode + non-truncated + NOERROR/NXDOMAIN) the only answer type; `cache.js:26` refuses anything else; blocked requests call `putPolicy` (`resolver.js:199`), which stores stamps only. Re-tested. |
| DNS-02 (unbounded decoder; uninitialized encoder bytes) | **Fixed** | Ingress/egress decode is `dns-wire.js:15-181`: size precheck, `(flags & ~0x0130) === 0`, single IN question, forward-only compression, `budget = 4096*16`, strict `pos === b.length`. `dnsutil.js:151-160` allocates zeroed memory and returns exactly `encode.bytes`. Fuzzed 200 000 mutated queries: no hang, worst case 1.5 ms, only `Error` throw types; a 338-record 4 KiB response parses in 2.6 ms. |
| IO-01 (limit after buffering) | **Fixed** | `bounded.js:5-39` counts delivered bytes, stops pulling on overflow, honours the deadline; `doh.js:33-46` caps URL length and concurrent admission before any read; `plugin.js:335-356` bounds POST and GET before decode; `server-node.js:999-1032` re-checks on the Node entry point. |
| AUTH-01 (HMAC 0 bytes; fail-open verifiers) | **Fixed** | `crypto.js:202-211` awaits and enforces 32 bytes; `auth-token.js:18-44` validates the whole configured set (host, 64-hex digest, partition, scope, duplicates) and throws on any malformed entry, so an empty `ACCESS_KEYS` is a 503, not public mode; `svc.js:58-67` runs a known-answer `selfTest()` at startup and leaves `services.ready` false on failure. Reproduced: RFC 4231 vector passes, correct/absent/wrong-host bearers behave as intended, `ACCESS_KEYS=""` / missing digest / duplicate digest all rejected. Workerd smoke confirms the 503 path. |
| AUTH-02 (bearers in logs/URLs/SNI) | **Fixed** | No auth material is logged (`auth-token.js` has no logger; `plugin-response.js:67-75` returns fixed labels, never the exception). Bearer generation is offline (`scripts/access-key.mjs`, mode 0600, `flag: "wx"`); `/genaccesskey` and `/gentlspsk` return 410 (`cc.js:125-133`); DoT listeners are not created when `ACCESS_KEYS` is set (`server-node.js:407-425`, `server-deno.ts:142`). Diagnostics test in `security.test.js:495`. |
| OBS-01 (no owner authorization for history) | **Fixed** | `log-pusher.js:134-150` requires `OBSERVABILITY_READS`, a `read` principal and a valid partition, and the exact `/logs` / `/analytics` path; history is written under `v2/<tenant>/<hour>/` from the authenticated partition only, and every returned record is re-checked against the tenant, hour, size and shape (`:154-186`). |
| OBS-02 (untrusted input → SQL) | **Fixed** | `log-pusher.js:40-72`: dataset and tenant validated by regex, only `blob1..blob3` are selectable, values are bound by strict integer parsing, no caller identifiers reach SQL. Probed 10 hostile variants (`t=1;DROP TABLE`, `l=10 OR 1=1`, `f=blob1`, injected tenant/dataset, duplicate/unknown params, out-of-range integers): all rejected before any fetch; the three valid shapes emit fixed templates. |
| OBS-03 (telemetry not gated) | **Fixed** | `log-pusher.js:84-100` needs `LOGPUSH_ENABLED`, a `write` principal and an exact `LOGPUSH_SRC` hostname; it emits `{type, result[, country]}` only — no query, IP, answer, URL or console sink. |
| TLS-01 (missing certs → plaintext) | **Fixed** | `listener-policy.js:9-42` requires an explicit platform and mode in production and refuses non-literal/ non-private binds; `node/config.js:58-80` rejects `TLS_OFFLOAD` mode conflicts and `TLS_ALLOW_ANY_SNI` in production; `validateIdentity()` checks key/cert match, validity window, and refuses the repository fixture by SPKI pin — the pin matches the checked-in test key exactly (verified: `9c13c8ed…f1ff`). `listener-smoke.mjs node` passes: production rejection, authenticated offload, pipelined/fragmented DoT. |
| DNS-03 (cache key/TTL/DNSSEC integrity) | **Fixed** | `cache-util.js:36-62` keys on revision, subdomain mode, view, name, type, class, opcode, flags (RD/CD/AD), EDNS payload size and DO; `lifetime()` returns 0 for zero TTL, truncated, unexpected rcodes, or any EDNS option (`:84-99`); `replay()` ages wire TTLs in place, never trims RRsets and never clears AD (`:102-121`). Tested: negative expiry, CD/view isolation, ECS stripping preserves DO/payload/other options byte-for-byte. |
| IMG-01 (unsupported Node, root user, wide build context) | **Fixed** | All three Dockerfiles pin base images by digest, run as `node` / `65532:65532`, copy an allowlist from the build stage, and `.dockerignore` is an allowlist; `check-image.sh` fails on a root user, a writable `/app`, a symlink, `node_modules`, dotfiles or key material, and proves offline read-only start-up. |
| Supply chain (unpinned actions/tools, scan after push) | **Fixed** | Actions are pinned to commit SHAs with `persist-credentials: false`; `scripts/ci-tool.sh` verifies the SHA-256 of every downloaded tool before extraction; images are built, scanned (`grype --fail-on high`) and attested **before** promotion by digest; the Worker release uploads a prebuilt bundle with `build`/`minify` stripped and `--no-bundle`, and the Deno release cross-checks Deno's resolution against the npm source archives. `npm audit` on a fresh resolution: **0 advisories** for both the full graph and `--omit=dev --omit=optional` (the 49/13 findings in the old baseline no longer apply). |

## Fixes applied

| Finding | Change | Files | Verified by |
|---|---|---|---|
| MEM-01 | Answers are cached in an LRU bounded by entries **and** bytes (16 MiB); each entry is charged its wire bytes, key and stamps; an entry that cannot fit the whole budget is refused. Policy stamps stay in the LFU. | `src/commons/dnsutil.js` (`cacheBytes()`), `src/plugins/dns-op/answer-cache.js`, `src/plugins/dns-op/cache.js` | `test/unit/answer-cache.test.js` (8 cases: byte ceiling, entry ceiling, LRU order, replacement, refusal, mixed sizes); measurement below |
| SRV-01 | The offload port is served by a local `net.Server` that selects HTTP/1.1 vs h2c on the RFC 9113 preface at offset 0, tolerates a split preface, refuses TLS, and re-injects the peeked bytes. `httpx-server` is removed from `dependencies`. | `src/core/node/cleartext-http.js`, `src/server-node.js`, `package.json` | `test/unit/cleartext-http.test.js` (6 cases), `test/listener-smoke.mjs node` |
| ASY-01 | The Workers cold-start install promise is caught before it reaches `waitUntil`. | `src/plugins/dns-op/resolver.js` | `npm test`, `test/worker-smoke.mjs` |

Measured after the change (same probe as MEM-01, production limits 30000 entries / 16 MiB):

| Workload | Before | After |
|---|---|---|
| 30 000 × 4 KiB answers (worst case) | 30 000 entries retained, +145 MB RSS | 3 794 entries retained, 16.0 MiB charged, +69 MB RSS |
| 30 000 × 100 B answers (typical) | 30 000 entries, unmeasured | 30 000 entries, 12.2 MiB charged |

The charged-byte ceiling is exact accounting, not a GC-dependent measurement, so the bound holds
regardless of allocator behaviour.

## What was executed here

| Check | Result |
|---|---|
| `npm install --no-package-lock --ignore-scripts`, `npm test`, `npm run lint` | 50/50 unit tests pass (36 original + 14 new); lint clean (Node 22.22.3). |
| `npm run build:fly` + `node test/listener-smoke.mjs node` (fixture metadata) | Pass: production startup rejection, authenticated offload, pipelined/fragmented DoT framing. |
| `npm run build` + `node test/worker-smoke.mjs` under workerd | Pass: allowed/denied clients get their own policy, one upstream lookup, `ACCESS_KEYS=""` → 503 `private, no-store`, telemetry written only for the write principal with the answer-country blob. |
| Ingress parser fuzz (200 k mutated queries) | No hang, no non-`Error` throws, ≤1.5 ms worst case; QR/opcode/count/pointer/loop/trailing-byte cases all rejected. |
| Worst-case response parse (338 records, 4 079 B) | 2.6 ms, accepted. |
| Auth primitives | RFC 4231 vector passes via `selfTest()`; verifier round-trips; malformed `ACCESS_KEYS` variants all rejected at construction. |
| SQL construction probe (`reportQuery`) | 10 hostile variants rejected before any fetch; 3 valid shapes emit fixed SQL templates. |
| `npm audit` (fresh lock, both graphs) | 0 advisories. |
| Secrets sweep of tracked files | Only the documented localhost fixture key under `test/data/tls/`, which is excluded from images, refused in production, and whose SPKI pin matches. |
| Cache memory before the fix | +145 MB RSS for 30 000 × 4 KiB answers (MEM-01); 30000 entries retained. |
| Cache memory after the fix | 3794 entries / 16.0 MiB charged for 30 000 × 4 KiB answers (+69 MB RSS); still 30000 entries at 12.2 MiB for typical 100-byte answers. |
| Offload listener after the fix | `test/unit/cleartext-http.test.js` 6/6 (HTTP/1.1, `HTTP/2.0` in a header, h2c, split preface, TLS hello, forwarded events); `test/listener-smoke.mjs node` passes. |

**Not performed:** cloud/provider execution, container builds or OS scans (no Docker here), Fastly
Wasm execution, production-sized blocklists, cache purges, credential rotation, and independent
attestation of the pinned action SHAs.

## Deploy triggers

Confirmed in the tree: **no workflow deploys on a push.** `cf.yml`, `deno-deploy.yml`,
`ghcr.yml`, `profiler.yml` and `fly.yml` are `workflow_dispatch` only; `pr.yml` runs on
`pull_request` and only builds fixtures; `scorecard.yml` runs on a push to `main` and does static
analysis. `fly.yml` additionally requires a caller-supplied GHCR digest, `refs/heads/main` on a
protected ref, the `production-fly` environment, and a verified attestation from `ghcr.yml`, and
`fly.toml` builds from a Dockerfile only under that dispatch.

Two provider-side switches are not in the repository and must be checked in their dashboards
before a merge during a release hold: Cloudflare Workers Builds (branch control and deploy
command; `wrangler.toml` still carries a `[build]` command) and Deno Deploy's Git integration.
See the release gates in the [rollout guide](../rollout.md).

## Before merging

The code is ready. These remain operator actions, not code changes:

1. Merge separate from deploy: confirm the provider has no push-to-production build trigger
   (Cloudflare Workers Builds, Deno Deploy Git integration, Fly auto-deploy) before this lands.
2. Keep history/analytics **reads** and telemetry collection off until a real bucket, dataset and
   least-privilege read token exist, and purge the legacy `answers`/`policy` namespaces on rollout
   (the new `verified-v2` / `answers-v2` keys cannot read old entries, but old instances must be
   drained).
3. Size the answer-cache budget for the smallest instance you run (`cacheBytes()`), and confirm
   peak RSS on production-sized blocklists.
4. Exercise the offload port **through the real frontend** on the canary; the listener now accepts
   HTTP/1.1 and h2c and refuses TLS.
5. Enforce ingress quotas and body/time limits at the edge; in-process caps are per isolate or
   per process, not a global quota.
6. Check `wrangler.toml` environment/route settings so a plain `wrangler deploy` cannot publish a
   public resolver (CFG-01).
