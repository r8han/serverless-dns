# Security audit — 20 November 2026

**Revision:** `d7a8bd988e10726202c5062f5f3167da9729b38f`

This review covers the DNS parser, request handling, access keys, filtering, upstream traffic, caches, TLS and proxy listeners, telemetry, build inputs, and CI. I reviewed the current source and ran local checks. I did not test live services or inspect production settings. No critical issue was confirmed. The findings below include issues confirmed by reading the code and risks that depend on deployment settings.

## Findings

| Priority | Finding | Where |
|---|---|---|
| High on exposed Node listeners | Requests compete for a shared limit before access checks | [Node HTTP handler](src/server-node.js#L998), [DoH handler](src/core/doh.js#L16), [plugin order](src/core/plugin.js#L52) |
| High if large blocklists are approved | Valid blocklists can exceed the Worker memory budget | [Artifact limits](src/commons/blocklist-integrity.js#L6), [parallel download](src/plugins/rethinkdns/main.js#L83), [body reader](src/commons/bounded.js#L5) |
| Medium | Worker DNS cache shares data across users and keeps query names in cache keys | [Cache key](src/plugins/cache-util.js#L37), [cache storage](src/plugins/dns-op/cache.js#L29), [Worker cache API](src/plugins/dns-op/cache-api.js#L10) |
| Medium when enabled | Optional PROXY v2 listener does not handle binary headers correctly | [Listener setup](src/server-node.js#L419), [proxy handler](src/server-node.js#L830) |
| Medium when enabled | DNS history has no retention limit enforced by the app | [History writes](src/plugins/observability/log-pusher.js#L122), [history reads](src/plugins/observability/log-pusher.js#L153) |
| Medium | Dependency versions can change between reviewed and released builds | [Ignored lockfiles](.gitignore), [PR checks](.github/workflows/pr.yml), [Node image](node.Dockerfile), [Bun image](bun.Dockerfile) |

### 1. Shared limits do not protect authenticated clients

The Node HTTP server takes one of 256 slots before it reads the body. It holds that slot until the request finishes or times out. Bearer checks happen later. A private resolver can therefore lose service to unauthenticated traffic if the origin is reachable and the edge does not limit it. The shared DoH handler also uses one limit for all callers; a valid caller can consume capacity that other users need. These limits cap total work, but do not give clients a fair share.

**Fix:** Limit traffic and slow bodies at the edge. Block direct access to an offload origin. Add a separate pre-auth limit and per-client or per-key quotas. Check credentials before reading bodies on private DoH routes. Keep the total limit as a final guard.

### 2. Blocklist size checks do not match Worker memory

The manifest accepts up to 192 MiB for each binary. The reader allocates a buffer of the pinned size before verification, and both files download in parallel. The two buffers alone can exceed the Worker’s 128 MiB limit, before adding the trie, caches and active requests. A trusted but oversized manifest can make cold Workers fail repeatedly. This is not a way for ordinary DNS clients to choose the size; the operator must approve the manifest.

**Fix:** Enforce a combined, Worker-specific size budget before any download or allocation. Set it using peak memory from a build with realistic blocklists and traffic. Reject oversized manifests in CI as well. Reading the files one at a time does not solve the problem if both must remain in memory.

### 3. The shared cache crosses privacy boundaries

The cache key includes the query name, upstream settings, and filter revision, but not the requesting account or hostname. Workers also store cache entries through `caches.default`. Client responses use `no-store`; that does not stop the separate internal cache. Where users share a cache, timing or remaining TTL can reveal that an answer was reused. That does not identify who made the earlier query. I did not verify that any cache data is publicly readable.

**Fix:** Let private deployments turn off the shared cache or split it by an explicit privacy group. Use an opaque keyed hash for provider cache keys if stored names are a concern. Hashing does not prevent signals between users who still share the same cache partition.

### 4. PROXY v2 handling can drop valid DoT connections

The handler assumes the first TCP read contains the full header, converts it to ASCII, looks for a line ending, and passes a string to a parser that expects bytes. PROXY v2 is a binary protocol with a length field, and TCP does not preserve read boundaries. The front listener also uses the normal TLS bind address and opens a backend connection before parsing the header. Parsed source details are not used for access control. I found no bypass of DoH bearer checks here; the feature is off by default and DoT is disabled when header auth is required.

**Fix:** Keep the option off until fixed. If needed, bind it separately to a restricted interface and allow only trusted proxies. Read a bounded binary header with a deadline, then open the backend connection. Add tests for split headers and extra data in the same read.

### 5. History read limits are not deletion limits

When enabled, DNS history writes one object per eligible request. The read path only lists up to 32 items from the current hour, but old objects are not removed by this code. Without a bucket lifecycle rule, records and storage costs can grow over time. Records contain time, tenant, query type and result, not raw domain names or IP addresses.

**Fix:** Keep history off unless the bucket has a tested expiration rule and a clear retention policy. Apply write quotas or sampling, and monitor storage growth.

### 6. Builds do not use a checked-in dependency resolution

Direct packages are pinned to exact versions or commit references. However, lockfiles are ignored and release jobs resolve dependencies at build time. Passing the advisory scan for one resolution does not prove a later build uses the same files. The npm audit also does not replace a review of the GitHub-hosted dependencies or the base images.

**Fix:** Check in reviewed lockfiles, use frozen installs in CI and image builds, and scan the exact release dependency tree and image. Update pins through reviewed changes.

## Controls that held up in review

- DNS requests have size and parse limits. Answers must match the query before admission to the cache. Client subnet data is stripped before sending queries upstream.
- Private DoH uses bearer headers. The checked Node listener setup disables DoT when header auth is required and rejects a known development TLS identity in production.
- The DoH resolver uses configured destinations, does not copy client bearer headers upstream, and does not follow redirects. Review whether you need two destinations: queries can reach both configured resolvers, not just the one that answers first.
- Blocklists use pinned hashes. Normal cold misses wait for verified filtering unless operators opt into a fallback resolver that must enforce the same policy.
- Telemetry reads require a read grant. The partition comes from the grant, and analytics query fields and limits are checked. Collection is optional.
- CI pins actions by commit and gives publishing permissions to separate jobs. Both runtime images use non-root users.

## Checks and limits

- **Passed:** 50 unit tests, lint, Node and Worker fixture builds, and the Node listener smoke test.
- **Dependency advisory scan:** 0 reported in both npm scans for the resolved trees. This is not a full supply-chain review.
- **Not verified:** Worker runtime smoke could not start because the local `workerd` platform binary was missing. Bun, production edge limits, real blocklist peak memory, cache visibility and bucket expiry were not tested.

**First steps:** Protect exposed private listeners, check peak Worker memory before approving new blocklists, and decide whether private deployments should use the shared Worker cache. No application code was changed.
