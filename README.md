#### It's a bird, it's a plane, it's... a self-hosted, pi-hole esque, DNS resolver

_serverless-dns_ is a Pi-Hole esque [content-blocking](https://github.com/serverless-dns/blocklists), serverless, stub DNS-over-HTTPS (DoH) and DNS-over-TLS (DoT) resolver. Primary targets are [Cloudflare Workers](https://workers.dev) and self-hosted Node/Bun. The Cloudflare Workers free tier should be enough to cover 10 to 20 devices worth of DNS traffic per month.

### The RethinkDNS resolver

RethinkDNS runs `serverless-dns` in production at these endpoints:

| Cloud platform     | Server locations | Protocol    | Domain                    | Usage                                   |
|--------------------|------------------|-------------|---------------------------|-----------------------------------------|
| ⛅ Cloudflare Workers | 280+ ([ping](https://check-host.net/check-ping?host=https://sky.rethinkdns.com))           | DoH         | `sky.rethinkdns.com`    | [configure](https://rethinkdns.com/configure?p=doh)  |

Server-side processing takes from 0 milliseconds (ms) to 2ms (median), and end-to-end latency (varies across regions and networks) is between 10ms to 30ms (median).

[<img src="https://raw.githubusercontent.com/fossunited/Branding/main/asset/FOSS%20United%20Logo/Extra/Extra%20Logo%20white%20on%20black.jpg"
     alt="FOSS United"
     height="40">](https://fossunited.org/grants)&emsp;
[<img src="https://floss.fund/static/badge.svg"
    alt="FLOSS/fund badge"
    height="40">](https://floss.fund)

### Self-host

Start with the [security rollout guide](docs/security/rollout.md). Production builds deliberately require a separately trusted blocklist manifest. This checkout has **no approved production manifest**: do not deploy its test fixture or bypass integrity checks. The [original audit](docs/security/2026-11-18/audit.md) records the pre-remediation findings.

The production Cloudflare Worker environments disable `workers.dev` by default. Add custom routes only for zones you control. Standalone runtimes require an explicit production listener mode. Use a deployment environment with reviewed secrets, TLS settings, quotas and logging policy, not a one-click build of an unreviewed ref.

To setup blocklists, visit `https://<my-domain>.tld/configure` from your browser (it should load something similar to [RethinkDNS' _configure_ page](https://rethinkdns.com/configure)).

For help or assistance, feel free to [open an issue](https://github.com/celzero/docs/issues) or [submit a patch](https://github.com/celzero/docs).

---

### Development
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/serverless-dns/serverless-dns/badge)](https://securityscorecards.dev/viewer/?uri=github.com/serverless-dns/serverless-dns)&emsp;
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/serverless-dns/serverless-dns)

#### Setup

Use Node 26 LTS (the CI and development pin is in `.node-version`). From the repository root:

```sh
npm install --no-package-lock --ignore-scripts
npm test
npm run lint
```

No npm or Bun lockfile is checked in. Direct dependencies are pinned, but separate installs can resolve different transitive versions. `npm run audit:dependencies` checks the build’s npm resolution, or resolves in a temporary directory if no local lock exists.

The tests use synthetic lists and mocked or loopback upstreams. They do not require a cloud account or production files. For an **offline fixture** bundle and Worker smoke in a disposable checkout:

```sh
fixture=$(mktemp -d)
node test/prepare-fixture.mjs "$fixture"
export BLOCKLIST_VERSION=2024/1706100000000 BLOCKLIST_MANIFEST="$fixture/manifest.json"
cp "$fixture/blocklist-metadata.json" src/
npm run build
node test/worker-smoke.mjs
npm run build:node && node test/listener-smoke.mjs node
```

Discard the disposable checkout and fixture after testing. Never set those two fixture variables on a release runner. `./run node|bun|workers` prepares trusted metadata before building or starting the respective service (Wrangler does so via its build command). Local Node/Bun termination defaults to loopback with the public test identity, **for development only**. Use `./run profile` for an offline CPU profile. See the [runtime test matrix](docs/security/rollout.md#release-gates).

#### Checks

Pull requests run the unit, Node, Bun and Workers fixture checks; these do not deploy. The container release builds Node and Bun. Every selected target still needs its verification and approval gates.

#### Filtering and forwarding

- A request carries a v1 blockstamp (`1:<base64url>` for DoH; `1-<base32>` in the first DoT label). It is a **policy selection, not a credential**. An explicit malformed stamp is an error. Lists govern all supported standard IN lookups. `BLOCK_SUBDOMAINS=true` (default) includes children; `false` matches exact domains. These are client-selected lists, not a mandatory administrator egress policy.
- The shared resolver accepts a single standard IN question (17–4096 bytes), using ASCII labels supported by the filter. It checks question names, answer owners, and CNAME/DNAME/HTTPS/SVCB targets; it does not interpret every opaque record as a domain name. Only a matching complete upstream answer can populate the answer cache. Clients sharing it are evaluated separately against the same verified list generation. Zero-TTL and expired data are not reused; signed RRsets are not trimmed. EDNS Client Subnet is stripped before forwarding.
- By default, allowed queries use HTTPS via `CF_DNS_RESOLVER_URL`. Workers can race it against `CF_DNS_RESOLVER_URL_2` (Google by default); set the secondary to an empty string for a single destination. Ordinary DNS questions can reach **both** configured upstreams. Node can explicitly opt into plain UDP/TCP with `NODE_DOH_ONLY=false`; use it only on a trusted network.
- Cold Workers use revision-scoped cache entries or wait for verified local filtering. On a miss and timeout they fail without sending a question to the ordinary upstream. **Opt-in:** `MAX_DNS_RESOLVER_URL` may name a trusted HTTPS resolver that enforces the same policy. It receives the question and stamp while the trie loads; its answers are never shared. Redirects are not followed. If filtering is disabled, requests selecting a list fail closed.

#### Private DoH

Generate a new high-entropy bearer **offline**. Use a new path outside this checkout, in a directory only you can read:

```sh
node scripts/access-key.mjs dns.example.org /secure/private/new-dns-bearer
```

The program writes the bearer with mode `0600` and prints only a `host|verifier` entry. Set `ACCESS_KEYS` in your secret store to the complete entry (CSV for several). Send the bearer in `Authorization: Bearer …` over HTTPS. Do **not** place it in a URL, SNI, DNS name, issue, log or online generator. An **unset** `ACCESS_KEYS` permits public DNS; an empty/malformed configured set does not. A DNS-only principal cannot read history. DoT cannot carry this header and is disabled when keys are configured.

#### Runtime and release configuration

| Target | Entrypoint | Configuration |
|---|---|---|
| Cloudflare Worker | `src/server-workers.js` | `wrangler.toml`; production `WORKER_ENV=production` |
| Node / Bun | `src/server-node.js` | `NODE_ENV=production` / `BUN_ENV=production` |

For local termination use `TLS_MODE=terminate` and mount `TLS_KEY_PATH` / `TLS_CRT_PATH`. In production specify `CLOUD_PLATFORM=standalone`. To offload TLS at a trusted gateway use `TLS_MODE=offload` with a loopback backend that forwards cleartext DoH (Node accepts HTTP/1.1 or h2c on that port); **no** cleartext DoT substitute. PSK is a separately provisioned Node TLS optimization, not DNS access control. Telemetry export and history reads are **off by default**. Workers can optionally [report the country of the DNS answer IP](docs/security/rollout.md#answer-country-breakdown-off-by-default), without exporting the IP or geolocating the requester. See the [migration, pinning and operator checklist](docs/security/rollout.md) before changing any of these settings.

### Production security settings

- Use Node 26.13.1 or a later Node 26 LTS patch, or Bun 1.4.5+ on the 1.x line. Both container builds use a verified Node 26 binary. The Node runtime image runs that binary; the Bun runtime image runs Bun. Use `npm ci` to install from the reviewed lockfile.
- Set `DNS_ACCESS_MODE=private` and supply valid `ACCESS_KEYS` for private DNS, or explicitly set `DNS_ACCESS_MODE=public` and leave keys unset. Set the mode in your reviewed Worker environment as well. Only direct TLS is supported for DoT; remove `DOT_HAS_PROXY_PROTO` from old deployments.
- Run an offload gateway in the same trusted network namespace as the loopback listener. Apply connection, slow-body and request-rate limits at the edge. Public Workers and public offload still need edge quotas; do not trust client-supplied forwarding headers. In-app quotas are local to a process or isolate, not global billing limits.
- The shared DNS cache is off by default. `DNS_CACHE_ENABLED=true` enables it only for public DNS. It can retain query names and expose shared cache hits. Purge old Worker cache entries if required by your privacy policy.
- Keep DNS history off unless the storage bucket has an expiration rule. Test deletion and remove any old records outside your retention period before setting `DNS_HISTORY_LIFECYCLE_READY=true`. The app cannot check the bucket rule itself.
- Supply an independently approved `config/blocklist-manifest.json` before releasing. Do not use fixture pins. Worker builds reject combined trie binaries over 48 MiB. Test peak memory with real assets and expected traffic before deployment.
