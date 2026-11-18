#### It's a bird, it's a plane, it's... a self-hosted, pi-hole esque, DNS resolver

_serverless-dns_ is a Pi-Hole esque [content-blocking](https://github.com/serverless-dns/blocklists), serverless, stub DNS-over-HTTPS (DoH) and DNS-over-TLS (DoT) resolver. Primary targets are [Cloudflare Workers](https://workers.dev) and Node/Bun (including [Fly.io](https://fly.io/)). [Deno Deploy](https://deno.com/deploy) and [Fastly Compute](https://www.fastly.com/products/edge-compute) are optional. Free tiers of all these services should be enough to cover 10 to 20 devices worth of DNS traffic per month.

### The RethinkDNS resolver

RethinkDNS runs `serverless-dns` in production at these endpoints:

| Cloud platform     | Server locations | Protocol    | Domain                    | Usage                                   |
|--------------------|------------------|-------------|---------------------------|-----------------------------------------|
| ⛅ Cloudflare Workers | 280+ ([ping](https://check-host.net/check-ping?host=https://sky.rethinkdns.com))           | DoH         | `sky.rethinkdns.com`    | [configure](https://rethinkdns.com/configure?p=doh)  |
| 🦕 Deno Deploy        | 30+ ([ping](https://check-host.net/check-ping?host=https://deno.dev))                      | DoH         | _private beta_          |                                         |
| ⏱️ Fastly Compute@Edge   | 80+ ([ping](https://check-host.net/check-ping?host=https://serverless-dns.edgecompute.app))| DoH         | _private beta_          |                                      |
| 🪂 Fly.io             | 30+ ([ping](https://check-host.net/check-ping?host=https://max.rethinkdns.com))           | DoH and DoT | `max.rethinkdns.com`      | [configure](https://rethinkdns.com/configure?p=dot)  |

Server-side processing takes from 0 milliseconds (ms) to 2ms (median), and end-to-end latency (varies across regions and networks) is between 10ms to 30ms (median).

[<img src="https://raw.githubusercontent.com/fossunited/Branding/main/asset/FOSS%20United%20Logo/Extra/Extra%20Logo%20white%20on%20black.jpg"
     alt="FOSS United"
     height="40">](https://fossunited.org/grants)&emsp;
[<img src="https://floss.fund/static/badge.svg"
    alt="FLOSS/fund badge"
    height="40">](https://floss.fund)

The *Rethink DNS* resolver on Fly.io is sponsored by [FLOSS/fund](https://floss.fund) and FOSS United.

### Self-host

Start with the [security rollout guide](docs/security/rollout.md). Production builds deliberately require a separately trusted blocklist manifest. This checkout has **no approved production manifest**: do not deploy its test fixture or bypass integrity checks. The [original audit](docs/security/2026-11-18/audit.md) records the pre-remediation findings.

The Cloudflare Worker environments use `workers.dev` by default. Add custom routes only for zones you control. Standalone runtimes require an explicit production listener mode. Use a deployment environment with reviewed secrets, TLS settings, quotas and logging policy, not a one-click build of an unreviewed ref.

To setup blocklists, visit `https://<my-domain>.tld/configure` from your browser (it should load something similar to [RethinkDNS' _configure_ page](https://rethinkdns.com/configure)).

For help or assistance, feel free to [open an issue](https://github.com/celzero/docs/issues) or [submit a patch](https://github.com/celzero/docs).

---

### Development
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/serverless-dns/serverless-dns/badge)](https://securityscorecards.dev/viewer/?uri=github.com/serverless-dns/serverless-dns)&emsp;
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/serverless-dns/serverless-dns)

#### Setup

Use a supported Node LTS (CI: Node 22.22.3 and 24.22.3). From the repository root:

```sh
npm install --no-package-lock --ignore-scripts
npm test
npm run lint
```

No npm, Bun or Deno lockfile is checked in. Direct dependencies are pinned, but separate installs can resolve different transitive versions. `npm run audit:dependencies` checks the build’s npm resolution, or resolves in a temporary directory if no local lock exists.

The tests use synthetic lists and mocked or loopback upstreams. They do not require a cloud account or production files. For an **offline fixture** bundle and Worker smoke in a disposable checkout:

```sh
fixture=$(mktemp -d)
node test/prepare-fixture.mjs "$fixture"
export BLOCKLIST_VERSION=2024/1706100000000 BLOCKLIST_MANIFEST="$fixture/manifest.json"
cp "$fixture/blocklist-metadata.json" src/
npm run build
node test/worker-smoke.mjs
npm run build:fly && node test/listener-smoke.mjs node
```

Discard the disposable checkout and fixture after testing. Never set those two fixture variables on a release runner. `./run node|bun|deno|workers|fastly|fly` prepares trusted metadata before building or starting the respective service (Wrangler does so via its build command). Local Node/Bun/Deno termination defaults to loopback with the public test identity, **for development only**. Use `./run profile` for an offline CPU profile. See the [runtime test matrix](docs/security/rollout.md#release-gates).

#### Optional deployments

Pull requests run the unit, Node, Bun and Workers checks. For Fastly or Deno, use **Actions → PR checks → Run workflow** and select `fastly` or `deno`. These checks use fixtures and do not deploy. To build Fastly locally, first run `npm run setup:fastly`; the compiler is not installed by the root package. For Deno, use Deno 2.5.6; `node scripts/stage-deno.mjs release` needs prepared metadata, the root npm dependencies and access to the commit-pinned module sources. It stages a local-only release graph.

The container release builds Node and Bun unless **include_deno** is selected. Managed Deno release is a separate manual workflow. Optional means not deployed by default; a selected target still needs its verification and approval gates.

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
| Fastly Compute (optional) | `src/server-fastly.js` | `fastly.toml`, `env` Config Store, `FASTLY_ENV=production` |
| Deno / Deno Deploy (optional) | `src/server-deno.ts` | `deno.json`, `import_map.json`, `DENO_ENV_DOMAIN=production` |
| Node / Bun | `src/server-node.js` | `NODE_ENV=production` / `BUN_ENV=production`, `fly.toml` or `fly.tls.toml` |

For local termination use `TLS_MODE=terminate` and mount `TLS_KEY_PATH` / `TLS_CRT_PATH`. In production specify `CLOUD_PLATFORM=standalone` or `fly`. To offload TLS at a trusted gateway use `TLS_MODE=offload` with a private backend; **no** cleartext DoT substitute. Managed Deno requires `CLOUD_PLATFORM=deno-deploy`, `TLS_MODE=managed`, and a provider deployment ID. Stamps on Deno standalone DoT require a fixed `DOT_POLICY`. PSK is a separately provisioned Node TLS optimization, not DNS access control. Telemetry export and history reads are **off by default**. See the [migration, pinning and operator checklist](docs/security/rollout.md) before changing any of these settings.
