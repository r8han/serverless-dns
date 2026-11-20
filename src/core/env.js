/**
 * Instantiation of EnvManager class makes env values available through a
 * common interface.
 *
 * EnvManager.get() or EnvManager.set() allow manipulation of `env` object.
 * Environment variables of runtime (node, bun, worker)
 *
 * @license
 * Copyright (c) 2021 RethinkDNS and its authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/**
 * @typedef {"number" | "string" | "boolean" | "csv"} EnvTyp
 * @typedef {string | number | boolean} EnvDefTyp
 * @typedef {EnvDefTyp|Set<string>} EnvConcreteTyp
 * @typedef {{type: EnvTyp, default: EnvDefTyp}} EnvDefs
 */

/**
 * @type {Map<String, EnvDefs>} defaults
 */
const defaults = new Map(
  Object.entries({
    // the env stage (production or development) workers is running in
    // development is always "local" (a laptop /a server, for example)
    WORKER_ENV: {
      type: "string",
      default: "development",
    },
    // the env stage nodejs is running in
    NODE_ENV: {
      type: "string",
      default: "development",
    },
    // the env stage bun is running in
    BUN_ENV: {
      type: "string",
      default: "development",
    },
    // the cloud-platform code is deployed on (cloudflare, standalone)
    CLOUD_PLATFORM: {
      type: "string",
      // also ref: EnvManager.mostLikelyCloudPlatform()
      default: "local",
    },
    // download blocklist files to disk, if any, and quit
    BLOCKLIST_DOWNLOAD_ONLY: {
      type: "boolean",
      default: false,
    },
    // path to tls (private) key
    TLS_KEY_PATH: {
      type: "string",
      default: "test/data/tls/dns.rethinkdns.localhost.key",
    },
    // path to tls (public) cert chain
    TLS_CRT_PATH: {
      type: "string",
      default: "test/data/tls/dns.rethinkdns.localhost.crt",
    },
    // indicate if tls termination is offloaded to an external process; for
    // example, a gateway that terminates tls in front of this listener.
    TLS_OFFLOAD: {
      type: "boolean",
      default: false,
    },
    // if true, do not validate the SNI field in TLS handshake
    // effectively allowing clients to "fake" SNI.
    // if true, DoT may not contain SNI information,
    // which disables blocklist checks.
    TLS_ALLOW_ANY_SNI: {
      type: "boolean",
      default: false,
    },
    TLS_PSK: {
      // Static TLS optimization only, not enrollment or DNS access control.
      type: "string",
      // DO NOT check-in the value; it should ideally be set via a vault or keystore
      default: "", // 32-64 bytes as hex
    },
    // global log level (debug, info, warn, error)
    LOG_LEVEL: {
      type: "string",
      default: "info",
    },
    // set via secret, cloudflare account-id
    CF_ACCOUNT_ID: {
      type: "string",
      default: "",
    },
    // url to blocklist files: trie (td), rank-dir (rd), metadata: (filetag)
    CF_BLOCKLIST_URL: {
      type: "string",
      default: "https://cfstore.rethinkdns.com/blocklists/",
    },
    // primary doh upstream
    CF_DNS_RESOLVER_URL: {
      type: "string",
      default: "https://cloudflare-dns.com/dns-query",
    },
    // secondary doh upstream
    CF_DNS_RESOLVER_URL_2: {
      type: "string",
      default: "https://dns.google/dns-query",
    },
    // Optional HTTPS resolver that understands RethinkDNS blockstamps.
    // Without an explicit fallback, cold Workers wait for local filtering.
    MAX_DNS_RESOLVER_URL: {
      type: "string",
      default: "",
    },
    // max doh request processing timeout some requests may have to wait
    // for blocklists to download before being responded to.
    WORKER_TIMEOUT: {
      type: "number",
      default: "10000", // 10s
    },
    // max blocklist files download timeout
    CF_BLOCKLIST_DOWNLOAD_TIMEOUT: {
      type: "number",
      default: "7500", // 7.5s
    },
    // disable downloading blocklists altogether
    DISABLE_BLOCKLISTS: {
      type: "boolean",
      default: false,
    },
    // treat all blocklists as wildcards, this means
    // if abc.xyz.com is in any blocklist, then
    // <*>.abc.xyz.com will also get blocked
    BLOCK_SUBDOMAINS: {
      type: "boolean",
      default: true,
    },
    // run in profiler mode
    PROFILE_DNS_RESOLVES: {
      type: "boolean",
      default: false,
    },
    DNS_ACCESS_MODE: { type: "string", default: null },
    ACCESS_KEYS: { type: "string", default: null },
    NODE_DOH_ONLY: { type: "boolean", default: true },
    DOT_HAS_PROXY_PROTO: { type: "boolean", default: false },
    DNS_CACHE_ENABLED: { type: "boolean", default: false },
    DNS_HISTORY_LIFECYCLE_READY: { type: "boolean", default: false },
    LOGPUSH_HISTORY: { type: "boolean", default: false },
    LOGPUSH_ANALYTICS: { type: "boolean", default: false },
    LOGPUSH_ANSWER_COUNTRY: { type: "boolean", default: false },
    GEOIP_URL: { type: "string", default: "" },
    GEOIP_V4_PIN: { type: "string", default: "" },
    GEOIP_V6_PIN: { type: "string", default: "" },
    OBSERVABILITY_READS: { type: "boolean", default: false },
    ANALYTICS_DATASET: { type: "string", default: "SDNS_EVENTS_V2" },
    LOGPUSH_ENABLED: {
      type: "boolean",
      default: false,
    },
    LOGPUSH_SRC: {
      type: "csv",
      // Exact source hostnames; none configured means no collection.
      default: "",
    },
    // Return 'Gateway IPs' for ALL eligible reqs (ref util.js:isGatewayRequest)
    GW_IP4: {
      type: "string",
      default: "",
    },
    GW_IP6: {
      type: "string",
      default: "",
    },
  })
);

/**
 * cast string x to type typ
 * @param {EnvDefTyp} x
 * @param {EnvTyp} typ
 * @returns {EnvConcreteTyp} casted value
 * @throws {Error}
 */
function caststr(x, typ) {
  if (typeof x === typ) return x;

  if (typ === "boolean") {
    return x === "true";
  } else if (typ === "number") {
    return Number(x);
  } else if (typ === "string") {
    return (x && x + "") || "";
  } else if (typ === "csv" && x instanceof Set) {
    return x;
  } else if (typ === "csv" && typeof x === "string") {
    if (!x) return new Set();
    return new Set(x.split(",").map((x) => x.trim()));
  } else {
    throw new Error(`unsupported type: ${typ}`);
  }
}

/**
 * @returns {string} runtime name
 */
function _determineRuntime() {
  if (typeof Bun !== "undefined") {
    return "bun"; // bun.sh/guides/util/detect-bun
  }

  if (globalThis.wenv) return "worker";

  if (typeof process !== "undefined") {
    // process also exists in Workers (miniflare), where wenv is defined
    if (process.env) return "node";
  }

  return null;
}

export default class EnvManager {
  /**
   * Initializes the env manager.
   */
  constructor() {
    /** @type {string} */
    this.runtime = _determineRuntime();
    /** @type {Map<string, EnvConcreteTyp>} */
    this.envMap = new Map();
    this.load();
  }

  /**
   * Loads env variables from runtime env. and is made globally available
   * through `env` namespace. Existing env variables will be overwritten.
   */
  load() {
    this.envMap = this.defaultEnv();
    // verbose log:
    // console.debug("env defaults", this.envMap);
  }

  determineEnvStage() {
    if (this.runtime === "node") return this.get("NODE_ENV");
    if (this.runtime === "bun") return this.get("BUN_ENV");
    if (this.runtime === "worker") return this.get("WORKER_ENV");
    return null;
  }

  // most-likely but not definitive platform this code is running on
  mostLikelyCloudPlatform() {
    const isDev = this.determineEnvStage() === "development";
    const hasWorkersUa =
      typeof navigator !== "undefined" &&
      navigator.userAgent === "Cloudflare-Workers";

    if (hasWorkersUa) return "cloudflare";
    // if dev, then whatever is running is likely local
    if (isDev) return "local";
    if (["node", "bun"].includes(this.runtime)) return "local";
    // if prod, then worker is likely running on cloudflare
    if (this.runtime === "worker") return "cloudflare";

    return null;
  }

  // most relevant host id for this env
  mostRelevantHostId(cloud) {
    if (cloud === "local") return "localhost";
    return "";
  }

  /**
   * Makes default env values.
   * @return {Map} Runtime environment defaults.
   */
  defaultEnv() {
    const env = new Map();

    for (const [key, mappedKey] of defaults) {
      if (typeof mappedKey !== "object") continue;

      const type = mappedKey.type;
      const val = mappedKey.default;

      if (!type || val == null) {
        // console.debug(key, "incomplete env val:", mappedKey);
        continue;
      }

      env.set(key, caststr(val, type));
    }

    const cloud = this.mostLikelyCloudPlatform();
    env.set("CLOUD_PLATFORM", cloud);
    env.set("HOST_IDENTIFIER", this.mostRelevantHostId(cloud)); // may be empty

    return env;
  }

  // one of nodejs, bun, or cloudflare workers
  r() {
    return this.runtime;
  }

  /**
   * Gets the value of an env variable.
   * @param {String} k - env variable name
   * @return {EnvConcreteTyp} - env variable value
   */
  get(k) {
    let v = null;
    if (this.runtime === "node") {
      v = process.env[k];
    } else if (this.runtime === "bun") {
      // bun.sh/guides/runtime/read-env
      v = Bun.env[k];
    } else if (this.runtime === "worker") {
      v = globalThis.wenv[k];
    }

    if (v == null) {
      v = this.envMap.get(k);
    }

    const m = defaults.get(k);
    // set default v when env var for k is not set
    if (m && v == null) v = m.default;

    // type-cast v as approp if k is among the defaults
    if (m && v != null) v = caststr(v, m.type);

    return v;
  }

  /**
   * @param {String} k - env name
   * @param {EnvDefTyp} v - env value
   * @param {EnvTyp} typ - env type, one of boolean, string, number, or csv
   */
  set(k, v, typ) {
    typ = typ || "string";
    this.envMap.set(k, caststr(v, typ));
  }
}
