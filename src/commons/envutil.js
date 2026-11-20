/*
 * Copyright (c) 2021 RethinkDNS and its authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

// musn't import /depend on anything.

export function isProd() {
  if (!envManager) return false;

  return envManager.determineEnvStage() === "production";
}

export function onCloudflare() {
  if (!envManager) return false;

  // wrangler imitates Workers runtime environment to a tee, and so
  // checks like the one proposed here archive.is/Izftu do not work
  return envManager.get("CLOUD_PLATFORM") === "cloudflare";
}

export function onLocal() {
  if (!envManager) return false;

  return !onCloudflare();
}

export function hasHttpCache() {
  return isWorkers();
}

export function isBun() {
  if (!envManager) return false;

  return envManager.r() === "bun";
}

export function isWorkers() {
  if (!envManager) return false;

  return envManager.r() === "worker";
}

export function isNode() {
  if (!envManager) return false;

  return envManager.r() === "node";
}

/**
 * in milliseconds
 */
export function workersTimeout(missing = 0) {
  if (!envManager) return missing;
  return envManager.get("WORKER_TIMEOUT") || missing;
}

export function downloadTimeout(missing = 0) {
  if (!envManager) return missing;
  return envManager.get("CF_BLOCKLIST_DOWNLOAD_TIMEOUT") || missing;
}

export function bgDownloadBlocklistWrapper() {
  return onCloudflare() && Boolean(maxDohUrl());
}

export function blocklistUrl() {
  if (!envManager) return null;
  return envManager.get("CF_BLOCKLIST_URL");
}

export function primaryDohResolver() {
  if (!envManager) return null;

  return envManager.get("CF_DNS_RESOLVER_URL");
}

export function secondaryDohResolver() {
  if (!envManager) return null;

  return envManager.get("CF_DNS_RESOLVER_URL_2");
}

export function maxDohUrl() {
  const value = globalThis.envManager?.get("MAX_DNS_RESOLVER_URL");
  if (!value) return null;
  try {
    const u = new URL(value);
    if (
      u.protocol !== "https:" ||
      u.username ||
      u.password ||
      /[?#]/.test(u.href)
    ) {
      return null;
    }
    if (!u.pathname.endsWith("/")) u.pathname += "/";
    return u.href;
  } catch {
    return null; // invalid fallback: wait for local filtering instead
  }
}

export function dohResolvers() {
  if (!envManager) return null;

  if (isWorkers()) {
    // upstream to two resolvers on workers; since egress is free,
    // faster among the 2 should help lower tail latencies at zero-cost
    return [primaryDohResolver(), secondaryDohResolver()];
  }

  return [primaryDohResolver()];
}

export function tlsCrtPath() {
  if (!envManager) return "";
  return envManager.get("TLS_CRT_PATH") || "";
}

export function tlsKeyPath() {
  if (!envManager) return "";
  return envManager.get("TLS_KEY_PATH") || "";
}

export function allowDomainFronting() {
  if (!envManager) return false;
  return envManager.get("TLS_ALLOW_ANY_SNI");
}

export function kdfSvcSecretHex() {
  if (!envManager) return null;
  return envManager.get("KDF_SVC") || null;
}

export function isCleartext() {
  if (!envManager) return false;

  // when a trusted gateway terminates tls, conns from it to this
  // listener are in cleartext
  return envManager.get("TLS_MODE") === "offload";
}

// sysctl get net.ipv4.tcp_syn_backlog
export function tcpBacklog() {
  if (!envManager) return 600;

  return envManager.get("TCP_BACKLOG") || 600;
}

export function maxconns() {
  if (!envManager) return 1000;

  return envManager.get("MAXCONNS") || 1000;
}

export function minconns() {
  if (!envManager) return 50;

  return envManager.get("MINCONNS") || 50;
}

export function ioTimeoutMs(missing = 0) {
  if (!envManager) return missing;

  return envManager.get("WORKER_TIMEOUT") || missing;
}

export function shutdownTimeoutMs() {
  if (!envManager) return 60 * 1000;

  return envManager.get("SHUTDOWN_TIMEOUT_MS") || 60 * 1000;
}

export function blocklistDownloadOnly() {
  if (!envManager) return false;

  // run the server just to download the blocklist files and do nothing else
  return envManager.get("BLOCKLIST_DOWNLOAD_ONLY");
}

// Ports which the services are exposed on.
export function dohBackendPort() {
  return 8080;
}

export function dohCleartextBackendPort() {
  return isCleartext() ? 8055 : /* random*/ 0;
}

export function dotBackendPort() {
  return 10000;
}

export function httpCheckPort() {
  return 8888;
}

export function profileDnsResolves() {
  if (!envManager) return false;

  return envManager.get("PROFILE_DNS_RESOLVES") || false;
}

export function hostId() {
  if (!envManager) return "";

  return envManager.get("HOST_IDENTIFIER") || "";
}

export function requiresHeaderAuth() {
  return globalThis.envManager?.get("ACCESS_KEYS") != null;
}

export function forceDoh() {
  if (!envManager) return true;

  // on other runtimes, continue using doh
  if (!isNode()) return true;

  return envManager.get("NODE_DOH_ONLY");
}

export function disableDnsCache() {
  // disable when profiling dns resolutions
  return profileDnsResolves();
}

export function disableBlocklists() {
  if (!envManager) return false;

  // server is up just to download blocklists, so skip this flag
  if (blocklistDownloadOnly()) return false;

  return envManager.get("DISABLE_BLOCKLISTS") || false;
}

export function blockSubdomains() {
  return globalThis.envManager?.get("BLOCK_SUBDOMAINS") ?? true;
}

export function gwip4() {
  if (!envManager) return "";
  return envManager.get("GW_IP4") || "";
}

export function gwip6() {
  if (!envManager) return "";
  return envManager.get("GW_IP6") || "";
}
