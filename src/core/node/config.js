/*
 * Copyright (c) 2021 RethinkDNS and its authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/**
 * Configuration file for node runtime
 * TODO: Remove all side-effects and use a constructor?
 * This module has side effects, sequentially setting up the environment.
 */
export let listener;
export let identity;
import { listenerPolicy, validateIdentity } from "./listener-policy.js";
import { readFileSync } from "node:fs";
import process from "node:process";
import * as dnst from "../../core/node/dns-transport.js";
import * as system from "../../system.js";
import EnvManager from "../env.js";
import Log, { log, setLogger } from "../log.js";
import { services, stopAfter } from "../svc.js";
import * as blocklists from "./blocklists.js";
import * as util from "./util.js";

// some of the cjs node globals aren't available in esm
// nodejs.org/docs/latest/api/globals.html
// github.com/webpack/webpack/issues/14072
// import path from "path";
// import { fileURLToPath } from "url";
// globalThis.__filename = fileURLToPath(import.meta.url);
// globalThis.__dirname = path.dirname(__filename);

((main) => {
  system.when("prepare").then(prep);
  system.when("steady").then(up);
})();

async function prep() {
  // if this file execs... assume we're on nodejs.
  const isProd =
    process.env.NODE_ENV === "production" ||
    process.env.BUN_ENV === "production";
  const profiling = process.env.PROFILE_DNS_RESOLVES === "true";
  globalThis.envManager = new EnvManager();
  const logger = new Log({
    level: envManager.get("LOG_LEVEL"),
    levelize: isProd || profiling,
    withTimestamps: true,
  });
  setLogger(logger);

  // ---- log and envManager available only after this line ---- \\

  if (!envManager.get("BLOCKLIST_DOWNLOAD_ONLY")) {
    listener = listenerPolicy({
      production: isProd,
      platform: process.env.CLOUD_PLATFORM,
      mode: process.env.TLS_MODE,
      tlsBind: process.env.TLS_BIND,
      privateBind: process.env.OFFLOAD_BIND,
    });
    if (
      (envManager.get("TLS_OFFLOAD") && listener.mode !== "offload") ||
      (isProd && envManager.get("TLS_ALLOW_ANY_SNI"))
    ) {
      throw new Error("unsafe or conflicting TLS configuration");
    }
    if (listener.mode === "terminate") {
      const certKey =
        process.env.TLS_CERTKEY ??
        (process.env.TLS_CN && process.env[`TLS_${process.env.TLS_CN}`]);
      const [key, cert] =
        certKey != null
          ? util.getCertKeyFromEnv(certKey)
          : [
              readFileSync(envManager.get("TLS_KEY_PATH")),
              readFileSync(envManager.get("TLS_CRT_PATH")),
            ];
      validateIdentity(key, cert, isProd);
      identity = { key, cert };
    }
  }

  // TODO: move dns* related settings to env
  const plainOldDnsIp = "1.1.1.2";
  const dns53 = envManager.get("NODE_DOH_ONLY")
    ? null
    : dnst.makeTransport(plainOldDnsIp);

  // signal ready
  system.pub("ready", [dns53]);
}

async function up() {
  if (!services.ready) {
    log.e("services not yet ready yet and there is a sig-up!?");
    return;
  }

  const bw = services.blocklistWrapper;
  if (bw != null && !bw.disabled()) {
    await blocklists.setup(bw);
  } else {
    log.w("Config", "blocklists unavailable / disabled");
  }

  process.on("SIGINT", (sig) => stopAfter());

  process.on("warning", (e) => log.w(e.stack));

  // signal all system are-a go
  system.pub("go");
}
