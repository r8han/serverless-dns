/*
 * Copyright (c) 2022 RethinkDNS and its authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

// env config at top, so if .env file variables are used, it is available to
// other modules.
import "./core/deno/config.ts";
import {
  listenerPolicy,
  validateIdentity,
} from "./core/node/listener-policy.js";
import { readFrame } from "./commons/dns-frame.js";
import { unstamp } from "./plugins/rdns-util.js";
import { handleRequest } from "./core/doh.js";
import { stopAfter, uptime } from "./core/svc.js";
import * as system from "./system.js";
import * as util from "./commons/util.js";
import * as bufutil from "./commons/bufutil.js";
import * as dnsutil from "./commons/dnsutil.js";
import * as envutil from "./commons/envutil.js";
import { loggerWithTags } from "./core/log.js";

let log: any = null;
let listeners: Array<any> = [];

((main) => {
  system.when("go").then(systemUp).catch(() => {
    console.error("listener startup failed");
    Deno.exit(1);
  });
  system.sub("stop", systemDown);
  // ask prepare phase to commence
  system.pub("prepare");
})();

function systemDown() {
  // system-down even may arrive even before the process has had the chance
  // to start, in which case globals like env and log may not be available
  console.info("rcv stop signal; uptime", uptime() / 1000, "secs");

  const srvs = listeners;
  listeners = [];

  srvs.forEach((s) => {
    if (!s) return;
    console.info("stopping...");
    // Deno.lisenters are closed, while Deno.Servers are aborted
    if (typeof s.close === "function") s.close();
    else if (typeof s.abort === "function") s.abort();
    else console.warn("unknown server type", s);
  });

  util.timeout(/* 2s*/ 2 * 1000, () => {
    console.info("game over");
    // exit success aka 0; ref: community.fly.io/t/4547/6
    Deno.exit(0);
  });
}

function systemUp() {
  log = loggerWithTags("Deno");
  if (!log) throw new Error("logger unavailable on system up");

  const downloadmode = envutil.blocklistDownloadOnly() as boolean;
  const profilermode = envutil.profileDnsResolves() as boolean;
  if (downloadmode) {
    log.i("in download mode, not running the dns resolver");
    return;
  } else if (profilermode) {
    const durationms = 60 * 1000;
    log.w("in profiler mode, run for", durationms, "and exit");
    stopAfter(durationms);
  }

  const abortctl = new AbortController();
  const production = Deno.env.get("DENO_ENV_DOMAIN") === "production";
  const policy = listenerPolicy({
    production,
    platform: Deno.env.get("CLOUD_PLATFORM"),
    mode: Deno.env.get("TLS_MODE"),
    tlsBind: Deno.env.get("TLS_BIND"),
    privateBind: Deno.env.get("OFFLOAD_BIND") || Deno.env.get("FLY_PRIVATE_IP"),
  });
  if (
    (envManager?.get("TLS_OFFLOAD") && policy.mode !== "offload") ||
    (production && envManager?.get("TLS_ALLOW_ANY_SNI"))
  ) throw new Error("unsafe or conflicting TLS configuration");
  const dotls = policy.mode === "terminate";
  const dohConnOpts = {
    hostname: policy.host,
    port: policy.mode === "offload"
      ? envutil.dohCleartextBackendPort()
      : envutil.dohBackendPort(),
  };
  const dotConnOpts = { hostname: policy.host, port: envutil.dotBackendPort() };
  const sigOpts = { signal: abortctl.signal };
  const tlsOpts = dotls
    ? {
      cert: Deno.readTextFileSync(envutil.tlsCrtPath() as string),
      key: Deno.readTextFileSync(envutil.tlsKeyPath() as string),
    }
    : { cert: "", key: "" };
  if (dotls) validateIdentity(tlsOpts.key, tlsOpts.cert, production);
  // Deno's connection API doesn't supply policy-bearing SNI. No silent
  // fallback: DoT requires an explicitly fixed public listener policy.
  const fixed = Deno.env.get("DOT_POLICY");
  if (fixed && fixed !== "none") unstamp(fixed);
  startDoh();
  startDotIfPossible().catch(() => {
    if (!abortctl.signal.aborted) {
      log.e("DoT listener failed");
      Deno.exit(1);
    }
  });

  // docs.deno.com/runtime/fundamentals/http_server
  // docs.deno.com/api/deno/~/Deno.serve
  function startDoh() {
    if (terminateTls()) {
      Deno.serve(
        {
          ...dohConnOpts,
          ...tlsOpts,
          ...sigOpts,
        },
        serveDoh,
      );
    } else {
      Deno.serve({ ...dohConnOpts, ...sigOpts }, serveDoh);
    }

    up("DoH", abortctl, dohConnOpts);
  }

  async function startDotIfPossible() {
    if (!dotls || !fixed || envutil.requiresHeaderAuth()) return;

    // doc.deno.land/deno/stable/~/Deno.listenTls
    // doc.deno.land/deno/stable/~/Deno.listen
    const dot = Deno.listenTls({ ...dotConnOpts, ...tlsOpts });

    up("DoT (fixed policy)", dot, dotConnOpts);
    let active = 0;
    for await (const conn of dot) {
      if (active >= 64) {
        conn.close();
        continue;
      }
      active++;
      serveTcp(conn, fixed).catch(() => {}).finally(() => {
        active--;
      });
    }
  }

  function up(p: string, s: any, opts: any) {
    log.i("up", p, opts, "tls?", terminateTls());
    // 's' may be a Deno.Listener or std:http/Server
    listeners.push(s);
  }

  function terminateTls() {
    return dotls;
  }
}

async function serveDoh(req: Request) {
  try {
    // doc.deno.land/deno/stable/~/Deno.RequestEvent
    // deno.land/manual/runtime/http_server_apis#http-requests-and-responses
    return await handleRequest(util.mkFetchEvent(req));
  } catch (e) {
    // Client may close conn abruptly before a response could be sent
    log.w("DoH request failed");
    return new Response(null, {
      status: 503,
      headers: { "cache-control": "private, no-store" },
    });
  }
}

async function serveTcp(conn: Deno.Conn, policy: string) {
  const close = () => {
    try {
      conn.close();
    } catch { /* already closed */ }
  };
  const ctl = new AbortController();
  try {
    for (;;) {
      // Absolute per-frame deadline includes reads, resolve and partial writes.
      const timer = setTimeout(() => {
        ctl.abort();
        close();
      }, dnsutil.requestTimeout());
      try {
        const q = await readFrame(conn);
        if (!q) break;
        const r = await resolveQuery(q, policy, ctl.signal);
        if (!r.length) break;
        const bytes = new Uint8Array([r.length >> 8, r.length & 255, ...r]);
        for (let i = 0; i < bytes.length;) {
          const n = await conn.write(bytes.subarray(i));
          if (!n) throw new Error("short write");
          i += n;
        }
      } finally {
        clearTimeout(timer);
      }
    }
  } finally {
    ctl.abort();
    close();
  }
}

async function resolveQuery(
  q: Uint8Array,
  policy: string,
  signal: AbortSignal,
) {
  const freq = new Request(
    "https://dot.invalid/" + (policy === "none" ? "dns-query" : policy),
    {
      method: "POST",
      headers: util.concatHeaders(
        util.dnsHeaders(),
        util.contentLengthHeader(q),
      ),
      body: new Uint8Array(q),
      signal,
    },
  );

  const r = await handleRequest(util.mkFetchEvent(freq));

  const ans = await r.arrayBuffer();

  if (!bufutil.emptyBuf(ans)) {
    return new Uint8Array(ans);
  } else {
    return new Uint8Array(dnsutil.servfailQ(q));
  }
}
