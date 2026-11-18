/*
 * Copyright (c) 2021 RethinkDNS and its authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

// should always be the first import
// import whyIsNodeRunning from "why-is-node-running";
import { listener, identity } from "./core/node/config.js";

import { LfuCache } from "@serverless-dns/lfu-cache";
import * as h2c from "httpx-server";
import { randomBytes, X509Certificate } from "node:crypto";
import http2 from "node:http2";
import https from "node:https";
import net from "node:net";
import { finished } from "node:stream";
import tls, { TLSSocket } from "node:tls";
import v8 from "node:v8";
import os from "os";
import process from "process";
import { V2ProxyProtocol } from "proxy-protocol-js";
import { readIncoming } from "./commons/bounded.js";
import * as bufutil from "./commons/bufutil.js";
import * as dnsutil from "./commons/dnsutil.js";
import * as envutil from "./commons/envutil.js";
import * as util from "./commons/util.js";
import { handleRequest } from "./core/doh.js";
import { log as log2, loggerWithTags } from "./core/log.js";
import http from "node:http";
import { readFrame } from "./commons/dns-frame.js";
import * as nodeutil from "./core/node/util.js";
import * as psk from "./core/psk.js";
import { stopAfter, uptime } from "./core/svc.js";
import * as system from "./system.js";
/**
 * @typedef {net.Socket} Socket
 * @typedef {http2.Http2ServerRequest} Http2ServerRequest
 * @typedef {http2.Http2ServerResponse} Http2ServerResponse
 */

let log = null;

// todo: as metrics
class Stats {
  constructor() {
    this.noreqs = -1;
    this.nofchecks = 0;
    this.tlserr = 0;
    this.tlspsks = 0;
    this.tlspskd = 0;
    this.tlspskmiss = 0;
    this.tottlspsk = 0;
    this.fasttls = 0;
    this.totfasttls = 0;
    this.noftlsadjs = 0;
    this.nofdrops = 0;
    this.nofconns = 0;
    this.openconns = 0;
    this.noftimeouts = 0;
    this.nofheapsnaps = 0;
    // avg1, avg5, avg15, adj, maxconns
    this.bp = [0, 0, 0, 0, 0];
  }

  str() {
    return (
      `reqs=${this.noreqs} c=${this.nofchecks} ` +
      `drops=${this.nofdrops}/tot=${this.nofconns}/open=${this.openconns} ` +
      `to=${this.noftimeouts}/tlserr=${this.tlserr}/tlspskmiss=${this.tlspskmiss} ` +
      `tls0=${this.fasttls}/tls0miss=${this.totfasttls}/tlsadjs=${this.noftlsadjs} ` +
      `tlspsks=${this.tlspsks}/tlspskd=${this.tlspskd}/tlspsktot=${this.tottlspsk} ` +
      `n=${this.bp[4]}/adj=${this.bp[3]} ` +
      `load=${this.bp[0]}/${this.bp[1]}/${this.bp[2]}`
    );
  }
}

class SoReport {
  constructor() {
    /** @type {int} total bytes transferred in preceding 1sec */
    this.tx = 0;
    /** @type {int} unix timestamp in millis */
    this.lastsnd = 0;
  }
}

class ConnW {
  /**
   * @param {Socket|TLSSocket} socket
   */
  constructor(socket) {
    this.socket = socket;
    this.rep = new SoReport();
  }
}

class Tracker {
  constructor() {
    this.zeroid = "";
    /** @type {Array<Map<string, ConnW>>} */
    this.connmap = [];
    this.reports = [];
    /** @type {Array<net.Server>} */
    this.srvs = [];
  }

  valid(id) {
    return id != null && this.zeroid !== id;
  }

  /**
   * @param {net.Server|tls.Server} server
   * @returns {string}
   */
  sid(server) {
    if (!server) return this.zeroid;

    const saddr = server.address();
    if (!saddr || !saddr.port) {
      log.w("trackConn: no addr/port");
      return this.zeroid;
    }

    return saddr.port + "";
  }

  /**
   * @param {Socket?} sock
   * @returns {string}
   */
  cid(sock) {
    if (!sock || util.emptyString(sock.remoteAddress)) return this.zeroid;
    else return sock.remoteAddress + "|" + sock.remotePort;
  }

  /**
   * @param {string} id
   * @param {net.Server} s
   * @returns {string} sid
   */
  trackServer(id, s) {
    if (!s) return this.zeroid;
    const mapid = this.sid(s);

    if (!this.valid(mapid)) {
      log.w("trackServer: server not tracked", id, mapid);
      return this.zeroid;
    }

    const cmap = this.connmap[mapid];
    if (cmap) {
      log.w("trackServer: server already tracked?", id, mapid);
      return this.zeroid;
    }

    log.i("trackServer: new server", id, mapid);
    this.connmap[mapid] = new Map();
    this.srvs.push(s);
    return mapid;
  }

  *servers() {
    yield* this.srvs;
  }

  *conns() {
    for (const cm of this.connmap) {
      if (!cm) continue;
      yield* cm.values();
    }
  }

  /**
   * @param {net.Server} server
   * @param {Socket} sock
   * @returns {string}
   */
  trackConn(server, sock) {
    // if no servers are being tracked, don't track connections either
    // happens if the server did not start or this.end was called
    if (util.emptyArray(this.srvs)) return this.zeroid;
    if (!server || !server.listening || !sock) return this.zeroid;

    const mapid = this.sid(server);
    const connid = this.cid(sock);
    const cmap = this.connmap[mapid];
    if (!this.valid(mapid) || !this.valid(connid) || !cmap) {
      log.d("trackConn: server/socket not tracked");
      return this.zeroid;
    }

    cmap.set(connid, new ConnW(sock));
    sock.on("close", (_haderr) => cmap.delete(connid));

    return connid;
  }

  /**
   *
   * @param {Socket|TLSSocket|null} sock
   * @returns {SoReport?} rep
   */
  sorep(sock) {
    const connid = this.cid(sock);
    if (!this.valid(connid)) return null; // unlikely

    for (const cmap of this.connmap) {
      if (!cmap) continue;
      const connw = cmap.get(connid);
      if (connw != null) return connw.rep;
    }
    return null; // sock not tracked!
  }

  /**
   * @returns {[Array<net.Server>, Array<Map<string, ConnW>>]}
   */
  end() {
    const srvs = this.srvs;
    const cmap = this.connmap;
    this.srvs = [];
    this.connmap = [];
    return [srvs, cmap];
  }
}

// nodejs.org/api/net.html#serverlisten
const tracker = new Tracker();
const stats = new Stats();
// blog.cloudflare.com/optimizing-tls-over-tcp-to-reduce-latency
// 1369 - (1500 - 1280) = 1149
const tlsStartFragmentSize = 1149; // bytes
const tlsMaxFragmentSize = 16 << 10; // 16kb
const cpucount = os.cpus().length || 1;
const adjPeriodSec = 5;
const maxCertUpdateAttempts = 20;
let adjTimer = null;

((_main) => {
  // listen for "go" and start the server
  system
    .when("go")
    .then(systemUp)
    .catch(() => {
      console.error("listener startup failed");
      process.exit(1);
    });
  // listen for "end" and stop the server
  system.sub("stop", systemDown);
  // ask prepare phase to commence
  system.pub("prepare");
})();

function systemDown() {
  // system-down even may arrive even before the process has had the chance
  // to start, in which case globals like env and log may not be available
  const upmins = (uptime() / 60000) | 0;
  log2.w("W rcv stop; uptime", upmins, "mins", stats.str());

  const shutdownTimeoutMs = envutil.shutdownTimeoutMs();
  // servers will start rejecting conns when tracker is empty
  const [srvs, cmap] = tracker.end();

  util.timeout(shutdownTimeoutMs, bye);

  if (adjTimer) clearInterval(adjTimer);
  // 0 was ignored; github.com/nodejs/node/pull/48276
  // accept only 1 conn (which keeps health-checks happy)
  adjustMaxConns(1);

  // drain all sockets stackoverflow.com/a/14636625
  // TODO: handle proxy protocol sockets
  for (const m of cmap) {
    if (!m) continue;
    log2.w("W closing...", m.size, "connections");
    for (const v of m.values()) {
      close(v.socket);
    }
  }

  // stopping net.server only stops incoming reqs; it does not
  // close open sockets: github.com/nodejs/node/issues/2642
  for (const s of srvs) {
    if (!s || !s.listening) continue;
    const saddr = s.address();
    log2.w("W stopping...", saddr);
    s.close(() => down(saddr));
    s.unref();
  }

  // test: util.next(whyIsNodeRunning, bye);
  util.next(bye);
}

function systemUp() {
  log = loggerWithTags("NodeJs");
  if (!log) throw new Error("logger unavailable on system up");

  const downloadmode = envutil.blocklistDownloadOnly();
  const profilermode = envutil.profileDnsResolves();
  const tlsoffload = listener?.mode === "offload";
  // todo: tcp backlog for doh/dot servers not supported on bun 1.1
  const tcpbacklog = envutil.tcpBacklog();
  const maxconns = envutil.maxconns();
  // see also: dns-transport.js:ioTimeout
  const ioTimeoutMs = envutil.ioTimeoutMs();
  const supportsHttp2 = envutil.isNode() || envutil.isDeno();
  const isBun = envutil.isBun();
  const tlsPsk = !isBun && psk.staticPsk(envManager.get("TLS_PSK"));
  const allowTlsPsk = Boolean(tlsPsk);

  if (downloadmode) {
    log.i("in download mode, not running the dns resolver");
    return;
  } else if (profilermode) {
    const durationms = 60 * 1000; // 1 min
    log.w("in profiler mode, run for", durationms, "and exit");
    stopAfter(durationms);
  } else {
    adjTimer = util.repeat(adjPeriodSec * 1000, adjustMaxConns);
    log.i(`cpu ${cpucount}, tcpb ${tcpbacklog}, c ${maxconns}`);
  }

  // nodejs.org/api/net.html#netcreateserveroptions-connectionlistener
  /** @type {net.ServerOpts} */
  const serverOpts = {
    keepAlive: true,
    noDelay: true,
  };
  // nodejs.org/api/tls.html#tlscreateserveroptions-secureconnectionlistener
  /** @type {tls.TlsOptions} */
  const tlsOpts = {
    minVersion: "TLSv1.2",
    honorCipherOrder: true,
    handshakeTimeout: Math.max((ioTimeoutMs / 2) | 0, 3 * 1000), // 3s in ms
    // blog.cloudflare.com/tls-session-resumption-full-speed-and-secure
    sessionTimeout: 60 * 60 * 24 * 7, // 7d in secs
  };
  // nodejs.org/api/http2.html#http2createsecureserveroptions-onrequesthandler
  const h2Opts = {
    allowHTTP1: true,
  };

  if (tlsoffload) {
    // fly.io terminated tls?
    const portdoh = envutil.dohCleartextBackendPort();
    const dohOpts = {
      port: portdoh,
      host: listener.host,
      backlog: tcpbacklog,
    };
    // An offloading frontend does not preserve policy-bearing DoT SNI. Do
    // not offer unfiltered TCP in its place; the frontend must forward DoH.
    // DNS over HTTPS Cleartext
    // Same port for http1.1/h2 does not work on node without tls, that is,
    // http2.createServer with opts { ALPNProtocols: ["h2", "http/1.1"],
    // allowHTTP1: true } doesn't handle http1.1 at all (but it does with
    // http2.createSecureServer which involves tls).
    // Ref (for servers): github.com/nodejs/node/issues/34296
    // Ref (for clients): github.com/nodejs/node/issues/31759
    // Impl: stackoverflow.com/a/42019773
    const dohct = (isBun ? http : h2c)
      .createServer(serverOpts, serveHTTPS)
      .listen(dohOpts, () => {
        up("DoH Cleartext", dohct.address());
        trapServerEvents("dohct", dohct);
      });
  } else {
    // terminate tls ourselves
    /** @type {tls.TlsOptions} */
    const secOpts = {
      ...identity,
      ...tlsOpts,
      ...serverOpts,
    };
    // Separate contexts and renewal state: replacing one server's certificate
    // does not replace the other server's SecureContext. Never enable PSK on
    // the HTTP listener that receives private DNS bearer credentials.
    const dotSecOpts = { ...secOpts };
    if (allowTlsPsk) {
      dotSecOpts.pskCallback = (_, id) => (id === psk.identity ? tlsPsk : null);
      dotSecOpts.pskIdentityHint = psk.identity;
      dotSecOpts.ciphers =
        "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE+AESGCM:ECDHE+CHACHA20:PSK-AES128-GCM-SHA256:!aNULL:!eNULL";
    }
    const portdot1 = envutil.dotBackendPort();
    const portdot2 = envutil.dotProxyProtoBackendPort();
    const portdoh = envutil.dohBackendPort();
    /** @type {net.ListenOptions} */
    const dohOpts = { port: portdoh, host: listener.host, backlog: tcpbacklog };
    /** @type {net.ListenOptions} */
    const dot1Opts = {
      port: portdot1,
      host: listener.host,
      backlog: tcpbacklog,
    };
    /** @type {net.ListenOptions} */
    const dot2Opts = {
      port: portdot2,
      host: listener.host,
      backlog: tcpbacklog,
    };
    // DNS over TLS
    const dot1 =
      !envutil.requiresHeaderAuth() &&
      tls
        .createServer(dotSecOpts, (socket) => serveTLS(socket, dotSecOpts.cert))
        .listen(dot1Opts, () => {
          up("DoT", dot1.address());
          certUpdateForever(dotSecOpts, dot1);
          trapSecureServerEvents("dot1", dot1);
        });

    // DNS over TLS w ProxyProto
    const dot2 =
      !envutil.requiresHeaderAuth() &&
      envutil.isDotOverProxyProto() &&
      net.createServer(serverOpts, serveDoTProxyProto).listen(dot2Opts, () => {
        up("DoT ProxyProto", dot2.address());
        trapServerEvents("dot2", dot2);
      });

    // DNS over HTTPS
    if (supportsHttp2) {
      const doh = http2
        .createSecureServer({ ...secOpts, ...h2Opts }, serveHTTPS)
        .listen(dohOpts, () => {
          up("DoH2", doh.address());
          certUpdateForever(secOpts, doh);
          trapSecureServerEvents("doh2", doh);
        });
    } else if (isBun) {
      const doh = https
        .createServer(secOpts, serveHTTPS)
        .listen(dohOpts, () => {
          up("DoH1", doh.address());
          certUpdateForever(secOpts, doh);
          trapSecureServerEvents("dohb1", doh);
        });
    } else {
      log2.i("unsupported runtime for doh");
    }
  }

  const portcheck = envutil.httpCheckPort();
  const checkHost =
    (envutil.onFly() && process.env.FLY_PRIVATE_IP) || "127.0.0.1";
  const hcheck = http
    .createServer(serve200)
    .listen(portcheck, checkHost, () => {
      up("http-check", hcheck.address());
      trapServerEvents("hcheck", hcheck);
    });

  heartbeat();
}

/**
 * Schedules the next cert-update attempt after a backoff delay.
 * The delay decreases as attempts are exhausted, and is clamped so that
 * the retry fires no later than one minute before the cert expires.
 * @param {tls.TlsOptions} secopts
 * @param {tls.Server} s
 * @param {int} n - already-incremented attempt count
 * @param {number} validUntil - ms until the current cert expires (may be ≤ 0)
 * @returns {number} scheduled delay in ms
 */
function scheduleCertBackoff(secopts, s, n, validUntil) {
  const oneMinMs = 1 * 60 * 1000;
  const sixMinMs = 6 * 60 * 1000;
  const attemptsLeft = Math.max(1, maxCertUpdateAttempts - n);
  let when = validUntil <= oneMinMs ? oneMinMs : sixMinMs * attemptsLeft;
  if (validUntil > oneMinMs && when > validUntil) {
    when = Math.max(oneMinMs, validUntil - oneMinMs);
  }
  util.timeout(when, () => certUpdateForever(secopts, s, n));
  return when;
}

/**
 * @param {tls.TlsOptions} secopts
 * @param {tls.Server} s
 * @param {int} n
 */
async function certUpdateForever(secopts, s, n = 0) {
  if (
    !envutil.kdfSvcSecretHex() ||
    !s.listening ||
    typeof s.setSecureContext !== "function"
  ) {
    return false;
  }
  if (n >= maxCertUpdateAttempts) {
    log2.e("crt: max update attempts reached", n);
    return false;
  }

  const crtpem = secopts.cert;
  if (bufutil.emptyBuf(crtpem)) {
    return false;
  }

  // nodejs.org/api/tls.html#tlsgetcertificates
  // nodejs.org/api/tls.html#certificate-object
  // X509Certificate throws on invalid input; it never returns null
  let crt = null;
  try {
    crt = new X509Certificate(crtpem);
  } catch (ex) {
    log2.e("crt: #", n, "update: invalid cert pem", ex.message);
    n = n + 1;
    const when = scheduleCertBackoff(secopts, s, n, 0);
    log2.e("crt: #", n, "update: next", when);
    return false;
  }
  logCertInfo(crt);

  const oneDayMs = 24 * 60 * 60 * 1000; // in ms
  const validUntil = new Date(crt.validTo).getTime() - Date.now();
  if (validUntil > oneDayMs) {
    log2.i("crt: #", n, "update: valid for", validUntil, "ms; not needed");
    util.timeout(validUntil - oneDayMs, () => certUpdateForever(secopts, s));
    return false;
  }

  const [latestKey, latestCert] = await nodeutil.replaceKeyCert(crt);
  if (bufutil.emptyBuf(latestKey) || bufutil.emptyBuf(latestCert)) {
    n = n + 1;
    const when = scheduleCertBackoff(secopts, s, n, validUntil);
    log2.e("crt: #", n, "update: no key/cert fetched; next", when);
    return false;
  }

  // X509Certificate throws on invalid input; it never returns null
  let latestcrt = null;
  try {
    latestcrt = new X509Certificate(latestCert);
  } catch (ex) {
    log2.e("crt: #", n, "update: invalid fetched cert", ex.message);
    n = n + 1;
    const when = scheduleCertBackoff(secopts, s, n, validUntil);
    log2.e("crt: #", n, "update: next", when);
    return false;
  }
  logCertInfo(latestcrt);

  // same serial: remote cert not yet rotated; backoff and retry
  if (latestcrt.serialNumber === crt.serialNumber) {
    n = n + 1;
    const when = scheduleCertBackoff(secopts, s, n, validUntil);
    log2.i("crt: #", n, "update: same cert; backoff", when);
    return false;
  }

  try {
    s.setSecureContext({ ...secopts, key: latestKey, cert: latestCert });
    Object.assign(secopts, { key: latestKey, cert: latestCert });
  } catch {
    scheduleCertBackoff(secopts, s, n + 1, validUntil);
    log2.e("crt: failed to install renewed identity");
    return false;
  }

  log2.i("crt: #", n, "update: set new cert");
  util.next(() => certUpdateForever(secopts, s));

  return true;
}

/**
 * @param {X509Certificate} crt
 */
function logCertInfo(crt) {
  if (!crt) {
    return;
  }
  log2.i(
    crt.serialNumber, // AF163398B8095EA6D273CC9B50E95DC3
    crt.issuer, // C=AT, O=ZeroSSL, CN=ZeroSSL ECC Domain Secure Site CA
    crt.subject, // CN=max.rethinkdns.com
    crt.fingerprint256, // 82:74:47:E6:A1:77:33:CD:1D:40:27:D4:B2:8B:E7:71:11:F9:F1:2C:D4:46:9D:3E:0D:84:89:B9:10:E7:32:5A
    crt.subjectAltName, // DNS:*.basic.rethinkdns.com, DNS:*.pro.rethinkdns.com, DNS:*.sky.rethinkdns.com, DNS:basic.rethinkdns.com, DNS:pro.rethinkdns.com
    crt.validFrom, // "Nov 20 00:00:00 2024 GMT"
    crt.validTo // "Jan 19 23:59:59 2025 GMT"
  );
}

/**
 * @param {string} id
 * @param  {... http2.Http2Server | net.Server} s
 */
function trapServerEvents(id, s) {
  const ioTimeoutMs = envutil.ioTimeoutMs();

  if (!s) return;

  const sid = tracker.trackServer(id, s);

  if (sid === tracker.zeroid) {
    log.w("tcp: may be already tracking server", id);
    return;
  }

  s.on("connection", (/** @type {Socket} */ socket) => {
    stats.nofconns += 1;
    stats.openconns += 1;

    const id = tracker.trackConn(s, socket);
    if (!tracker.valid(id)) {
      log.i("tcp: not tracking; server shutting down?");
      close(socket);
      return;
    }

    socket.setTimeout(ioTimeoutMs, () => {
      stats.noftimeouts += 1;
      log.d("tcp: incoming conn timed out");
      socket.end();
    });

    socket.on("error", (err) => {
      log.d("tcp: incoming connection closed");
      close(socket);
    });

    socket.on("end", () => {
      // TODO: is this needed? this is the default anyway
      socket.end();
    });

    socket.on("close", () => {
      stats.openconns -= 1;
    });
  });

  // emitted when the req is discarded due to maxConnections
  s.on("drop", (_data) => {
    stats.nofdrops += 1;
    stats.nofconns += 1;
  });

  s.on("error", (err) => {
    log.e("tcp: stop! server error; " + err.message, err);
    stopAfter(0);
  });
}

/**
 * @param {string} id
 * @param  {http2.Http2SecureServer | tls.Server} s
 */
function trapSecureServerEvents(id, s) {
  const ioTimeoutMs = envutil.ioTimeoutMs();

  if (!s) return;

  const sid = tracker.trackServer(id, s);

  if (sid === tracker.zeroid) {
    log.w("tls: may be already tracking server", id);
    return;
  }

  // github.com/grpc/grpc-node/blob/e6ea6f517epackages/grpc-js/src/server.ts#L392
  s.on("secureConnection", (/** @type {TLSSocket} */ socket) => {
    stats.nofconns += 1;
    stats.openconns += 1;

    const id = tracker.trackConn(s, socket);
    if (!tracker.valid(id)) {
      log.i("tls: not tracking; server shutting down?");
      close(socket);
      return;
    }

    // github.com/nodejs/node-v0.x-archive/issues/6889
    socket.setMaxSendFragment?.(tlsStartFragmentSize);

    socket.setTimeout(ioTimeoutMs, () => {
      stats.noftimeouts += 1;
      log.d("tls: incoming conn timed out");
      close(socket);
    });

    // error must be handled by Http2SecureServer
    // github.com/nodejs/node/issues/35824
    socket.on("error", (err) => {
      log.e("tls: incoming connection closed");
      close(socket);
    });

    socket.on("end", () => {
      // client gone, socket half-open at this point
      // close this end of the socket, too
      socket.end();
    });

    socket.on("close", () => {
      stats.openconns -= 1;
    });
  });

  const rottm = util.repeat(86400000 * 7, () => rotateTkt(id, s)); // 7d
  s.on("close", () => clearInterval(rottm));

  s.on("error", (err) => {
    log.e("tls: stop!", id, "server err; " + err.message, err);
    stopAfter(0);
  });

  // timtaubert.de/blog/2017/02/the-future-of-session-resumption
  // timtaubert.de/blog/2015/11/more-privacy-less-latency-improved-handshakes-in-tls-13
  // bajtos.net/posts/2013-08-07-improve-the-performance-of-the-node-js-https-server
  // session tickets take precedence over session ids; -no_ticket is needed
  // openssl s_client -connect :10000 -reconnect -tls1_2 -no_ticket
  // on bun, since session tickets cannot be set by programs (though may be vended
  // by the runtime itself), session ids may come in handy.
  const tlsSessions = new LfuCache("tlsSessions", 1024);
  s.on("newSession", (id, data, next) => {
    const hid = bufutil.hex(id);
    tlsSessions.put(hid, data);
    // log.d("tls: new session;", hid);
    next();
  });

  s.on("resumeSession", (id, next) => {
    const hid = bufutil.hex(id);
    const data = tlsSessions.get(hid) || null;
    // log.d("tls: resume;", hid, "ok?", data != null);
    if (data) stats.fasttls += 1;
    else stats.totfasttls += 1;
    next(/* err */ null, data);
  });

  // emitted when the req is discarded due to maxConnections
  s.on("drop", (_data) => {
    stats.nofdrops += 1;
    stats.nofconns += 1;
  });

  s.on("tlsClientError", (err, /** @type {TLSSocket} */ tlsSocket) => {
    stats.tlserr += 1;
    // fly tcp healthchecks also trigger tlsClientErrors
    // log.d("tls: client err;", err.message, addrstr(tlsSocket));
    close(tlsSocket);
  });
}

/**
 * Rotates TLS session tickets.
 * @param {string} id
 * @param {tls.Server?} s
 * @returns {void}
 */
function rotateTkt(id, s) {
  if (envutil.isCleartext()) return; // tls offload
  if (envutil.isBun()) return;
  if (!s || !s.listening) return;

  // Independent per listener and instance. Never reuse a PSK, service
  // credential or certificate private key as session-ticket key material.
  s.setTicketKeys(randomBytes(48));
}

function down(addr) {
  log2.w(`W closed: [${addr.address}]:${addr.port}`);
}

function up(server, addr) {
  log.i(server, `listening on: [${addr.address}]:${addr.port}`);
}

/**
 * RST and/or closes tcp socket.
 * @param {Socket | TLSSocket | null} sock
 */
function close(sock) {
  if (!sock || sock.destroyed) return;
  if (sock.connecting) sock.resetAndDestroy();
  else sock.destroySoon();
  sock.unref();
}

/**
 * @param {Http2ServerResponse?} res
 */
function resClose(res) {
  if (res && !res.destroyed) res.destroy();
}

/**
 * @param {Http2ServerResponse?} res
 * @returns {Boolean}
 */
function resOkay(res) {
  // determine if res is not destroyed, finished, and is writable
  return res.writable;
}

/**
 * @param {Socket?} sock
 * @returns {Boolean}
 */
function tcpOkay(sock) {
  return sock && sock.writable;
}

/**
 * Creates a duplex pipe between `a` and `b` sockets.
 * @param {Socket?} a
 * @param {Socket?} b
 * @return {Boolean} - true if pipe created, false if error
 */
function proxySockets(a, b) {
  if (!a || !b) return false;
  if (a.destroyed || b.destroyed) return false;
  // handle errors? stackoverflow.com/a/61091744
  a.pipe(b);
  b.pipe(a);
  return true;
}

/**
 * Proxies connection to DOT server, retrieving proxy proto header.
 * @param {Socket} clientSocket
 */
function serveDoTProxyProto(clientSocket) {
  let ppHandled = false;
  log.d("--> new client Connection");

  const dotSock = net.connect(envutil.dotBackendPort(), () =>
    log.d("pp: dot socket ready")
  );

  dotSock.on("error", (e) => {
    log.w("pp: dot socket err", e);
    close(clientSocket);
    close(dotSock);
  });

  function handleProxyProto(buf) {
    // Data from only first tcp segment is to be consumed to get proxy proto.
    // After extracting proxy proto, a duplex pipe is created to DoT server.
    // So, further tcp segments return here.
    if (ppHandled) return;

    const chunk = buf.toString("ascii");
    const delim = chunk.indexOf("\r\n") + 2; // CRLF = \x0D \x0A
    ppHandled = true;

    if (delim < 2) {
      log.e("pp: invalid header");
      close(clientSocket);
      close(dotSock);
      return;
    }

    try {
      // TODO: admission control
      const proto = V2ProxyProtocol.parse(chunk.slice(0, delim));

      // remaining data from first tcp segment
      if (!dotSock.destroyed) dotSock.write(buf.slice(delim));

      const ok = proxySockets(clientSocket, dotSock);
      if (!ok) throw new Error(proto + " err clientSock <> dotSock proxy");
    } catch (e) {
      log.w("proxy connection failed");
      close(clientSocket);
      close(dotSock);
      return;
    }
  }

  clientSocket.on("error", (_e) => {
    log.w("pp: client err, closing");
    close(clientSocket);
    close(dotSock);
  });
  clientSocket.on("data", handleProxyProto);
}

/**
 * Services a DNS over TLS connection
 * @param {TLSSocket} socket
 */
async function serveTLS(socket, cert) {
  const ctl = new AbortController();
  const abort = () => ctl.abort();
  socket.once("close", abort);
  try {
    const sni = socket.servername;
    if (
      !envutil.allowDomainFronting() &&
      (!sni ||
        !new X509Certificate(cert).checkHost(sni, {
          subject: "never",
          partialWildcards: false,
        }))
    ) {
      return;
    }
    const host = sni || "dot.invalid";
    // Adapt the async iterator to exact reads. One pending frame per socket,
    // including pipelined input; no concurrent mutation of a scratch buffer.
    const chunks = socket[Symbol.asyncIterator]();
    let rest;
    const reader = {
      async read(dst) {
        while (!rest?.length) {
          const next = await chunks.next();
          if (next.done) return null;
          rest = next.value;
        }
        const n = Math.min(dst.length, rest.length);
        dst.set(rest.subarray(0, n));
        rest = rest.subarray(n);
        return n;
      },
    };
    for (;;) {
      const timer = setTimeout(() => {
        abort();
        socket.destroy();
      }, dnsutil.requestTimeout());
      try {
        const q = await readFrame(reader);
        if (!q) break;
        heartbeat();
        const r = await resolveQuery(util.xid(), q, host, ctl.signal);
        if (!r?.length || ctl.signal.aborted) break;
        const frame = Buffer.alloc(2 + r.byteLength);
        frame.writeUInt16BE(r.byteLength);
        frame.set(r, 2);
        await new Promise((resolve, reject) =>
          socket.write(frame, (err) => (err ? reject(err) : resolve()))
        );
        adjustTLSFragAfterWrites(socket, frame.length);
      } finally {
        clearTimeout(timer);
      }
    }
  } catch {
    /* A disconnect, invalid input or deadline ends this stream. */
  } finally {
    abort();
    socket.off("close", abort);
    socket.destroy();
  }
}
/**
 * @param {String} rxid
 * @param {Buffer} q
 * @param {String} host
 * @param {AbortSignal} signal
 * @return {Promise<Uint8Array?>}
 */
async function resolveQuery(rxid, q, host, signal) {
  // Using POST, since GET requests cannot be greater than 2KB,
  // where-as DNS-over-TCP msgs could be upto 64KB in size.
  const freq = new Request(`https://${host}/dns-query`, {
    method: "POST",
    headers: util.concatHeaders(
      util.dnsHeaders(),
      util.contentLengthHeader(q),
      util.rxidHeader(rxid)
    ),
    body: q,
    signal,
  });

  const r = await handleRequest(util.mkFetchEvent(freq));

  const ans = await r.arrayBuffer();

  if (!bufutil.emptyBuf(ans)) {
    return bufutil.normalize8(ans);
  } else {
    log.w(rxid, "empty DNS answer");
    return new Uint8Array(dnsutil.servfailQ(q));
  }
}

function serve200(req, res) {
  stats.nofchecks += 1;
  res.writeHead(200);
  res.end();
}

/**
 * Services a DNS over HTTPS connection
 * @param {Http2ServerRequest} req
 * @param {Http2ServerResponse} res
 */
let httpActive = 0;
async function serveHTTPS(req, res) {
  if (httpActive >= 256 || req.url.length > 8192) {
    res.writeHead(httpActive >= 256 ? 503 : 414, {
      "cache-control": "private, no-store",
    });
    res.end(() => req.destroy());
    return;
  }
  httpActive++;
  const ctl = new AbortController();
  const abort = () => ctl.abort();
  const wait = dnsutil.requestTimeout();
  const deadline = Date.now() + wait;
  const timer = setTimeout(abort, wait);
  res.once("close", abort);
  try {
    const limit = req.method === "POST" ? dnsutil.maxDNSPacketSize : 0;
    const chunks = await readIncoming(req, limit, ctl.signal);
    await handleHTTPRequest(
      bufutil.concatBuf(chunks),
      req,
      res,
      ctl.signal,
      deadline
    );
  } catch (e) {
    if (resOkay(res) && !res.headersSent) {
      res.writeHead(
        ctl.signal.aborted ? 408 : e instanceof RangeError ? 413 : 400,
        { "cache-control": "private, no-store" }
      );
    }
    if (resOkay(res)) res.end(() => req.destroy());
    else req.destroy();
  } finally {
    httpActive--;
    res.off("close", abort);
    clearTimeout(timer);
  }
}

/**
 * @param {Buffer} b - Request body
 * @param {Http2ServerRequest} req
 * @param {Http2ServerResponse} res
 */
async function handleHTTPRequest(b, req, res, signal, deadline) {
  heartbeat();

  const rxid = util.xid();
  try {
    const fReq = new Request(nodeutil.requestUrl(req.headers, req.url), {
      // Note: In a VM container, Object spread may not be working for all
      // properties, especially of "hidden" Symbol values!? like "headers"?
      signal,
      headers: util.concatHeaders(
        util.rxidHeader(rxid),
        nodeutil.copyNonPseudoHeaders(req.headers)
      ),
      method: req.method,
      body: req.method === "POST" ? b : null,
    });

    const event = util.mkFetchEvent(fReq);
    event.deadline = deadline;
    const fRes = await handleRequest(event);

    if (!resOkay(res)) {
      throw new Error("res not writable 1");
    }

    res.writeHead(fRes.status, util.copyHeaders(fRes));

    // ans may be null on non-2xx responses, such as redirects (3xx) by cc.js
    // or 4xx responses on timeouts or 5xx on invalid http method
    const ans = await fRes.arrayBuffer();
    const sz = bufutil.len(ans);

    if (!resOkay(res)) {
      throw new Error("res not writable 2");
    } else if (sz > 0) {
      adjustTLSFragAfterWrites(res.socket, sz);
      res.end(bufutil.normalize8(ans));
    } else {
      // expect fRes.status to be set to non 2xx above
      res.end();
    }
  } catch (e) {
    const ok = resOkay(res);
    if (ok && !res.headersSent) {
      res.writeHead(400, { "cache-control": "private, no-store" });
    } // bad request
    if (ok && !res.writableEnded) res.end();
    if (!ok) resClose(res);
    log.w("HTTP request failed");
  }
}

/**
 * @param {Http2ServerRequest} req
 * @param {Http2ServerResponse} res
 */
function heartbeat() {
  const minc = envutil.minconns();
  // increment no of requests
  stats.noreqs += 1;

  if (stats.noreqs % (minc * 2) === 0) {
    log.i(stats.str(), "in", (uptime() / 60000) | 0, "mins");
  }
}

/**
 * github.com/nodejs/node-v0.x-archive/issues/6889
 * github.com/golang/go/blob/ef3e1dae2f/src/crypto/tls/conn.go#L895
 * @param {TLSSocket?} socket
 * @param {SoReport?} rep
 * @param {int} sz
 */
function adjustTLSFragAfterWrites(socket, sz, rep = tracker.sorep(socket)) {
  if (typeof sz !== "number" || sz <= 0) return; // also skip lastsnd
  if (socket == null || !(socket instanceof TLSSocket)) return;
  if (rep == null) return;

  const now = Date.now();
  if (now - rep.lastsnd > 1000) {
    // reset tx time threshold: 1s
    socket.setMaxSendFragment?.(tlsStartFragmentSize);
    rep.tx = sz;
  } else if (rep.tx > tlsStartFragmentSize * 1000) {
    stats.noftlsadjs += 1;

    // boost upto max thres: 1139 * 1000 = ~128kb or ~1000 frags
    socket.setMaxSendFragment?.(tlsMaxFragmentSize);
  } // else: adaptively set to (sz * est fragments rcvd so far)
  rep.lastsnd = now;
  rep.tx += sz;
  // socket.setMaxSendFragment(sz * sb.tx/tlsStartFragmentSize)
}

function adjustMaxConns(n) {
  const isNode = envutil.isNode();
  const notCloud = envutil.onLocal();
  const maxc = envutil.maxconns();
  const minc = envutil.minconns();
  const adjsPerSec = 60 / adjPeriodSec;

  // caveats:
  // linux-magazine.com/content/download/62593/485442/version/1/file/Load_Average.pdf
  // brendangregg.com/blog/2017-08-08/linux-load-averages.html
  // linuxjournal.com/article/9001
  let [avg1, avg5, avg15] = os.loadavg();
  avg1 = ((avg1 * 100) / cpucount) | 0;
  avg5 = ((avg5 * 100) / cpucount) | 0;
  avg15 = ((avg15 * 100) / cpucount) | 0;

  const freemem = os.freemem() / (1024 * 1024); // in mb
  const totmem = os.totalmem() / (1024 * 1024); // in mb
  const lowram = freemem < 0.1 * totmem;
  const verylowram = freemem < 0.025 * totmem;

  let adj = stats.bp[3] || 0;
  // increase in load
  if (avg5 > 90) {
    adj += 3;
  } else if (avg1 > 100) {
    adj += 2;
  } else if (avg1 > avg5) {
    adj += 1;
  }
  if (n == null) {
    // determine n based on load-avg
    n = maxc;
    if (avg1 > 100) {
      n = minc;
    } else if (avg1 > 90 || avg5 > 80 || lowram) {
      n = Math.max((n * 0.2) | 0, minc);
    } else if (avg1 > 80 || avg5 > 75) {
      n = Math.max((n * 0.4) | 0, minc);
    } else if (avg1 > 70) {
      n = Math.max((n * 0.6) | 0, minc);
    } else {
      // reclaim adjs 25% at a time as n approaches maxconns
      // ex: if adj is 100, then the decay would be,
      // [75, 56, 42, 31, 23, 17, 12, 9, 6, 4, 3, 2, 1, 0]
      adj = Math.max(0, adj * 0.75) | 0;
    }
  } else {
    // clamp n based on a preset
    n = Math.min(maxc, n);
    n = Math.max(minc, n);
    // n adjusts as per client input, not load avg
    adj = 0;
  }

  // adjustMaxConns is called every adjPeriodSec
  const breakpoint = 6 * adjsPerSec; // 6 mins
  const stresspoint = 4 * adjsPerSec; // 4 mins
  const nstr = stats.openconns + "/" + n;
  if (adj > breakpoint || (verylowram && !notCloud)) {
    log.w("load: verylowram! freemem:", freemem, "totmem:", totmem);
    log.w("load: stopping lowram?", verylowram, "; n:", nstr, "adjs:", adj);
    stopAfter(0);
    return;
  } else if (adj > stresspoint) {
    log.w("load: stress; lowram?", lowram, "mem:", freemem, " / ", totmem);
    log.w("load: stress; n:", nstr, "adjs:", adj, "avgs:", avg1, avg5, avg15);
    n = (minc / 2) | 0;
  } else if (adj > 0) {
    log.d("load: high; lowram?", lowram, "mem:", freemem, " / ", totmem);
    log.d("load: high; n:", nstr, "adjs:", adj, "avgs:", avg1, avg5, avg15);
  }

  stats.bp = [avg1, avg5, avg15, adj, n];
  for (const s of tracker.servers()) {
    if (!s || !s.listening) continue;
    s.maxConnections = n;
  }

  // nodejs.org/en/docs/guides/diagnostics/memory/using-gc-traces
  if (adj > 0) {
    if (isNode) v8.setFlagsFromString("--trace-gc");
  } else {
    if (isNode) v8.setFlagsFromString("--notrace-gc");
  }
}

function bye() {
  // in some cases, node stops listening but the process doesn't exit because
  // of other unreleased resources (see: svc.js#systemStop); and so exit with
  // success (exit code 0) regardless; ref: community.fly.io/t/4547/6
  log2.w("W game over");

  process.exit(0);
}
