/*
 * Copyright (c) 2021 RethinkDNS and its authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
import dgram from "node:dgram";
import net from "node:net";
import * as util from "../../commons/util.js";
import { IdlePool } from "../dns/conns.js";
import { TcpTx, UdpTx } from "../dns/transact.js";
import { log } from "../log.js";

/**
 * @typedef {import("net").Socket | import("dgram").Socket} AnySock
 * @typedef {import("net").Socket} TcpSock
 * @typedef {import("dgram").Socket} UdpSock
 */

/**
 *
 * @param {string} host
 * @param {int} port
 * @param {any} opts
 * @returns {Transport}
 */
export function makeTransport(host, port = 53, opts = {}) {
  return new Transport(host, port, opts);
}

// Transport upstreams plain-old DNS queries over both UDPv4 and TCPv4.
// Host and port constructor parameters are IPv4 addresses of the upstream.
// TCP and UDP connections are pooled for reuse, but DNS queries are not
// multiplexed. IO timeout, connection pool size, connection expiry are other
// constructor parameters to configure the pooling behaviour. Methods udpquery
// and tcpquery are the main entry points which forward a raw dns-packet as
// and return non-null dns-answers, if recieved on-time and without errors.
export class Transport {
  constructor(host, port, opts = {}) {
    if (util.emptyString(host)) throw new Error("invalid host" + host);
    /** @type {string} */
    this.host = host;
    /** @type {int} */
    this.port = port || 53;
    /** @type {int} */
    this.connectTimeout = opts.connectTimeout || 3000; // 3s
    /** @type {int} */
    this.ioTimeout = opts.ioTimeout || 10000; // 10s
    /** @type {int} */
    this.ipproto = net.isIP(host); // 4, 6, or 0
    const sz = opts.poolSize || 500; // conns
    const ttl = opts.poolTtl || 60000; // 1m
    this.tcpconns = new IdlePool(true, sz, ttl);
    this.udpconns = new IdlePool(false, sz, ttl);
    this.shutdown = new AbortController();

    this.log = log.withTags("DnsTransport");
    this.log.i(this.ipproto, "W transport", host, port, "pool", sz, ttl);
  }

  async teardown() {
    this.shutdown.abort();
    this.tcpconns.drain();
    this.udpconns.drain();
  }

  /**
   * @param {string} rxid
   * @param {Buffer} q
   * @returns {Promise<Buffer>|null}
   */
  udpquery(rxid, q, signal) {
    return this.exchange("udp", rxid, q, signal);
  }
  tcpquery(rxid, q, signal) {
    return this.exchange("tcp", rxid, q, signal);
  }

  async exchange(proto, rxid, q, signal) {
    const tcp = proto === "tcp";
    const pool = tcp ? this.tcpconns : this.udpconns;
    let sock;
    const close = () => {
      pool.discard(sock);
      sock = null;
    };
    const shutdown = this.shutdown.signal;
    signal = signal ? AbortSignal.any([signal, shutdown]) : shutdown;
    try {
      signal.throwIfAborted();
      sock = pool.take() || (await this.makeConn(proto, signal));
      signal.throwIfAborted();
      signal.addEventListener("abort", close, { once: true });
      const tx = tcp ? TcpTx.begin(sock) : UdpTx.begin(sock);
      const ans = await tx.exchange(rxid, q, this.ioTimeout);
      signal.throwIfAborted();
      if (!pool.give(sock)) close();
      return ans;
    } catch {
      close();
      throw new Error("DNS transport unavailable");
    } finally {
      signal.removeEventListener("abort", close);
    }
  }

  /**
   * @param {string} proto
   * @returns {Promise<AnySock>}
   * @throws {Error}
   */
  makeConn(proto, signal) {
    return new Promise((resolve, reject) => {
      const tcp = proto === "tcp";
      const sock = tcp
        ? new net.Socket()
        : dgram.createSocket(this.ipproto === 6 ? "udp6" : "udp4");
      let settled = false;
      const cleanup = () => {
        settled = true;
        clearTimeout(timer);
        signal?.removeEventListener("abort", fail);
      };
      const fail = () => {
        if (settled) return;
        cleanup();
        (tcp ? this.tcpconns : this.udpconns).discard(sock);
        reject(new Error("DNS connect failed"));
      };
      const timer = setTimeout(fail, this.connectTimeout);
      sock.once("error", fail);
      signal?.addEventListener("abort", fail, { once: true });
      if (signal?.aborted) return fail();
      try {
        sock.connect(this.port, this.host, (err) => {
          if (settled) return;
          if (err) return fail();
          cleanup();
          sock.off("error", fail);
          resolve(sock);
        });
      } catch {
        fail();
      }
    });
  }
}
