/*
 * Copyright (c) 2021 RethinkDNS and its authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
import {
  cancelScope,
  checkAlive,
  fetchSignal,
  openResponse,
  whileAlive,
} from "../../commons/cancel.js";
import { readBounded } from "../../commons/bounded.js";
import * as bufutil from "../../commons/bufutil.js";
import * as dnsutil from "../../commons/dnsutil.js";
import * as envutil from "../../commons/envutil.js";
import * as util from "../../commons/util.js";
import { log } from "../../core/log.js";
import * as cacheutil from "../cache-util.js";
import * as pres from "../plugin-response.js";
import * as rdnsutil from "../rdns-util.js";
import { DnsBlocker } from "./blocker.js";

export default class DNSResolver {
  /**
   * @param {import("../rethinkdns/main.js").BlocklistWrapper} blocklistWrapper
   * @param {import("./cache.js").DnsCache} cache
   * @param {any} dns53
   */
  constructor(blocklistWrapper, cache, dns53) {
    /** @type {import("./cache.js").DnsCache} */
    this.cache = cache;
    this.blocker = new DnsBlocker();
    /** @type {import("../rethinkdns/main.js").BlocklistWrapper} */
    this.bw = blocklistWrapper;
    // deno bundler not happy with typedef as it imports node:dgram
    // @type {import("../../core/node/dns-transport.js").Transport}
    this.transport = dns53 || null;
    this.log = log.withTags("DnsResolver");

    this.measurements = [];
    this.pendingQueries = new Map(); // plain-DNS exchanges in flight on this transport
    this.profileResolve = envutil.profileDnsResolves();
    // only valid on nodejs
    this.forceDoh = envutil.forceDoh();
    this.timeout = Math.floor(dnsutil.requestTimeout() / 2);

    this.bgBwInit = envutil.bgDownloadBlocklistWrapper();
    this.maxDoh = envutil.maxDohUrl();

    if (this.profileResolve) {
      this.log.w("profiling enabled");
      this.log.w("doh?", this.forceDoh);
    } else {
      const cok = this.cache != null;
      const dok = this.transport != null;
      this.log.i("init: cache?", cok, "dns53?", dok, "doh?", this.forceDoh);
    }
  }

  async close() {
    this.log.i("closing resolver (& transport?", this.transport != null, ")");
    if (this.transport) return await this.transport.teardown();
  }

  /**
   * @param {Object} ctx
   * @param {String} ctx.rxid
   * @param {Request} ctx.request
   * @param {ArrayBuffer} ctx.requestBodyBuffer
   * @param {Object} ctx.requestDecodedDnsPacket
   * @param {Object} ctx.userBlocklistInfo
   * @param {String} ctx.userDnsResolverUrl
   * @param {string} ctx.userBlockstamp
   * @param {function(function):void} ctx.dispatcher
   * @returns {Promise<pres.RResp>}
   */
  async exec(ctx) {
    let response = pres.emptyResponse();

    try {
      response.data = await this.resolveDns(ctx);
    } catch (e) {
      response = pres.errResponse("dnsResolver");
      this.log.w(ctx.rxid, "resolution failed");
    }

    return response;
  }

  determineDohResolvers(preferredDoh, forceDoh = this.forceDoh) {
    // when this.transport is set, do not use doh unless forced
    if (this.transport && !forceDoh) return [];

    if (!util.emptyString(preferredDoh)) {
      return [preferredDoh];
    }

    return envutil.dohResolvers();
  }

  // TODO: nodejs.org/api/perf_hooks.html
  // github: pola-rs/polars@475cf3c/nodejs-polars/benches/list-operations.js
  // Deno perf-hooks: github.com/denoland/deno/issues/5386
  // WebAPI: developer.mozilla.org/en-US/docs/Web/API/Performance
  logMeasurementsPeriodically(period = 100) {
    const len = this.measurements.length - 1;
    // log after period number of measurements are done
    if ((len + 1) % period !== 0) return;

    this.measurements.sort((a, b) => a - b);
    const p10 = this.measurements[Math.floor(len * 0.1)];
    const p50 = this.measurements[Math.floor(len * 0.5)];
    const p75 = this.measurements[Math.floor(len * 0.75)];
    const p90 = this.measurements[Math.floor(len * 0.9)];
    const p95 = this.measurements[Math.floor(len * 0.95)];
    const p99 = this.measurements[Math.floor(len * 0.99)];
    const p999 = this.measurements[Math.floor(len * 0.999)];
    const p9999 = this.measurements[Math.floor(len * 0.9999)];
    const p100 = this.measurements[len];

    this.log.qStart("runs:", len + 1);
    this.log.q("p10/50/75/90/95", p10, p50, p75, p90, p95);
    this.log.qEnd("p99/99.9/99.99/100", p99, p999, p9999, p100);
  }

  /**
   * @param {Object} ctx
   * @param {String} ctx.rxid
   * @param {Request} ctx.request
   * @param {ArrayBuffer} ctx.requestBodyBuffer
   * @param {Object} ctx.requestDecodedDnsPacket
   * @param {pres.BlockstampInfo} ctx.userBlocklistInfo
   * @param {String} ctx.userDnsResolverUrl
   * @param {string} ctx.userBlockstamp
   * @param {number} [ctx.deadline] - request deadline in epoch milliseconds
   * @param {pres.BStamp?} ctx.domainBlockstamp
   * @param {function(function):void} ctx.dispatcher
   * @returns {Promise<pres.RResp>}
   */
  async resolveDns(ctx) {
    const rxid = ctx.rxid;
    const req = ctx.request;
    const blInfo = ctx.userBlocklistInfo;
    const rawpacket = ctx.requestBodyBuffer;
    const decodedpacket = dnsutil.decodeQuery(rawpacket);
    const userDns = ctx.userDnsResolverUrl;
    const forceUserDns = this.forceDoh || !util.emptyString(userDns);
    const dispatcher = ctx.dispatcher;
    const userBlockstamp = ctx.userBlockstamp;
    // may be null or empty-obj (stamp then needs to be got from blf)
    // may be a obj { domainName: String -> blockstamps: Uint16Array }
    const stamps = ctx.domainBlockstamp;

    if (ctx.deadline != null && Date.now() >= ctx.deadline) {
      throw new Error("request deadline exceeded");
    }
    if (this.bw.disabled() && rdnsutil.hasBlockstamp(blInfo)) {
      throw new Error("requested filtering unavailable");
    }
    let blf = this.bw.getBlocklistFilter();
    const cold = !this.bw.disabled() && !rdnsutil.isBlocklistFilterSetup(blf);
    const fromMax = cold && this.bgBwInit;
    if (cold && !fromMax) {
      // Do not send even the question upstream until its policy is known.
      // A download can finish for other requests after this one times out.
      const deadline = ctx.deadline ?? Date.now() + dnsutil.requestTimeout();
      const waitMs = Math.min(deadline - Date.now(), envutil.downloadTimeout());
      if (waitMs <= 0) throw new Error("blocklist deadline exceeded");
      const init = this.bw.init(rxid, true);
      dispatcher(init); // allow the filter download to outlive a slow request
      await whileAlive(
        util.timedOp((done) => {
          init.then(
            (v) => done(v),
            (err) => done(null, err)
          );
        }, waitMs),
        ctx.signal
      );
      checkAlive(ctx.signal);
      blf = this.bw.getBlocklistFilter();
      if (Date.now() >= deadline || !rdnsutil.isBlocklistFilterSetup(blf)) {
        throw new Error("local blocklist filter unavailable");
      }
    }
    const ts = this.bw.cacheTimestamp();
    const q = this.makeRdnsResponse(
      decodedpacket,
      rawpacket,
      blf,
      cold ? null : stamps
    );
    const key = cacheutil.cacheKey(decodedpacket, ts, userDns);
    this.blocker.blockQuestion(rxid, q, blInfo);
    if (q.isBlocked) {
      this.cache.putPolicy(key, q.stamps);
      return q;
    }

    const start = this.profileResolve ? Date.now() : 0;
    let answer;
    if (fromMax) {
      // A failed install must not surface as an unhandled rejection: this
      // request answered from the approved endpoint, and the next one retries.
      dispatcher(this.bw.init(rxid).catch(() => {}));
      // Only this operator-approved endpoint can apply the user's blockstamp.
      // Do not race it against an unfiltered answer in the shared cache.
      answer = await this.queryDoh(
        this.ofMax(userBlockstamp),
        req,
        rawpacket,
        decodedpacket,
        ctx.signal
      );
    } else {
      answer = await this.queryUpstream(
        rxid,
        ts,
        req,
        this.determineDohResolvers(userDns, forceUserDns),
        rawpacket,
        decodedpacket,
        ctx.signal
      );
    }
    if (this.profileResolve) {
      this.measurements.push(Date.now() - start);
      this.logMeasurementsPeriodically();
    }

    // Question-only stamps may not cover CNAMEs in the upstream answer.
    const r = this.makeRdnsResponse(answer.packet, answer.bytes, blf);
    this.blocker.blockAnswer(rxid, r, blInfo);
    checkAlive(ctx.signal);
    if (!fromMax) this.cache.putAnswer(key, answer, r.stamps, dispatcher);
    return r;
  }

  /**
   * @param {Object} dnsPacket
   * @param {ArrayBuffer} raw
   * @param {import("../rethinkdns/filter.js").BlocklistFilter} blf
   * @param {pres.BStamp?} stamps
   * @returns {pres.RespData}
   */
  makeRdnsResponse(dnsPacket, raw, blf, stamps = null) {
    // stamps are empty for domains that are not in any blocklist
    // but there's no way to know if that was indeed the case as
    // stamps are sent here by cache-resolver, which may or may not
    // have retrieved the stamps in the first-place.
    stamps = util.emptyObj(stamps)
      ? rdnsutil.blockstampFromBlocklistFilter(dnsPacket, blf)
      : stamps;

    return pres.dnsResponse(dnsPacket, raw, stamps);
  }

  ofMax(blockstamp) {
    if (util.emptyString(this.maxDoh)) return "";
    if (util.emptyString(blockstamp)) return this.maxDoh;
    else return this.maxDoh + blockstamp;
  }

  // Return decoded answers alongside their wire bytes: validate before the
  // race, without having to parse the winning DNS packet a second time.
  async queryUpstream(
    rxid,
    ts,
    request,
    resolverUrls,
    query,
    packet,
    signal = request.signal
  ) {
    checkAlive(signal);
    if (util.emptyArray(resolverUrls)) {
      return this.queryPlainDns(rxid, query, packet, signal);
    }
    const race = cancelScope([signal]);
    try {
      return await Promise.any(
        resolverUrls
          .filter(Boolean)
          .slice(0, 2)
          .map((url) => this.queryDoh(url, request, query, packet, race.signal))
      );
    } finally {
      race.close();
    }
  }

  async queryDoh(url, request, query, question, signal = request.signal) {
    const upstream = new URL(url);
    if (
      upstream.protocol !== "https:" ||
      upstream.username ||
      upstream.password
    ) {
      throw new Error("HTTPS upstream required");
    }
    const scope = cancelScope([signal], this.timeout);
    try {
      const init = {
        method: request.method,
        redirect: "manual",
        headers: util.dnsHeaders(),
        ...fetchSignal(scope.signal),
      };
      if (util.isGetRequest(request)) {
        upstream.searchParams.set("dns", bufutil.bytesToBase64Url(query));
      } else if (util.isPostRequest(request)) {
        init.body = query;
      } else {
        throw new Error("get/post only");
      }
      const res = await openResponse(
        () => fetch(new Request(upstream.href, init)),
        scope.signal
      );
      if (res.status !== 200) {
        res.body?.cancel().catch(() => {});
        throw new Error("upstream HTTP status: " + res.status);
      }
      return new cacheutil.UpstreamAnswer(
        await readBounded(res, dnsutil.maxDNSPacketSize, scope.signal),
        question
      );
    } finally {
      scope.close();
    }
  }

  async queryPlainDns(rxid, query, packet, signal) {
    const key = bufutil.bytesToBase64Url(bufutil.normalize8(query).subarray(2));
    let flight = this.pendingQueries.get(key);
    if (!flight) {
      if (this.pendingQueries.size >= 256) throw new Error("resolver busy");
      const scope = cancelScope([], this.timeout);
      flight = { scope, users: 0 };
      this.pendingQueries.set(key, flight);
      flight.work = this.exchangePlainDns(rxid, query, scope.signal).finally(
        () => {
          if (this.pendingQueries.get(key) === flight) {
            this.pendingQueries.delete(key);
          }
          scope.close();
        }
      );
    }
    flight.users++;
    let bytes;
    try {
      bytes = (await whileAlive(flight.work, signal)).slice(0);
    } finally {
      if (--flight.users === 0) flight.scope.close();
    }
    new DataView(bytes).setUint16(0, packet.id);
    return new cacheutil.UpstreamAnswer(bytes, packet);
  }

  async exchangePlainDns(rxid, query, signal) {
    if (!this.transport) throw new Error("plain dns transport not set");
    const q = bufutil.bufferOf(new Uint8Array(query).slice().buffer);
    crypto.getRandomValues(q.subarray(0, 2));
    const question = dnsutil.decodeQuery(q);
    let ans = await this.transport.udpquery(rxid, q, signal);
    checkAlive(signal);
    if (dnsutil.truncated(ans)) {
      const partial = dnsutil.decode(ans);
      if (
        partial.id !== question.id ||
        !cacheutil.sameQuestion(partial, question)
      ) {
        throw new Error("mismatched UDP question");
      }
      ans = await this.transport.tcpquery(rxid, q, signal);
      checkAlive(signal);
    }
    const bytes = bufutil.arrayBufferOf(ans);
    return new cacheutil.UpstreamAnswer(bytes, question).bytes;
  }
}
