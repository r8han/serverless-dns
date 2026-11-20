/*
 * Copyright (c) 2021 RethinkDNS and its authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

import { checkAlive } from "../commons/cancel.js";
import { readBounded } from "../commons/bounded.js";
import * as bufutil from "../commons/bufutil.js";
import * as dnsutil from "../commons/dnsutil.js";
import * as envutil from "../commons/envutil.js";
import * as util from "../commons/util.js";
import { RResp } from "../plugins/plugin-response.js";
import IOState from "./io-state.js";
import { log } from "./log.js";
import { services } from "./svc.js";

export default class RethinkPlugin {
  /**
   * @param {{request: Request, waitUntil: Function, respondWith: Function}} event
   */
  constructor(event) {
    if (!services.ready) throw new Error("services not ready");
    /**
     * Parameters of RethinkPlugin which may be used by individual plugins.
     */
    this.ctx = new Map();

    const rxid = util.xid();
    this.addCtx("rxid", "[rx." + rxid + "]");

    // works on fly.io and cloudflare
    this.addCtx("region", getRegion(event.request) || "");

    // caution: event isn't an event on nodejs, but event.request is a request
    this.addCtx("request", event.request);

    // TODO: a more generic way for plugins to queue events on all platforms
    // dispatcher fn when called, fails with 'illegal invocation' if not
    // bound explicitly to 'event' (since it then executes in the context
    // of which-ever obj calls it): stackoverflow.com/a/9678166
    this.addCtx("dispatcher", event.waitUntil.bind(event));

    this.log = log.withTags("RethinkPlugin");

    /** @type {Array<RPlugin>} */
    this.plugin = [];

    this.registerPlugin(
      "userOp",
      services.userOp,
      ["rxid", "request", "requestDecodedDnsPacket", "isDnsMsg"],
      this.userOpCallback
    );

    // filter out undelegated domains if running recurisve resolver
    envutil.recursive() &&
      this.registerPlugin(
        "prefilter",
        services.prefilter,
        ["rxid", "requestDecodedDnsPacket"],
        this.prefilterCallback
      );

    this.registerPlugin(
      "cacheOnlyResolver",
      services.dnsCacheHandler,
      [
        "rxid",
        "userBlocklistInfo",
        "requestDecodedDnsPacket",
        "isDnsMsg",
        "userDnsResolverUrl",
        "signal",
      ],
      this.dnsCacheCallback
    );

    this.registerPlugin(
      "commandControl",
      services.commandControl,
      ["rxid", "userAuth", "signal", "request", "isDnsMsg"],
      this.commandControlCallback
    );

    this.registerPlugin(
      "dnsResolver",
      services.dnsResolver,
      [
        "rxid",
        "deadline",
        "signal",
        "dispatcher",
        "request",
        // resolver-url overriden by user-op
        "userDnsResolverUrl",
        "userBlocklistInfo",
        "userBlockstamp",
        "domainBlockstamp",
        "requestDecodedDnsPacket",
        "requestBodyBuffer",
      ],
      this.dnsResolverCallback
    );

    this.registerPlugin(
      "logpush",
      services.logPusher,
      [
        "userAuth",
        "isDnsMsg",
        "dispatcher",
        "request",
        "requestDecodedDnsPacket",
        "responseDecodedDnsPacket",
        "responseBodyBuffer",
        "isBlocked",
      ],
      util.stubAsync, // no callback
      true, // always exec this plugin
      true // on exception, don't exec
    );
  }

  addCtx(k, v) {
    this.ctx.set(k, v);
  }

  /**
   *
   * @param {string} name
   * @param {any} mod
   * @param {Array<string>} pctx
   * @param {function?} cb
   * @param {boolean} alwaysexec
   */
  registerPlugin(name, mod, pctx, cb, alwaysexec = false, bail = false) {
    this.plugin.push(new RPlugin(name, mod, pctx, cb, alwaysexec, bail));
  }

  async execute() {
    const io = this.io;
    // const rxid = this.ctx.get("rxid");
    for (const p of this.plugin) {
      if (io.stopProcessing && !p.continueOnStopProcess) {
        continue;
      }
      if (io.isException && p.bailOnException) {
        continue;
      }

      checkAlive(this.ctx.get("signal"));
      const res = await p.module.exec(makectx(this.ctx, p.pctx));

      if (typeof p.callback === "function") {
        await p.callback.call(this, res, io);
      }
    }
  }

  /**
   * @param {RResp} response
   * @param {IOState} io
   */
  async commandControlCallback(response, io) {
    const rxid = this.ctx.get("rxid");
    const r = response.data;
    this.log.d(rxid, "command-control response");

    if (!util.emptyObj(r) && r.stopProcessing) {
      this.log.d(rxid, "command-control reply");
      io.hResponse(r.httpResponse);
    }
  }

  /**
   * Adds "userBlocklistInfo", "userBlocklistInfo",  and "dnsResolverUrl"
   * to RethinkPlugin ctx.
   * @param {RResp} response
   * @param {Promise<IOState>} io
   */
  async userOpCallback(response, io) {
    const rxid = this.ctx.get("rxid");
    const r = response.data;
    this.log.d(rxid, "user-op response");

    if (response.isException) {
      io.isException = true;
      io.hResponse(
        new Response(null, {
          status: response.exceptionFrom === "UserOp:Policy" ? 400 : 401,
        })
      );
    } else if (!util.emptyObj(r)) {
      // will only be null in case of errors
      const a = r.userAuth;
      // r.userBlocklistInfo and r.dnsResolverUrl may be "null"
      const bi = r.userBlocklistInfo;
      const rr = r.dnsResolverUrl;
      // may be empty string; usually of form "v:base64" or "v-base32"
      const bs = r.userBlocklistFlag;

      this.addCtx("userAuth", a);
      this.addCtx("userBlocklistInfo", bi);
      this.addCtx("userBlockstamp", bs);
      this.addCtx("userDnsResolverUrl", rr);
    } else {
      this.log.i(rxid, "user-op is a no-op, possibly a command-control req");
    }
  }

  /**
   * @param {RResp} response
   * @param {IOState} io
   */
  prefilterCallback(response, io) {
    const rxid = this.ctx.get("rxid");
    const r = response.data;
    const deny = r.isBlocked;
    const err = response.isException;
    this.log.d(rxid, "prefilter deny?", deny, "err?", err);

    if (err) {
      this.log.w(rxid, "prefilter error");
      this.loadException(rxid, response, io);
    } else if (deny) {
      this.addCtx("isBlocked", true);
      io.dnsNxDomainResponse(r.flag);
    } else {
      this.log.d(rxid, "prefilter no-op");
    }
  }

  /**
   * @param {RResp} response
   * @param {IOState} io
   */
  dnsCacheCallback(response, io) {
    const rxid = this.ctx.get("rxid");
    const r = response.data;
    const deny = r.isBlocked;
    const isAns = dnsutil.isAnswer(r.dnsPacket);
    const noErr = dnsutil.rcodeNoError(r.dnsPacket);

    this.log.d(rxid, "crr: block?", deny, "ans?", isAns, "noerr", noErr);

    if (response.isException) {
      this.loadException(rxid, response, io);
    } else if (deny) {
      this.addCtx("isBlocked", true);
      // TODO: create block packets/buffers in dnsBlocker.js
      io.dnsBlockResponse(r.flag);
    } else if (isAns) {
      this.deliverAnswer(r, io);
    } else {
      this.addCtx("domainBlockstamp", r.stamps);
      this.log.d(rxid, "resolve query; no response from cache-handler");
    }
  }

  /**
   * @param {RResp} response
   * @param {IOState} io
   */
  dnsResolverCallback(response, io) {
    const rxid = this.ctx.get("rxid");
    const r = response.data;
    const deny = r.isBlocked;
    // dns packets may have no answers, but still be a valid response
    // for example, servfail do not contain any answers, whereas
    // nxdomain has an authority-section (but no answers).
    const isAns = dnsutil.isAnswer(r.dnsPacket);
    const noErr = dnsutil.rcodeNoError(r.dnsPacket);
    this.log.d(rxid, "rr: block?", deny, "ans?", isAns, "noerr?", noErr);

    if (deny) {
      // TODO: create block packets/buffers in dnsBlocker.js?
      this.addCtx("isBlocked", true);
      io.dnsBlockResponse(r.flag);
    } else if (response.isException || !isAns) {
      // if not blocked, but then, no-ans or is-exception, then:
      this.loadException(rxid, response, io);
    } else {
      this.deliverAnswer(r, io);
    }
  }

  /**
   *
   * @param {String} rxid
   * @param {RResp} response
   * @param {IOState} io
   */
  loadException(rxid, response, io) {
    this.log.w(rxid, "plugin failed");
    io.dnsExceptionResponse(response);
  }

  deliverAnswer(r, io) {
    const wire = io.dnsResponse(r.dnsBuffer, r.dnsPacket, r.flag);
    // Telemetry sees the response after policy and gateway rewriting, never
    // an upstream address that was withheld from the client.
    this.addCtx("responseBodyBuffer", wire);
    this.addCtx("responseDecodedDnsPacket", io.decodedDnsPacket);
  }

  /**
   * @param {IOState} io
   * @returns
   */
  async initIoState(io) {
    this.io = io;

    const request = this.ctx.get("request");
    const rxid = this.ctx.get("rxid");
    const region = this.ctx.get("region");
    const isDnsMsg = util.isDnsMsg(request);
    const isGwReq = util.isGatewayRequest(request);
    let question = null;

    io.id(rxid, region);

    this.addCtx("isDnsMsg", isDnsMsg);
    if (
      !util.isGetRequest(request) &&
      !(isDnsMsg && util.isPostRequest(request))
    ) {
      io.hResponse(util.respond405());
      return;
    }
    try {
      if (util.isPostRequest(request)) {
        question = await readBounded(
          request,
          dnsutil.maxDNSPacketSize,
          this.ctx.get("signal")
        );
      } else {
        const values = new URL(request.url).searchParams.getAll("dns");
        if (!isDnsMsg && !values.length) return; // command, not DNS
        if (
          values.length !== 1 ||
          values[0].length > 5462 ||
          !/^[a-zA-Z0-9_-]+$/.test(values[0])
        ) {
          throw new Error("invalid DNS parameter");
        }
        question = bufutil.base64ToBytes(values[0]);
      }
      let qpacket = dnsutil.decodeQuery(question);
      const stripped = dnsutil.stripClientSubnet(question, qpacket);
      if (question !== stripped) {
        question = stripped;
        qpacket = dnsutil.decodeQuery(question);
      }
      if (isGwReq) io.gatewayAnswersOnly(envutil.gwip4(), envutil.gwip6());
      io.input(qpacket);
      this.addCtx("isDnsMsg", true);
      this.addCtx("requestDecodedDnsPacket", qpacket);
      this.addCtx("requestBodyBuffer", question);
    } catch (e) {
      io.hResponse(
        new Response(null, { status: e instanceof RangeError ? 413 : 400 })
      );
    }
  }
}

/**
 * Makes ctx for a plugin
 * @param {Map<String, Object>} context - Execution context
 * @param {String[]} ctxkeys - Context required by a plugin
 * @returns {*} - A context object
 */
function makectx(context, ctxkeys) {
  const out = {};
  for (const key of ctxkeys) {
    out[key] = context.get(key) ?? null;
  }
  return out;
}

function getRegion(request) {
  if (envutil.onCloudflare()) {
    return util.regionFromCf(request);
  } else if (envutil.onFly()) {
    return envutil.region();
  }
  return "";
}

class RPlugin {
  constructor(name, mod, pctx, cb, alwaysexec, bail) {
    /** @type {String} */
    this.name = name;
    /** @type {{exec: function(Object): Promise<RResp>} */
    this.module = mod;
    /** @type {String[]} */
    this.pctx = pctx;
    /** @type {Function} */
    this.callback = cb;
    /** @type {boolean} */
    this.continueOnStopProcess = alwaysexec;
    /** @type {boolean} */
    this.bailOnException = bail;
  }
}
