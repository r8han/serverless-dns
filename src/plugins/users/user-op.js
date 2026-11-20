/*
 * Copyright (c) 2020 RethinkDNS and its authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
import * as dnsutil from "../../commons/dnsutil.js";
import * as envutil from "../../commons/envutil.js";
import * as util from "../../commons/util.js";
import { log } from "../../core/log.js";
import * as pres from "../plugin-response.js";
import * as rdnsutil from "../rdns-util.js";
import * as token from "./auth-token.js";
import { UserCache } from "./user-cache.js";

// TODO: determine an approp cache-size
const cacheSize = 20000;

// use fixed doh upstream for these domains,
// instead of either recursing (on Fly.io)
const delegated = new Set(["ipv4only.arpa"]);

export class UserOp {
  constructor() {
    this.keys = token.credentials(envManager.get("ACCESS_KEYS"));
    this.userConfigCache = new UserCache(cacheSize);
    this.log = log.withTags("UserOp");
  }

  /**
   * @param {{request: Request, requestDecodedDnsPacket: any, isDnsMsg: Boolean, rxid: string}} ctx
   * @returns {Promise<pres.RResp>}
   */
  async exec(ctx) {
    let res = pres.emptyResponse();

    try {
      const out = await token.auth(ctx.request, this.keys);
      if (!out.ok || (ctx.isDnsMsg && out.scope === "read")) {
        res = pres.errResponse("UserOp:Auth");
      } else {
        res = this.loadUser(ctx);
      }
      res.data.userAuth = out;
    } catch (ex) {
      res = pres.errResponse("UserOp");
    }

    return res;
  }

  /**
   * @param {{request: Request, requestDecodedDnsPacket: any, isDnsMsg: Boolean, rxid: string}} ctx
   * @returns {pres.RResp}
   */
  loadUser(ctx) {
    const response = pres.emptyResponse();

    if (!ctx.isDnsMsg) {
      this.log.w(ctx.rxid, "not a dns-msg, ignore");
      return response;
    }

    try {
      const dnsPacket = ctx.requestDecodedDnsPacket;
      const domains = dnsutil.extractDomains(dnsPacket);
      for (const d of domains) {
        if (delegated.has(d)) {
          // may be overriden by user-preferred doh upstream
          response.data.dnsResolverUrl = envutil.primaryDohResolver();
        }
      }

      const blocklistFlag = rdnsutil.blockstampFromUrl(ctx.request.url, true);
      const hasflag = !util.emptyString(blocklistFlag);

      // blocklistFlag may be invalid, ref rdnsutil.blockstampFromUrl
      let r = this.userConfigCache.get(blocklistFlag);
      let hasdata = rdnsutil.hasBlockstamp(r);
      if (hasflag && !hasdata) {
        // r not in cache
        r = rdnsutil.unstamp(blocklistFlag); // r is never null, may throw ex
        hasdata = rdnsutil.hasBlockstamp(r);

        if (!hasdata) throw new Error("invalid policy");
        this.userConfigCache.put(blocklistFlag, r);
      }

      if (hasdata) {
        response.data.userBlocklistInfo = r;
        response.data.userBlocklistFlag = blocklistFlag;
        // TODO: override response.data.dnsResolverUrl
      }
    } catch (e) {
      return pres.errResponse("UserOp:Policy");
    }

    return response;
  }
}
