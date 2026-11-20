// SPDX-License-Identifier: MPL-2.0
import * as pres from "../plugin-response.js";
import { cacheKey } from "../cache-util.js";
import { DnsBlocker } from "./blocker.js";

export class DNSCacheResponder {
  constructor(wrapper, cache) {
    this.bw = wrapper;
    this.cache = cache;
    this.blocker = new DnsBlocker();
  }
  async exec(ctx) {
    const res = pres.emptyResponse();
    if (!ctx.isDnsMsg || (this.bw.disabled() && ctx.userBlocklistInfo)) {
      return res;
    }
    const query = ctx.requestDecodedDnsPacket;
    const key = cacheKey(
      query,
      this.bw.cacheTimestamp(),
      ctx.userDnsResolverUrl
    );
    const hit = await this.cache.getAnswer(key, query, ctx.signal);
    const stamps = hit ? hit.stamps : this.cache.getPolicy(key);
    const result = new pres.RespData(
      false,
      "",
      hit?.packet || query,
      hit?.bytes || null,
      stamps
    );
    this.blocker.blockQuestion(ctx.rxid, result, ctx.userBlocklistInfo);
    if (hit && !result.isBlocked) {
      this.blocker.blockAnswer(ctx.rxid, result, ctx.userBlocklistInfo);
    }
    res.data = result;
    return res;
  }
}
