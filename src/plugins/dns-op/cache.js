// SPDX-License-Identifier: MPL-2.0
import { LfuCache } from "@serverless-dns/lfu-cache";
import * as dnsutil from "../../commons/dnsutil.js";
import * as env from "../../commons/envutil.js";
import { openResponse } from "../../commons/cancel.js";
import { readBounded } from "../../commons/bounded.js";
import { UpstreamAnswer, lifetime, replay } from "../cache-util.js";
import { AnswerCache } from "./answer-cache.js";
import { CacheApi } from "./cache-api.js";

export class DnsCache {
  constructor(size, bytes = dnsutil.cacheBytes()) {
    this.disabled =
      env.disableDnsCache() ||
      env.requiresHeaderAuth() ||
      !globalThis.envManager?.get("DNS_CACHE_ENABLED");
    // Answers carry up to a full DNS packet each, so they are bounded by
    // bytes as well as entries. Policy entries are per-question stamps and
    // are small enough for the entry cap to bound them.
    this.answers = new AnswerCache(size, bytes);
    this.policy = new LfuCache("policy-v2", size);
    this.http = new CacheApi();
  }

  // Revision-scoped question stamps only; cannot overwrite an answer in
  // either tier. No request wire bytes or per-user decision are retained.
  putPolicy(key, stamps) {
    if (!this.disabled && key && stamps) this.policy.put(key.href, stamps);
  }
  getPolicy(key) {
    return !this.disabled && key ? this.policy.get(key.href) : null;
  }

  putAnswer(key, answer, stamps, dispatcher) {
    if (this.disabled || !key || !(answer instanceof UpstreamAnswer)) return;
    const ttl = lifetime(answer.packet);
    if (!ttl) return;
    const time = Date.now();
    const bytes = answer.bytes.slice(0);
    this.answers.put(key.href, { bytes, time, stamps });
    const metadata = JSON.stringify({ key: key.href, time, stamps }, (_, x) =>
      x instanceof Uint16Array ? Array.from(x) : x
    );
    if (metadata.length > 8192 || this.http.noop) return;
    dispatcher(
      this.http
        .put(
          key.href,
          new Response(bytes, {
            headers: {
              "x-sdns-metadata": metadata,
              "cache-control": `max-age=${ttl}`,
            },
          })
        )
        .catch(() => {})
    );
  }

  async getAnswer(key, query, signal) {
    if (this.disabled || !key) return null;
    const local = this.answers.get(key.href);
    if (local) return replay(local, query);
    let res;
    try {
      res = await openResponse(() => this.http.get(key.href), signal);
      if (res?.status !== 200) return null;
      const header = res.headers.get("x-sdns-metadata");
      if (!header || header.length > 8192) return null;
      const { key: storedKey, time, stamps } = JSON.parse(header);
      if (storedKey !== key.href) return null;
      if (
        stamps !== false &&
        (!stamps || typeof stamps !== "object" || Array.isArray(stamps))
      ) {
        return null;
      }
      for (const [name, flags] of Object.entries(stamps || {})) {
        if (
          !Array.isArray(flags) ||
          flags.length > 17 ||
          flags.some((v) => !Number.isInteger(v) || v < 0 || v > 65535)
        ) {
          return null;
        }
        stamps[name] = Uint16Array.from(flags);
      }
      const bytes = await readBounded(res, 4096, signal);
      const entry = { bytes, time, stamps };
      const hit = replay(entry, query);
      if (hit) this.answers.put(key.href, entry);
      return hit;
    } catch {
      return null;
    } finally {
      if (res?.body && !res.bodyUsed) res.body.cancel().catch(() => {});
    }
  }
}
