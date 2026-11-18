// SPDX-License-Identifier: MPL-2.0
import {
  cancelScope,
  checkAlive,
  fetchSignal,
  whileAlive,
  openResponse,
} from "../../commons/cancel.js";
import { readBounded } from "../../commons/bounded.js";
import { validPartition } from "../users/auth-token.js";
import * as pres from "../plugin-response.js";

const privateHeaders = {
  "cache-control": "private, no-store",
  "referrer-policy": "no-referrer",
};
const fields = new Map([
  ["type", "blob1"],
  ["result", "blob2"],
]);
const typeOK = (s) => typeof s === "string" && /^[A-Z0-9_]{1,16}$/.test(s);
const resultOK = (s) => ["blocked", "answered", "negative"].includes(s);
const deny = (status) =>
  new Response(null, { status, headers: privateHeaders });
const json = (data) => Response.json(data, { headers: privateHeaders });
const hour = (t) => Math.floor(t / 3600000);
const prefix = (tenant, t) => `v2/${tenant}/${hour(t)}/`;
function integer(s, min, max) {
  if (!/^(?:0|[1-9]\d{0,12})$/.test(s) || Number(s) < min || Number(s) > max) {
    throw new Error("invalid integer");
  }
  return Number(s);
}

// The provider does not support bound SQL parameters. Only configuration-
// validated identifiers, principal-derived partitions and integers enter SQL.
export function reportQuery(dataset, tenant, params) {
  if (
    !/^[A-Za-z][A-Za-z0-9_]{0,62}$/.test(dataset) ||
    !validPartition.test(tenant)
  ) {
    throw new Error("invalid analytics configuration");
  }
  for (const key of params.keys()) {
    if (!["f", "t", "l"].includes(key) || params.getAll(key).length !== 1) {
      throw new Error("invalid report option");
    }
  }
  const col = fields.get(params.get("f") ?? "result");
  if (!col) throw new Error("unknown report field");
  const minutes = integer(params.get("t") ?? "30", 1, 60);
  const limit = integer(params.get("l") ?? "10", 1, 32);
  return `SELECT ${col} AS category, SUM(_sample_interval) AS n FROM ${dataset} WHERE index1 = '${tenant}' AND timestamp > NOW() - INTERVAL '${minutes}' MINUTE GROUP BY category ORDER BY n DESC LIMIT ${limit} FORMAT JSON`;
}

export class LogPusher {
  // No raw query, IP, answer, credential, URL, free-form log id or console
  // output, even when opted in. The write credential determines the partition.
  async exec(ctx) {
    const env = globalThis.envManager;
    const auth = ctx.userAuth;
    const out = pres.emptyResponse();
    if (
      !ctx.isDnsMsg ||
      !env.get("LOGPUSH_ENABLED") ||
      auth?.scope !== "write" ||
      !auth.ok ||
      !validPartition.test(auth.partition) ||
      !env.get("LOGPUSH_SRC")?.has(new URL(ctx.request.url).hostname)
    ) {
      return out;
    }
    const type = ctx.requestDecodedDnsPacket?.questions[0]?.type;
    if (!typeOK(type)) return out;
    const result = ctx.blockflag
      ? "blocked"
      : ctx.responseDecodedDnsPacket?.answers?.length
      ? "answered"
      : "negative";
    const tenant = auth.partition;
    const time = Date.now();
    const bindings = globalThis.wenv;
    if (env.get("LOGPUSH_ANALYTICS")) {
      bindings?.METRICS?.writeDataPoint({
        indexes: [tenant],
        blobs: [type, result],
      });
    }
    if (env.get("LOGPUSH_HISTORY") && bindings?.DNS_HISTORY) {
      const data = JSON.stringify({ tenant, time, type, result });
      ctx.dispatcher(
        bindings.DNS_HISTORY.put(
          prefix(tenant, time) + crypto.randomUUID(),
          data
        ).catch(() => {})
      );
    }
    return out;
  }

  async read(command, request, auth, signal) {
    const env = globalThis.envManager;
    if (
      !env.get("OBSERVABILITY_READS") ||
      !auth?.ok ||
      auth.scope !== "read" ||
      !auth.partition ||
      !validPartition.test(auth.partition)
    ) {
      return deny(403);
    }
    const url = new URL(request.url);
    // Old /l:<id>/logs routes and tenant/SQL selectors are not supported.
    if (url.pathname !== "/" + command) return deny(400);
    const p = url.searchParams;
    const tenant = auth.partition;
    const scope = cancelScope([signal], 4000);
    signal = scope.signal;
    try {
      checkAlive(signal);
      if (command === "logs") {
        if (p.size !== 0) return deny(400);
        const store = globalThis.wenv?.DNS_HISTORY;
        if (!store) return deny(503);
        const now = Date.now();
        const keyPrefix = prefix(tenant, now);
        const page = await whileAlive(
          store.list({ prefix: keyPrefix, limit: 32 }),
          signal
        );
        const result = [];
        for (const { key } of page.objects.slice(0, 32)) {
          checkAlive(signal);
          if (!key.startsWith(keyPrefix)) throw new Error("partition mismatch");
          const obj = await openResponse(() => store.get(key), signal);
          if (!obj || obj.size > 512) {
            obj?.body?.cancel().catch(() => {});
            throw new Error("invalid record");
          }
          const bytes = await readBounded(new Response(obj.body), 512, signal);
          const row = JSON.parse(new TextDecoder().decode(bytes));
          if (
            row.tenant !== tenant ||
            !Number.isSafeInteger(row.time) ||
            hour(row.time) !== hour(now) ||
            !typeOK(row.type) ||
            !resultOK(row.result)
          ) {
            throw new Error("invalid record");
          }
          result.push({ time: row.time, type: row.type, result: row.result });
        }
        return json(result);
      }
      if (command !== "analytics") return deny(404);
      let sql;
      try {
        sql = reportQuery(env.get("ANALYTICS_DATASET"), tenant, p);
      } catch {
        return deny(400);
      }
      const account = env.get("CF_ACCOUNT_ID");
      const token = env.get("CF_ANALYTICS_READ_TOKEN");
      if (!token || !/^[0-9a-f]{32}$/.test(account)) return deny(503);
      const res = await openResponse(
        () =>
          fetch(
            `https://api.cloudflare.com/client/v4/accounts/${account}/analytics_engine/sql`,
            {
              method: "POST",
              redirect: "manual",
              headers: { authorization: `Bearer ${token}` },
              body: sql,
              ...fetchSignal(signal),
            }
          ),
        signal
      );
      if (res.status !== 200) {
        res.body?.cancel().catch(() => {});
        return deny(502);
      }
      const raw = await readBounded(res, 16384, signal);
      const rows = JSON.parse(new TextDecoder().decode(raw)).data;
      if (!Array.isArray(rows) || rows.length > 32) return deny(502);
      return json(
        rows.map(({ category, n }) => {
          if (
            !(p.get("f") === "type" ? typeOK(category) : resultOK(category)) ||
            !Number.isSafeInteger(Number(n)) ||
            Number(n) < 0
          ) {
            throw new Error("invalid report");
          }
          return { category, n: Number(n) };
        })
      );
    } catch {
      return deny(502);
    } finally {
      scope.close();
    } // never pass through provider error bodies
  }
}
