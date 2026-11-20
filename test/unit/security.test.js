// SPDX-License-Identifier: MPL-2.0
import assert from "node:assert/strict";
import { test } from "node:test";
import { Readable } from "node:stream";
import { format } from "node:util";
import { Buffer } from "node:buffer";
import { readFileSync } from "node:fs";
import { registerHooks } from "node:module";
import { fixture, fixtureMetadata } from "./fixture.js";
import * as dns from "../../src/commons/dnsutil.js";
import { readBounded, readIncoming } from "../../src/commons/bounded.js";
import { readFrame } from "../../src/commons/dns-frame.js";
import {
  digest,
  fetchArtifact,
} from "../../src/commons/blocklist-integrity.js";
import { fromStr, hex2buf } from "../../src/commons/bufutil.js";
import { svckeys, hmacverify } from "../../src/commons/crypto.js";
import {
  listenerPolicy,
  validateIdentity,
} from "../../src/core/node/listener-policy.js";
import {
  cancelScope,
  openResponse,
  fetchSignal,
} from "../../src/commons/cancel.js";
import { replaceKeyCert, requestUrl } from "../../src/core/node/util.js";
import { staticPsk } from "../../src/core/psk.js";
import {
  credentials,
  auth,
  verifier,
} from "../../src/plugins/users/auth-token.js";
import {
  LogPusher,
  reportQuery,
} from "../../src/plugins/observability/log-pusher.js";
import EnvManager from "../../src/core/env.js";
import Log, { setLogger } from "../../src/core/log.js";
import "../../test/conformance.mjs";

// Substitute only the generated build input, even if the checkout contains
// real metadata. Never write into src/ from a test or need an upstream store.
const metadata = fixtureMetadata();
registerHooks({
  resolve(s, ctx, next) {
    if (
      s === "../blocklist-metadata.json" &&
      ctx.parentURL.endsWith("/src/core/cfg.js")
    ) {
      return {
        url:
          "data:application/json;base64," +
          Buffer.from(JSON.stringify(metadata)).toString("base64"),
        shortCircuit: true,
      };
    }
    return next(s, ctx);
  },
});
const { handleRequest } = await import("../../src/core/doh.js");
const { services } = await import("../../src/core/svc.js");
const { BlocklistWrapper } = await import(
  "../../src/plugins/rethinkdns/main.js"
);
const { UserOp } = await import("../../src/plugins/users/user-op.js");
const { CommandControl } = await import(
  "../../src/plugins/command-control/cc.js"
);
const { DNSCacheResponder, DNSResolver, DnsCache } = await import(
  "../../src/plugins/dns-op/dns-op.js"
);
const { cacheKey, lifetime, replay, UpstreamAnswer } = await import(
  "../../src/plugins/cache-util.js"
);
const binary = (b64) => Uint8Array.from(Buffer.from(b64, "base64")).buffer;
const query = dns.mkQ(5, [{ name: "listed.example", type: "A" }]);
const q = dns.decodeQuery(query);
function response(rr, flags = 0x180, authorities = []) {
  return dns.encode({
    id: q.id,
    type: "response",
    questions: q.questions,
    flags,
    answers: rr,
    authorities,
  });
}
const a = { name: "listed.example", type: "A", ttl: 55, data: "192.0.2.8" };
const key = "a".repeat(43);
const host = "resolver.example";
function request(path, init) {
  return new Request(`https://${host}${path}`, init);
}
function env(t, vars = {}) {
  globalThis.wenv = {
    CLOUD_PLATFORM: "cloudflare",
    CF_DNS_RESOLVER_URL_2: "",
    ...vars,
  };
  globalThis.envManager = new EnvManager();
  setLogger(new Log({ level: "error" }));
  t.after(() => {
    delete globalThis.wenv;
    delete globalThis.envManager;
    delete globalThis.caches;
  });
}

test("credentials: only an exact hostname, full verifier and header bearer authorize", async () => {
  const entry = await verifier(key, host);
  for (const bad of [
    "",
    " ",
    entry + ",",
    entry.slice(0, -1),
    entry + "|owner",
    entry + "|../other|write",
    entry + "|one|admin",
  ]) {
    assert.throws(() => credentials(bad));
  }
  const entries = credentials(entry + "|one|write");
  const headers = { authorization: "Bearer " + key };
  assert.equal(
    (await auth(request("/", { headers }), entries)).partition,
    "one"
  );
  for (const r of [
    request("/"),
    request("/" + key),
    request("/", { headers: { authorization: "Bearer " + "b".repeat(43) } }),
    new Request(`https://child.${host}/`, { headers }),
  ]) {
    assert.equal((await auth(r, entries)).ok, false);
  }
  assert.deepEqual(await auth(request("/"), credentials(null)), {
    ok: true,
    scope: "public",
  });
});

test("certificate-renewal client signs exactly the path with a 32-byte verifiable MAC", async (t) => {
  env(t, { KDF_SVC: "aa".repeat(32) });
  const [, macKey] = await svckeys();
  let verified = false;
  t.mock.method(globalThis, "fetch", async (req) => {
    const mac = hex2buf(req.headers.get("x-rethinkdns-xsvc-authz"));
    verified =
      mac.length === 32 &&
      (await hmacverify(macKey, mac, fromStr(new URL(req.url).pathname)));
    return new Response(null, { status: 404 });
  });
  await replaceKeyCert({
    subject: "rethinkdns.com",
    subjectAltName: "DNS:rethinkdns.com",
  });
  assert.equal(verified, true);
});

test("stream admission stops pulling on declared or actual byte overflow; abort ends stalled reads", async () => {
  let pulls = 0;
  let cancellations = 0;
  const body = () =>
    new ReadableStream(
      {
        pull(c) {
          pulls++;
          c.enqueue(new Uint8Array(8));
        },
        cancel() {
          cancellations++;
        },
      },
      { highWaterMark: 0 }
    );
  await assert.rejects(
    readBounded(
      new Response(body(), { headers: { "content-length": "100" } }),
      10
    ),
    RangeError
  );
  assert.equal(pulls, 0);
  await assert.rejects(readBounded(new Response(body()), 10), RangeError);
  assert.equal(pulls, 2);
  assert.equal(cancellations, 2);
  const ctl = new AbortController();
  const pending = readBounded(
    new Response(
      new ReadableStream({
        cancel() {
          cancellations++;
        },
      })
    ),
    4096,
    ctl.signal
  );
  ctl.abort();
  await assert.rejects(pending);
  assert.equal(cancellations, 3);
  const req = Readable.from([
    Buffer.alloc(8),
    Buffer.alloc(8),
    Buffer.alloc(8),
  ]);
  req.headers = {};
  await assert.rejects(
    readIncoming(req, 9, new AbortController().signal),
    RangeError
  );
  assert.equal(req.isPaused(), true);
  assert.equal(req.listenerCount("data"), 0);
  req.destroy();
});

test("DoT reads fragmented lengths and bodies exactly, checking the size before the body read", async () => {
  const raw = Buffer.from(query);
  const frame = Buffer.concat([Buffer.from([0, raw.length]), raw]);
  let pos = 0;
  assert.deepEqual(
    await readFrame({
      async read(buf) {
        buf[0] = frame[pos++];
        return 1;
      },
    }),
    new Uint8Array(query)
  );
  let calls = 0;
  await assert.rejects(
    readFrame({
      async read(buf) {
        calls++;
        buf.set([0, 0]);
        return 2;
      },
    })
  );
  assert.equal(calls, 1);
  assert.equal(await readFrame({ read: async () => null }), null);
});

test("answer replay preserves complete signed RRsets, ages wire TTLs and never revives expired or negative data", (t) => {
  env(t);
  const sig = {
    name: a.name,
    type: "RRSIG",
    ttl: 45,
    data: {
      typeCovered: "A",
      algorithm: 8,
      labels: 2,
      originalTTL: 55,
      expiration: 1900000000,
      inception: 1700000000,
      keyTag: 1,
      signersName: a.name,
      signature: Buffer.alloc(16, 5),
    },
  };
  const bytes = response([a, { ...a, data: "192.0.2.9" }, sig], 0x1a0);
  const entry = { time: Date.now() - 2000, bytes, stamps: {} };
  const hit = replay(entry, { ...q, id: 18 });
  assert.deepEqual(
    hit.packet.answers.map((r) => r.ttl),
    [53, 53, 43]
  );
  assert.equal(hit.packet.flag_ad, true);
  const expected = bytes.slice(0);
  const view = new DataView(expected);
  view.setUint16(0, 18);
  for (const r of dns.decode(bytes).answers) {
    view.setUint32(r.ttlOffset, r.ttl - 2);
  }
  assert.deepEqual(hit.bytes, expected);
  assert.equal(dns.decode(bytes).id, 5);
  for (const f of [2, 5, 512]) {
    assert.throws(() => new UpstreamAnswer(response([a], f), q));
  }
  assert.equal(lifetime(dns.decode(response([{ ...a, ttl: 0 }]))), 0);
  assert.equal(replay({ ...entry, time: Date.now() - 45000 }, q), null);
  const soa = {
    name: "example",
    type: "SOA",
    ttl: 20,
    data: {
      mname: "ns.example",
      rname: "host.example",
      serial: 1,
      refresh: 2,
      retry: 2,
      expire: 20,
      minimum: 6,
    },
  };
  const negative = response([], 3, [soa]);
  assert.equal(lifetime(dns.decode(negative)), 6);
  assert.equal(
    replay({ ...entry, bytes: negative }, q).packet.authorities[0].ttl,
    4
  );
  assert.equal(lifetime(dns.decode(response([], 3))), 0);
  assert.notEqual(
    cacheKey(q, "v").href,
    cacheKey({ ...q, flags: q.flags | 16 }, "v").href
  );
  assert.notEqual(
    cacheKey(q, "v", "https://up1.example").href,
    cacheKey(q, "v", "https://up2.example").href
  );
});

test("blocklist installation is all-or-nothing; interrupted, partial, and corrupt generations cannot replace it", async (t) => {
  env(t);
  const bw = new BlocklistWrapper();
  const td = binary(fixture.td);
  const rd = binary(fixture.rd);
  await bw.install(td, rd);
  const first = bw.getBlocklistFilter();
  for (const data of [td.slice(1), new ArrayBuffer(td.byteLength)]) {
    await assert.rejects(bw.install(data, rd));
    assert.equal(bw.getBlocklistFilter(), first);
  }
  for (const res of [
    new Response(td, { status: 206 }),
    new Response(td.slice(1)),
    new Response(new Uint8Array(td.byteLength)),
  ]) {
    await assert.rejects(
      fetchArtifact(
        "https://store.test",
        metadata.manifest,
        "td.txt",
        async () => res
      )
    );
  }
  await assert.rejects(
    fetchArtifact(
      "https://store.test",
      { ...metadata.manifest, version: "not-a-version" },
      "td.txt",
      () => assert.fail("invalid version fetched")
    )
  );
  assert.deepEqual(
    await fetchArtifact(
      "https://store.test",
      metadata.manifest,
      "td.txt",
      async () => new Response(td)
    ),
    td
  );
});

test("production startup selects only explicit modes with private offload and rejects fixture identities", () => {
  const cfg = { production: true, platform: "standalone", mode: "terminate" };
  for (const bad of [
    { mode: undefined },
    { platform: undefined },
    { mode: "offload", privateBind: "0.0.0.0" },
    { mode: "managed", platform: "deno-deploy" },
  ]) {
    assert.throws(() => listenerPolicy({ ...cfg, ...bad }));
  }
  assert.equal(listenerPolicy({ ...cfg, mode: "offload" }).host, "127.0.0.1");
  assert.equal(
    listenerPolicy({
      ...cfg,
      mode: "managed",
      platform: "deno-deploy",
      managedDeno: true,
    }).mode,
    "managed"
  );
  const crt = (ext) =>
    readFileSync(
      new URL("../data/tls/dns.rethinkdns.localhost." + ext, import.meta.url)
    );
  validateIdentity(crt("key"), crt("crt"), false);
  assert.throws(
    () => validateIdentity(crt("key"), crt("crt"), true),
    /development/
  );
  assert.throws(() => validateIdentity("", crt("crt"), true));
  assert.throws(() => staticPsk("abcd"));
});

function configureServices(t, bw) {
  const cache = new DnsCache(32);
  const lp = new LogPusher();
  const resolver = new DNSResolver(bw, cache);
  Object.assign(services, {
    ready: true,
    userOp: new UserOp(),
    dnsCacheHandler: new DNSCacheResponder(bw, cache),
    dnsResolver: resolver,
    logPusher: lp,
    commandControl: new CommandControl(bw, resolver, lp),
  });
  t.after(() => {
    services.ready = false;
  });
  return cache;
}

test("HTTP admission and cache provenance: reject nonqueries and bad policy, retain only question stamps on denial", async (t) => {
  env(t);
  const writes = new Map();
  globalThis.caches = {
    default: {
      match: async (k) => writes.get(k)?.clone(),
      put: async (k, v) => writes.set(k, v),
    },
  };
  const bw = new BlocklistWrapper();
  await bw.install(binary(fixture.td), binary(fixture.rd));
  const cache = configureServices(t, bw);
  let sent = 0;
  const bg = [];
  t.mock.method(globalThis, "fetch", async (req) => {
    sent++;
    const query = dns.decodeQuery(await req.arrayBuffer());
    return new Response(
      dns.encode({
        id: query.id,
        type: "response",
        questions: query.questions,
        answers: [a],
      })
    );
  });
  const dispatch = (r) =>
    handleRequest({ request: r, waitUntil: (p) => bg.push(p) });
  const post = (body, path = "/dns-query") =>
    dispatch(request(path, { method: "POST", body, headers: dnsHeaders }));
  const dnsHeaders = { "content-type": "application/dns-message" };
  for (const bytes of [response([a]), query.slice(0, -1)]) {
    assert.equal((await post(bytes)).status, 400);
  }
  for (const path of [
    "/1:",
    "/2:AAIAgA",
    "/1%3Ainvalid",
    "/1:AAIAgA:legacy",
    "/not-a-policy",
    "/rec/sec",
  ]) {
    assert.equal((await post(query, path)).status, 400);
  }
  assert.equal(
    (await dispatch(request("/?dns=" + "A".repeat(5500)))).status,
    400
  );
  const denied = await post(query, "/1:AIAAgA");
  assert.equal(
    dns.decode(await denied.arrayBuffer()).answers[0].data,
    "0.0.0.0"
  );
  const k = cacheKey(q, bw.cacheTimestamp());
  assert.ok(cache.getPolicy(k));
  assert.equal(await cache.getAnswer(k, q), null);
  assert.equal(sent, 0);
  assert.equal(writes.size, 0);
  // Non-address lookups are governed by the same list, with REFUSED rather than an invented IP RR.
  const txt = await post(
    dns.mkQ(9, [{ name: a.name, type: "TXT" }]),
    "/1:AIAAgA"
  );
  assert.equal(dns.decode(await txt.arrayBuffer()).rcode, "REFUSED");
  assert.equal(sent, 0);
  const allowed = await post(query);
  assert.equal(allowed.headers.get("cache-control"), "private, no-store");
  assert.equal(dns.decode(await allowed.arrayBuffer()).answers[0].data, a.data);
  await Promise.all(bg);
  assert.equal(sent, 1);
  assert.equal(writes.size, 1);
});

function captureDiagnostics(t) {
  const diagnostics = [];
  for (const level of ["log", "debug", "info", "warn", "error"]) {
    t.mock.method(console, level, (...args) =>
      diagnostics.push(format(...args))
    );
  }
  setLogger(new Log({ level: "debug" }));
  return diagnostics;
}

test("all HTTP credential outcomes and retired enrollment routes are private; no secret or URL enters diagnostics", async (t) => {
  const entry = await verifier(key, host);
  env(t, { ACCESS_KEYS: entry });
  const diagnostics = captureDiagnostics(t);
  const bw = new BlocklistWrapper();
  const cache = configureServices(t, bw);
  void cache;
  const dispatch = (r) => handleRequest({ request: r, waitUntil() {} });
  t.mock.method(globalThis, "fetch", () =>
    assert.fail("credential request went upstream")
  );
  for (const [r, status] of [
    [request("/" + key), 401],
    [
      request("/gentlspsk", { headers: { authorization: "Bearer " + key } }),
      410,
    ],
    [
      request("/genaccesskey?key=" + key, {
        headers: { authorization: "Bearer " + key },
      }),
      410,
    ],
    [request("/logs", { headers: { authorization: "Bearer " + key } }), 403],
  ]) {
    const res = await dispatch(r);
    assert.equal(res.status, status);
    assert.equal(res.headers.get("cache-control"), "private, no-store");
  }
  assert.ok(!diagnostics.join("\n").includes(key));
  assert.ok(!diagnostics.join("\n").includes(entry.split("|")[1]));
  assert.ok(!diagnostics.join("\n").includes("https://" + host));
});

test("history and analytics are opt-in and scoped to structured tenant-owned records", async (t) => {
  env(t, {
    LOGPUSH_SRC: host,
    LOGPUSH_HISTORY: "true",
    LOGPUSH_ANALYTICS: "true",
    LOGPUSH_ANSWER_COUNTRY: "true",
  });
  const store = new Map();
  const get = t.mock.fn(async (k) => {
    const s = store.get(k);
    return { size: s.length, body: new Response(s).body };
  });
  const list = t.mock.fn(async ({ prefix }) => ({
    objects: [...store.keys()]
      .filter((k) => k.startsWith(prefix))
      .map((key) => ({ key })),
  }));
  const metric = t.mock.fn();
  wenv.METRICS = { writeDataPoint: metric };
  wenv.DNS_HISTORY = { get, list, put: async (k, v) => store.set(k, v) };
  const bg = [];
  const lp = new LogPusher();
  const lookup = t.mock.method(lp.geo, "country", async () => "IN");
  const principal = (scope, partition) => ({ ok: true, scope, partition });
  const row = {
    isDnsMsg: true,
    request: request("/l:two"),
    requestDecodedDnsPacket: q,
    responseDecodedDnsPacket: { answers: [a] },
    responseBodyBuffer: response([a]),
    dispatcher: (p) => bg.push(p),
    userAuth: principal("write", "one"),
  };
  const consoleLogs = t.mock.method(console, "log", () => {});
  await lp.exec(row);
  assert.equal(consoleLogs.mock.callCount(), 0);
  assert.equal(store.size, 0);
  assert.equal(metric.mock.callCount(), 0);
  wenv.LOGPUSH_ENABLED = "true";
  await lp.exec({ ...row, request: new Request("https://not" + host + "/") });
  for (const auth of [
    principal("read", "one"),
    principal("dns", "one"),
    principal("write", undefined),
  ]) {
    await lp.exec({ ...row, userAuth: auth });
  }
  assert.equal(lookup.mock.callCount(), 0);
  assert.equal(store.size, 0);
  await lp.exec(row);
  await lp.exec({ ...row, userAuth: principal("write", "two") });
  await Promise.all(bg);
  assert.equal(store.size, 2);
  assert.equal(lookup.mock.callCount(), 2);
  assert.deepEqual(
    metric.mock.calls.map((c) => c.arguments[0]),
    ["one", "two"].map((tenant) => ({
      indexes: [tenant],
      blobs: ["A", "answered", "IN"],
    }))
  );
  const read = (auth, url = "/logs") => lp.read("logs", request(url), auth);
  const reader = principal("read", "one");
  assert.equal((await read(reader)).status, 403);
  wenv.OBSERVABILITY_READS = "true";
  assert.equal((await read(row.userAuth)).status, 403);
  assert.equal((await read(reader, "/l:two/logs")).status, 400);
  assert.equal(list.mock.callCount(), 0);
  const res = await read(reader);
  assert.equal(res.status, 200);
  const rows = await res.json();
  assert.equal(rows.length, 1);
  assert.deepEqual(Object.keys(rows[0]).sort(), ["result", "time", "type"]);
  // Records need no trailing newline. Check ownership even when the provider
  // returns a single complete but misplaced object or fails mid-page.
  const one = [...store.keys()].find((k) => k.startsWith("v2/one/"));
  store.set(
    one,
    [...store.values()].find((v) => JSON.parse(v).tenant === "two")
  );
  assert.equal((await read(reader)).status, 502);
  get.mock.mockImplementation(() => {
    throw new Error("private provider error");
  });
  assert.equal(await (await read(reader)).text(), "");
  const provider = t.mock.method(globalThis, "fetch", () =>
    assert.fail("denied analytics fetched provider")
  );
  for (const query of [
    "?f=other",
    "?d=other",
    "?t=1.5",
    "?l=33",
    "?tenant=two",
  ]) {
    assert.equal(
      (await lp.read("analytics", request("/analytics" + query), reader))
        .status,
      400
    );
  }
  assert.equal(
    (await lp.read("analytics", request("/analytics"), row.userAuth)).status,
    403
  );
  assert.equal(provider.mock.callCount(), 0);
  for (const [field, col] of [
    ["type", "blob1"],
    ["result", "blob2"],
  ]) {
    assert.equal(
      reportQuery("SDNS_EVENTS_V2", "one", new URLSearchParams({ f: field })),
      `SELECT ${col} AS category, SUM(_sample_interval) AS n FROM SDNS_EVENTS_V2 WHERE index1 = 'one' AND timestamp > NOW() - INTERVAL '30' MINUTE GROUP BY category ORDER BY n DESC LIMIT 10 FORMAT JSON`
    );
  }
});

test("answer-country metrics follow the served answer, not the requester or an upstream hidden by policy", async (t) => {
  const table = Uint8Array.from([192, 0, 2, 0, 73, 78, 203, 0, 113, 0, 78, 90]); // IN / NZ
  const points = [];
  const history = [];
  env(t, {
    ACCESS_KEYS: (await verifier(key, host)) + "|one|write",
    LOGPUSH_ENABLED: "true",
    LOGPUSH_SRC: host,
    LOGPUSH_HISTORY: "true",
    LOGPUSH_ANALYTICS: "true",
    DNS_HISTORY: { put: async (_, data) => history.push(JSON.parse(data)) },
    METRICS: { writeDataPoint: (point) => points.push(point) },
    GW_IP4: "203.0.113.8",
    GW_IP6: "2001:db8::1",
    GEOIP_URL: "https://geo.example/revision/",
    GEOIP_V4_PIN: `${table.length}:${await digest(table)}`,
  });
  const diagnostics = captureDiagnostics(t);
  globalThis.caches = {
    default: { match: async () => undefined, put: async () => {} },
  };
  const bw = new BlocklistWrapper();
  await bw.install(binary(fixture.td), binary(fixture.rd));
  configureServices(t, bw);
  const bg = [];
  let upstream = 0;
  let downloads = 0;
  const pending = Promise.withResolvers();
  t.mock.method(globalThis, "fetch", async (req) => {
    if (
      req instanceof URL &&
      req.href === "https://geo.example/revision/dbip.v4"
    ) {
      downloads++;
      return (await pending.promise).clone();
    }
    upstream++;
    const query = dns.decodeQuery(await req.arrayBuffer());
    return new Response(
      dns.encode({
        id: query.id,
        questions: query.questions,
        type: "response",
        answers: [a],
      })
    );
  });
  async function send(path) {
    const res = await handleRequest({
      request: request(path, {
        method: "POST",
        body: query,
        headers: {
          "content-type": "application/dns-message",
          "cf-connecting-ip": "203.0.113.99",
          "authorization": "Bearer " + key,
        },
      }),
      waitUntil: (p) => bg.push(p),
    });
    assert.equal(res.status, 200);
    return dns.decode(await res.arrayBuffer()).answers[0].data;
  }
  assert.equal(await send("/dns-query"), a.data);
  await Promise.all(bg);
  assert.equal(downloads, 0); // explicit extra opt-in even for an authorized writer
  wenv.LOGPUSH_ANSWER_COUNTRY = "true";
  assert.equal(await send("/1:AIAAgA"), "0.0.0.0");
  assert.equal(downloads, 0);
  assert.equal(await send("/dns-query"), a.data); // DNS finished while table fetch is still pending
  assert.equal(downloads, 1);
  pending.resolve(new Response(table));
  await Promise.all(bg);
  assert.equal(await send("/gateway"), "203.0.113.8");
  await Promise.all(bg);
  // A rotation with the wrong digest must keep the ordinary metric and reply,
  // not keep reporting from the previously approved generation.
  wenv.GEOIP_V4_PIN = `${table.length}:${"0".repeat(64)}`;
  assert.equal(await send("/dns-query"), a.data);
  await Promise.all(bg);
  assert.equal(upstream, 1); // cache hits are measured after gateway/policy decisions too
  assert.equal(downloads, 2);
  assert.deepEqual(
    points,
    [
      ["A", "answered"],
      ["A", "blocked"],
      ["A", "answered", "IN"],
      ["A", "answered", "NZ"],
      ["A", "answered"],
    ].map((blobs) => ({ indexes: ["one"], blobs }))
  );
  assert.ok(diagnostics.length > 0);
  const logs = diagnostics.join("\n");
  for (const value of [
    a.data,
    a.name,
    "203.0.113.99",
    wenv.GW_IP4,
    wenv.GW_IP6,
    key,
  ]) {
    assert.ok(!logs.includes(value), "raw query data entered diagnostics");
  }
  assert.equal(history.length, 5);
  for (const row of history) {
    assert.deepEqual(Object.keys(row).sort(), [
      "result",
      "tenant",
      "time",
      "type",
    ]);
  }
});

test("country report is opt-in, requires the tenant read grant and only returns country/count pairs", async (t) => {
  env(t, {
    OBSERVABILITY_READS: "true",
    CF_ACCOUNT_ID: "c".repeat(32),
    CF_ANALYTICS_READ_TOKEN: "fixture",
  });
  const lp = new LogPusher();
  const read = (scope, search = "?f=country", partition = "one") =>
    lp.read("analytics", request("/analytics" + search), {
      ok: true,
      scope,
      partition,
    });
  let category = "IN";
  const partitions = [];
  const provider = t.mock.method(globalThis, "fetch", (_, opts) => {
    assert.match(opts.body, /SELECT blob3 AS category/);
    const tenant =
      /WHERE index1 = '(one|two)' AND blob3 != '' AND timestamp/.exec(
        opts.body
      )?.[1];
    assert.ok(tenant);
    partitions.push(tenant);
    return Response.json({
      data: [
        {
          category: tenant === "one" ? category : "DE",
          n: "2",
          private: "not exported",
        },
      ],
    });
  });
  assert.equal((await read("read")).status, 400);
  wenv.LOGPUSH_ANSWER_COUNTRY = "true";
  assert.equal((await read("write")).status, 403);
  assert.equal((await read("read", "?f=country&tenant=other")).status, 400);
  assert.equal(provider.mock.callCount(), 0);
  const res = await read("read");
  assert.equal(res.headers.get("cache-control"), "private, no-store");
  assert.deepEqual(await res.json(), [{ category: "IN", n: 2 }]);
  assert.deepEqual(await (await read("read", "?f=country", "two")).json(), [
    { category: "DE", n: 2 },
  ]);
  assert.deepEqual(partitions, ["one", "two"]);
  category = "192.0.2.9";
  const invalid = await read("read");
  assert.equal(invalid.status, 502);
  assert.equal(await invalid.text(), "");
});

test("EDNS keeps DO, advertised size and non-ECS bytes; options bypass shared answer storage", (t) => {
  env(t);
  const records = new Uint8Array([
    0, 0, 41, 4, 208, 0, 0, 128, 0, 0, 13, 0, 8, 0, 4, 0, 1, 0, 0, 0, 12, 0, 1,
    0,
  ]);
  const wire = new Uint8Array(query.byteLength + records.length);
  wire.set(new Uint8Array(query));
  wire.set(records, query.byteLength);
  new DataView(wire.buffer).setUint16(10, 1);
  const pkt = dns.decodeQuery(wire);
  const keep = dns.stripClientSubnet(wire, pkt);
  const filtered = dns.decodeQuery(keep);
  assert.deepEqual(
    filtered.additionals[0].options.map((x) => x.code),
    [12]
  );
  assert.equal(filtered.additionals[0].udpPayloadSize, 1232);
  assert.equal(dns.hasDnssecOk(filtered), true);
  assert.equal(cacheKey(filtered, "v"), null);
  const onlyOpt = wire.slice(0, query.byteLength + 11);
  new DataView(onlyOpt.buffer).setUint16(onlyOpt.length - 2, 0);
  const doKey = cacheKey(dns.decodeQuery(onlyOpt), "v").href;
  new DataView(onlyOpt.buffer).setUint16(onlyOpt.length - 4, 0);
  assert.notEqual(cacheKey(dns.decodeQuery(onlyOpt), "v").href, doKey);
  const chaos = query.slice(0);
  new DataView(chaos).setUint16(chaos.byteLength - 2, 3);
  assert.throws(() => dns.decodeQuery(chaos));
});

test("private HTTP cache replay enforces negative expiry, CD/view isolation and skips a disabled filter", async (t) => {
  env(t);
  const backing = new Map();
  globalThis.caches = {
    default: {
      put: async (k, r) => backing.set(k, r),
      match: async (k) => backing.get(k)?.clone(),
    },
  };
  const bw = new BlocklistWrapper();
  const stored = new DnsCache(8);
  const key = cacheKey(q, bw.cacheTimestamp());
  const soa = {
    name: "example",
    type: "SOA",
    ttl: 60,
    data: {
      mname: "ns.example",
      rname: "host.example",
      serial: 1,
      refresh: 2,
      retry: 2,
      expire: 20,
      minimum: 4,
    },
  };
  const entry = new UpstreamAnswer(response([], 3, [soa]), q);
  let pending;
  stored.putAnswer(key, entry, {}, (p) => {
    pending = p;
  });
  await pending;
  const cold = new DnsCache(8);
  assert.equal((await cold.getAnswer(key, { ...q, id: 45 })).packet.id, 45);
  const next = { ...q, flags: q.flags | 16 };
  assert.equal(
    await cold.getAnswer(cacheKey(next, bw.cacheTimestamp()), next),
    null
  );
  assert.equal(
    await cold.getAnswer(cacheKey(q, bw.cacheTimestamp(), "different-view"), q),
    null
  );
  // Even an incorrect provider return under a different requested view cannot
  // enter the LFU. The serialized item must bind the same structured key.
  const mixed = cacheKey(next, bw.cacheTimestamp());
  backing.set(mixed.href, backing.get(key.href));
  assert.equal(await cold.getAnswer(mixed, next), null);
  t.mock.method(Date, "now", () => entryTime + 5000);
  function time() {
    return JSON.parse(backing.get(key.href).headers.get("x-sdns-metadata"))
      .time;
  }
  const entryTime = time();
  assert.equal(await cold.getAnswer(key, q), null);
  assert.equal(await new DnsCache(8).getAnswer(key, q), null);
  const cache = {
    getAnswer: () => assert.fail("disabled policy served answer"),
  };
  const disabled = new DNSCacheResponder({ disabled: () => true }, cache);
  assert.equal(
    (await disabled.exec({ isDnsMsg: true, userBlocklistInfo: {} })).data
      .dnsBuffer,
    null
  );
});

test("origin-form DoH binds exactly one HTTP authority", () => {
  const h = {
    "host": "Resolver.Example:443",
    ":authority": "resolver.example",
  };
  assert.equal(
    requestUrl(h, "/dns-query").href,
    "https://resolver.example/dns-query"
  );
  assert.equal(requestUrl({ host: "[::1]:8080" }, "/").hostname, "[::1]");
  assert.throws(() =>
    requestUrl({ ...h, host: "other.example" }, "/dns-query")
  );
  assert.throws(() => requestUrl(h, "https://other.example/dns-query"));
  assert.throws(() => requestUrl(h, "//resolver.example/dns-query"));
});

test("without a native AbortController a deadline cancels a late response body without consuming it", async (t) => {
  let provide;
  let reads = 0;
  let cancelled = 0;
  const res = {
    body: {
      async cancel() {
        cancelled++;
      },
    },
  };
  const descriptor = Object.getOwnPropertyDescriptor(
    globalThis,
    "AbortController"
  );
  Object.defineProperty(globalThis, "AbortController", {
    ...descriptor,
    value: undefined,
  });
  t.after(() =>
    Object.defineProperty(globalThis, "AbortController", descriptor)
  );
  const parent = cancelScope([], 5);
  const child = cancelScope([parent.signal]);
  assert.deepEqual(fetchSignal(child.signal), {});
  const work = openResponse(
    () =>
      new Promise((ok) => {
        provide = ok;
      }),
    child.signal
  ).then(() => {
    reads++;
  });
  await assert.rejects(work);
  provide(res);
  await new Promise((ok) => setImmediate(ok));
  assert.equal(reads, 0);
  assert.equal(cancelled, 1);
  assert.throws(() =>
    openResponse(() => assert.fail("opened after abort"), child.signal)
  );
});
