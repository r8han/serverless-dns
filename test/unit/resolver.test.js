// SPDX-License-Identifier: MPL-2.0
import assert from "node:assert/strict";
import {
  setImmediate as tick,
  setTimeout as delay,
} from "node:timers/promises";
import { beforeEach, test } from "node:test";
import { createTrie } from "@serverless-dns/trie/ftrie.js";
import { tagsToFlags } from "@serverless-dns/trie/stamp.js";
import { BlocklistFilter } from "../../src/plugins/rethinkdns/filter.js";
import { fixture } from "./fixture.js";
import * as dns from "../../src/commons/dnsutil.js";
import EnvManager from "../../src/core/env.js";
import Log, { setLogger } from "../../src/core/log.js";
import {
  DNSCacheResponder,
  DNSResolver,
  DnsCache,
} from "../../src/plugins/dns-op/dns-op.js";
import { getB64Flag, unstamp } from "../../src/plugins/rdns-util.js";

setLogger(new Log({ level: "error" }));
const primary = "https://primary.test/dns-query";
const secondary = "https://secondary.test/dns-query";
const name = "listed.example";
const selected = getB64Flag(tagsToFlags([0]), "1");
const other = getB64Flag(tagsToFlags([1]), "1");
const bytes = (b64) => Uint8Array.from(Buffer.from(b64, "base64")).buffer;
const filter = new BlocklistFilter();
filter.load(
  createTrie(bytes(fixture.td), bytes(fixture.rd), fixture.basicconfig),
  fixture.filetag
);
const miss = { getAnswer: async () => null, putPolicy() {}, putAnswer() {} };

// Never let a routing regression turn an offline test into a network request.
beforeEach((t) => {
  t.mock.method(globalThis, "fetch", () => assert.fail("unexpected fetch"));
});

function nodeRuntime(t) {
  const env = new EnvManager();
  env.set("NODE_DOH_ONLY", false, "boolean");
  t.mock.method(env, "get", (key) => env.envMap.get(key));
  globalThis.envManager = env;
  t.after(() => {
    delete globalThis.envManager;
  });
}

function worker(t, vars = {}) {
  globalThis.wenv = {
    CLOUD_PLATFORM: "cloudflare",
    CF_DNS_RESOLVER_URL: primary,
    CF_DNS_RESOLVER_URL_2: "",
    ...vars,
  };
  globalThis.envManager = new EnvManager();
  t.after(() => {
    delete globalThis.wenv;
    delete globalThis.envManager;
    delete globalThis.caches;
  });
}

function wrapper(ready = true) {
  return {
    filter: ready ? filter : null,
    getBlocklistFilter() {
      return this.filter;
    },
    isBlocklistFilterSetup() {
      return Boolean(this.filter);
    },
    async init() {
      this.filter = filter;
    },
    cacheTimestamp: () => fixture.basicconfig.timestamp,
    disabled: () => false,
  };
}

function context(id = 0, stamp = other, domain = name) {
  const questions = [{ name: domain, type: "A" }];
  const raw = dns.mkQ(id, questions);
  return {
    rxid: "test",
    request: new Request("https://client.test/dns-query", {
      method: "POST",
      body: raw,
    }),
    requestBodyBuffer: raw,
    requestDecodedDnsPacket: dns.decode(raw),
    isDnsMsg: true,
    userBlockstamp: stamp,
    userBlocklistInfo: unstamp(stamp),
    dispatcher() {},
  };
}

function reply(query, flags = 0) {
  return dns.encode({
    id: query.id,
    type: "response",
    flags,
    questions: query.questions,
    answers: flags
      ? []
      : [
          {
            name: query.questions[0].name,
            type: "A",
            ttl: 600,
            data: "192.0.2.1",
          },
        ],
  });
}

test("BLOCK_SUBDOMAINS controls child matches, not exact matches", async (t) => {
  worker(t);
  const fetch = t.mock.method(
    globalThis,
    "fetch",
    async (req) => new Response(reply(dns.decode(await req.arrayBuffer())))
  );
  const resolver = new DNSResolver(wrapper(), miss);
  const blocked = async (n) =>
    (await resolver.resolveDns(context(0, selected, n))).isBlocked;
  for (const value of [undefined, "false", "true"]) {
    globalThis.wenv.BLOCK_SUBDOMAINS = value;
    assert.equal(await blocked(name), true);
    assert.equal(await blocked(`child.${name}`), value !== "false");
  }
  assert.equal(fetch.mock.callCount(), 1); // only the child in exact mode
});

test("a shared DNS answer is filtered for each client, including after HTTP cache serialization", async (t) => {
  worker(t);
  const backing = new Map();
  globalThis.caches = {
    default: {
      match: async (k) => backing.get(k)?.clone(),
      put: async (k, v) => backing.set(k, v),
    },
  };
  const cache = new DnsCache(32);
  const bw = wrapper();
  const warm = context(12);
  const fetch = t.mock.method(
    globalThis,
    "fetch",
    async () => new Response(reply(warm.requestDecodedDnsPacket))
  );
  const writes = [];
  warm.dispatcher = (p) => writes.push(p);
  const answer = await new DNSResolver(bw, cache).resolveDns(warm);
  assert.equal(answer.dnsPacket.answers[0].data, "192.0.2.1");
  await Promise.all(writes);
  assert.equal(backing.size, 1);
  // The same name from a different revision must not reuse these flags.
  const otherVersion = new URL(
    [...backing.keys()][0].replace("1706100000000", "1707100000000")
  );
  assert.equal(
    await cache.getAnswer(otherVersion, warm.requestDecodedDnsPacket),
    null
  );

  // Second isolate: no trie and an empty LFU; first hit comes from the Cache API.
  for (const handler of [
    new DNSCacheResponder(bw, cache),
    new DNSCacheResponder(wrapper(false), new DnsCache(32)),
  ]) {
    const denied = await handler.exec(context(27, selected));
    assert.equal(denied.data.isBlocked, true);
    assert.equal(denied.data.flag, selected);
    const allowed = await handler.exec(context(28, other));
    assert.equal(allowed.data.isBlocked, false);
    const packet = dns.decode(allowed.data.dnsBuffer);
    assert.equal(packet.id, 28);
    assert.equal(packet.answers[0].data, "192.0.2.1");
  }
  assert.equal(fetch.mock.callCount(), 1);
});

test("DoH: an HTTP error or an invalid DNS message cannot beat a valid negative answer", async (t) => {
  worker(t, { CF_DNS_RESOLVER_URL_2: secondary });
  const ctx = context();
  const resolver = new DNSResolver(wrapper(), miss);
  for (const first of [
    new Response(null, { status: 503 }),
    new Response("not DNS"),
    new Response(ctx.requestBodyBuffer),
    new Response(reply(ctx.requestDecodedDnsPacket, 2)),
    new Response(reply({ ...ctx.requestDecodedDnsPacket, id: 123 })),
    new Response(
      reply({
        ...ctx.requestDecodedDnsPacket,
        questions: [{ name: "other.example", type: "A" }],
      })
    ),
  ]) {
    const fetch = t.mock.method(globalThis, "fetch", async (req) => {
      if (req.url === primary) return first;
      assert.equal(req.url, secondary);
      await tick();
      return new Response(reply(ctx.requestDecodedDnsPacket, 3)); // NXDOMAIN
    });
    const ans = await resolver.resolveDns(ctx);
    assert.equal(ans.dnsPacket.rcode, "NXDOMAIN");
    assert.equal(ans.dnsPacket.answers.length, 0);
    fetch.mock.restore();
  }
  t.mock.method(
    globalThis,
    "fetch",
    async () => new Response(null, { status: 503 })
  );
  await assert.rejects(resolver.resolveDns(ctx), AggregateError);
});

test("plain DNS: concurrent callers share one exchange but keep their own wire IDs", async (t) => {
  nodeRuntime(t);
  const udpquery = t.mock.fn(async (_rxid, query) => {
    await tick();
    return Buffer.from(reply(dns.decode(query)));
  });
  const resolver = new DNSResolver(wrapper(), miss, { udpquery });
  const resolve = (id) => resolver.resolveDns(context(id));
  const ids = [0x1234, 0, 0x5678];
  const responses = await Promise.all(ids.map(resolve));
  assert.equal(udpquery.mock.callCount(), 1);
  for (const [i, res] of responses.entries()) {
    assert.equal(dns.decode(res.dnsBuffer).id, ids[i]);
  }
  await resolve(10);
  assert.equal(udpquery.mock.callCount(), 2); // nothing left in flight
});

test("a failed coalesced TCP retry does not strand the next plain DNS lookup", async (t) => {
  nodeRuntime(t);
  const udpquery = t.mock.fn(async (_, q) =>
    Buffer.from(reply(dns.decode(q), 0x0200))
  ); // TC
  const tcpquery = t.mock.fn(async (_, q) => Buffer.from(reply(dns.decode(q))));
  tcpquery.mock.mockImplementationOnce(() => {
    throw new Error("TCP unavailable");
  });
  const resolver = new DNSResolver(wrapper(), miss, { udpquery, tcpquery });
  const result = await Promise.allSettled(
    [1, 2].map((id) => resolver.resolveDns(context(id)))
  );
  assert.ok(
    result.every(
      (r) => r.status === "rejected" && r.reason.message === "TCP unavailable"
    )
  );
  const next = await resolver.resolveDns(context(3));
  assert.equal(dns.decode(next.dnsBuffer).id, 3);
  assert.equal(udpquery.mock.callCount(), 2);
  assert.equal(tcpquery.mock.callCount(), 2);
});

test("cold Worker waits for local policy before sending anything", async (t) => {
  worker(t);
  const bw = wrapper(false);
  const ready = Promise.withResolvers();
  bw.init = async () => {
    await ready.promise;
    bw.filter = filter;
  };
  const fetch = t.mock.method(globalThis, "fetch", () =>
    assert.fail("blocked question sent upstream")
  );
  const resolving = new DNSResolver(bw, miss).resolveDns(context(1, selected));
  await tick();
  assert.equal(fetch.mock.callCount(), 0);
  ready.resolve();
  assert.equal((await resolving).isBlocked, true);
  assert.equal(fetch.mock.callCount(), 0);
});

test("expired cold start fails closed even if the download later succeeds", async (t) => {
  worker(t, {
    MAX_DNS_RESOLVER_URL: "not-a-url",
    CF_BLOCKLIST_DOWNLOAD_TIMEOUT: "1",
  });
  const bw = wrapper(false);
  bw.init = async () => {
    await delay(15);
    bw.filter = filter;
  };
  const fetch = t.mock.method(globalThis, "fetch", () =>
    assert.fail("unexpected upstream")
  );
  await assert.rejects(
    new DNSResolver(bw, miss).resolveDns(context()),
    /timeout/
  );
  await delay(20);
  assert.equal(fetch.mock.callCount(), 0);
});

test("local filtering respects the remaining request deadline, not just the download timeout", async (t) => {
  worker(t);
  const ctx = context();
  const bw = wrapper(false);
  const now = Date.now();
  ctx.deadline = now + 100;
  const clock = t.mock.method(Date, "now", () => now);
  bw.init = async () => {
    bw.filter = filter;
    clock.mock.mockImplementation(() => ctx.deadline);
  };
  const fetch = t.mock.method(globalThis, "fetch", () =>
    assert.fail("deadline already reached")
  );
  await assert.rejects(
    new DNSResolver(bw, miss).resolveDns(ctx),
    /unavailable|deadline/
  );
  assert.equal(fetch.mock.callCount(), 0);
});

test("only an explicit HTTPS fallback receives cold queries, with their blockstamp", async (t) => {
  worker(t, { MAX_DNS_RESOLVER_URL: "https://fallback.test/filter" });
  const bw = wrapper(false);
  const ctx = context();
  const init = t.mock.method(bw, "init");
  const bg = t.mock.method(ctx, "dispatcher");
  const fetch = t.mock.method(globalThis, "fetch", async (req) => {
    assert.equal(req.url, `https://fallback.test/filter/${ctx.userBlockstamp}`);
    assert.equal(req.redirect, "manual");
    return new Response(reply(ctx.requestDecodedDnsPacket));
  });
  const cache = {
    get: () => assert.fail("fallback raced shared cache"),
    putAnswer: () => assert.fail("fallback answer cached"),
  };
  await new DNSResolver(bw, cache).resolveDns(ctx);
  assert.equal(fetch.mock.callCount(), 1);
  assert.equal(init.mock.callCount(), 1);
  assert.equal(bg.mock.callCount(), 1);
});

test("mixed answers: later aliases remain blockable on fresh and cached replies even alongside a sinkhole", async (t) => {
  worker(t);
  globalThis.caches = {
    default: { match: async () => undefined, put: async () => {} },
  };
  const unlisted = "ordinary.example";
  const ctx = context(7, selected, unlisted);
  const bw = wrapper();
  const cache = new DnsCache(32);
  const wire = dns.encode({
    id: 7,
    type: "response",
    questions: ctx.requestDecodedDnsPacket.questions,
    answers: [
      { name: unlisted, type: "A", ttl: 50, data: "0.0.0.0" },
      { name: unlisted, type: "A", ttl: 60, data: "192.0.2.7" },
      {
        name: unlisted,
        type: "HTTPS",
        ttl: 40,
        data: { svcPriority: 0, targetName: name, svcParams: {} },
      },
    ],
  });
  const fetch = t.mock.method(
    globalThis,
    "fetch",
    async () => new Response(wire)
  );
  const fresh = await new DNSResolver(bw, cache).resolveDns(ctx);
  assert.equal(fresh.isBlocked, true);
  const cached = new DNSCacheResponder(bw, cache);
  assert.equal(
    (await cached.exec(context(8, selected, unlisted))).data.isBlocked,
    true
  );
  const allowed = (await cached.exec(context(9, other, unlisted))).data;
  assert.equal(allowed.isBlocked, false);
  assert.equal(dns.decode(allowed.dnsBuffer).answers.length, 3);
  assert.equal(fetch.mock.callCount(), 1);
});

test("plain coalescing cancels the transport only when the last waiter leaves", async (t) => {
  nodeRuntime(t);
  let stops = 0;
  let starts = 0;
  const resolver = new DNSResolver(wrapper(), miss, {
    udpquery(_, q, signal) {
      starts++;
      return new Promise((_, reject) =>
        signal.addEventListener(
          "abort",
          () => {
            stops++;
            reject(new Error("aborted"));
          },
          { once: true }
        )
      );
    },
  });
  const a = new AbortController();
  const b = new AbortController();
  const one = resolver.resolveDns({ ...context(7), signal: a.signal });
  const two = resolver.resolveDns({ ...context(8), signal: b.signal });
  a.abort();
  await assert.rejects(one);
  assert.equal(stops, 0);
  b.abort();
  await assert.rejects(two);
  await tick();
  assert.equal(starts, 1);
  assert.equal(stops, 1);
  assert.equal(resolver.pendingQueries.size, 0);
});

test(
  "loopback UDP to fragmented TCP fallback, idle close, disconnect and refused connect clean up",
  { timeout: 5000 },
  async (t) => {
    nodeRuntime(t);
    const { Transport } = await import("../../src/core/node/dns-transport.js");
    const { createSocket } = await import("node:dgram");
    const { createServer } = await import("node:net");
    const { once } = await import("node:events");
    let peer;
    const server = createServer((s) => {
      peer = s;
      let buf = Buffer.alloc(0);
      s.on("data", (b) => {
        buf = Buffer.concat([buf, b]);
        if (buf.length < 2 || buf.length < buf.readUInt16BE(0) + 2) return;
        const body = Buffer.from(reply(dns.decode(buf.subarray(2))));
        const header = Buffer.alloc(2);
        header.writeUInt16BE(body.length);
        s.write(header.subarray(0, 1));
        setImmediate(() => s.write(Buffer.concat([header.subarray(1), body])));
      });
    });
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    const port = server.address().port;
    const udp = createSocket("udp4");
    const tx = new Transport("127.0.0.1", port, {
      connectTimeout: 500,
      ioTimeout: 1000,
      poolSize: 2,
    });
    t.after(() => {
      tx.teardown();
      udp.close();
      peer?.destroy();
      server.close();
    });
    udp.bind(port, "127.0.0.1");
    await once(udp, "listening");
    let receivedId;
    udp.once("message", (q, source) => {
      const packet = dns.decodeQuery(q);
      receivedId = packet.id;
      udp.send(Buffer.from(reply(packet, 0x0200)), source.port, source.address);
    });
    t.mock.method(crypto, "getRandomValues", (bytes) => bytes.fill(17));
    const resolver = new DNSResolver(wrapper(), miss, tx);
    const r = await resolver.resolveDns(context(123));
    assert.equal(receivedId, 0x1111);
    assert.equal(dns.decode(r.dnsBuffer).id, 123);
    assert.equal(tx.tcpconns.idle.size, 1);
    assert.equal(tx.udpconns.idle.size, 1);
    const closed = once([...tx.tcpconns.idle.keys()][0], "close");
    peer.destroy();
    await closed;
    assert.equal(tx.tcpconns.idle.size, 0);
    const ctl = new AbortController();
    const arrival = once(udp, "message");
    const q = Buffer.from(dns.mkQ(87, [{ name, type: "A" }]));
    const pending = tx.udpquery("cancel", q, ctl.signal);
    await arrival;
    ctl.abort();
    await assert.rejects(pending);
    assert.equal(tx.udpconns.idle.size, 0);
    const stopped = once(server, "close");
    server.close();
    await stopped;
    await assert.rejects(tx.tcpquery("refused", q));
    assert.equal(tx.tcpconns.idle.size, 0);
  }
);
