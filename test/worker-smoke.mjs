// SPDX-License-Identifier: MPL-2.0
// Execute the actual bundle under workerd; all subrequests are intercepted.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { setTimeout as sleep } from "node:timers/promises";
import { verifier } from "../src/plugins/users/auth-token.js";
import { digest } from "../src/commons/blocklist-integrity.js";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import { mkQ, decode, encode } from "../src/commons/dnsutil.js";
import { fixture } from "./unit/fixture.js";
let lookups = 0;
const script = readFileSync("dist/worker.js", "utf8");
const table = Uint8Array.from([192, 0, 2, 0, 73, 78]); // fixture only
const written = Promise.withResolvers();
// Local Analytics Engine does not persist writes. Substitute just the binding
// at the Worker entrypoint; the application bundle and waitUntil are real.
const metricShim = `import worker from "./bundle.js";
export default {fetch(req, env, ctx) {
  const METRICS = {writeDataPoint(point) {
    return fetch("https://metrics.test/", {method:"POST", body:JSON.stringify(point)});
  }};
  return worker.fetch(req, {...env, METRICS}, ctx);
}};`;
const build = (bindings = {}, captureMetrics = false) =>
  new Miniflare(
    convertV4MiniflareOptions({
      name: "offline-dns",
      ...(captureMetrics
        ? {
            modules: [
              { type: "ESModule", path: "shim.js", contents: metricShim },
              { type: "ESModule", path: "bundle.js", contents: script },
            ],
          }
        : { modules: true, script }),
      compatibilityDate: "2023-03-21",
      bindings: {
        CLOUD_PLATFORM: "cloudflare",
        DNS_CACHE_ENABLED: "true",
        WORKER_ENV: "production",
        DNS_ACCESS_MODE: "public",
        LOG_LEVEL: "error",
        ...bindings,
        CF_BLOCKLIST_URL: "https://fixture.test/",
        CF_DNS_RESOLVER_URL: "https://upstream.test/dns-query",
        CF_DNS_RESOLVER_URL_2: "",
      },
      outboundService: async (req) => {
        const url = new URL(req.url);
        if (captureMetrics && url.href === "https://geo.test/r1/dbip.v4") {
          assert.equal(req.headers.get("authorization"), null);
          return new Response(table);
        }
        if (captureMetrics && url.href === "https://metrics.test/") {
          written.resolve(await req.json());
          return new Response(null);
        }
        if (url.hostname === "fixture.test") {
          const file = url.pathname.split("/").pop();
          assert.ok(["rd.txt", "td.txt"].includes(file));
          return new Response(Buffer.from(fixture[file.slice(0, 2)], "base64"));
        }
        assert.equal(url.hostname, "upstream.test");
        lookups++;
        const q = decode(await req.arrayBuffer());
        return new Response(
          encode({
            id: q.id,
            type: "response",
            questions: q.questions,
            answers: [
              {
                name: q.questions[0].name,
                type: "A",
                ttl: 60,
                data: "192.0.2.10",
              },
            ],
          })
        );
      },
    })
  );
const worker = build();
try {
  for (const [id, path, expected] of [
    [2, "/1:AIAAgA", "0.0.0.0"],
    [1, "/dns-query", "192.0.2.10"],
    [3, "/1:AIAAgA", "0.0.0.0"],
    [4, "/dns-query", "192.0.2.10"],
  ]) {
    const res = await worker.dispatchFetch("https://resolver.test" + path, {
      method: "POST",
      headers: { "content-type": "application/dns-message" },
      body: mkQ(id, [{ name: "listed.example", type: "A" }]),
    });
    assert.equal(res.status, 200);
    const packet = decode(await res.arrayBuffer());
    assert.equal(packet.id, id);
    assert.equal(packet.answers[0]?.data, expected);
  }
  assert.equal(lookups, 1);
} finally {
  await worker.dispose();
}

const invalid = build({ ACCESS_KEYS: "" });
try {
  const res = await invalid.dispatchFetch("https://resolver.test/genaccesskey");
  assert.equal(res.status, 503);
  assert.equal(res.headers.get("cache-control"), "private, no-store");
  assert.equal(lookups, 1);
} finally {
  await invalid.dispose();
}

const bearer = "w".repeat(43); // synthetic, never a real credential
const geo = build(
  {
    DNS_ACCESS_MODE: "private",
    ACCESS_KEYS: (await verifier(bearer, "resolver.test")) + "|demo|write",
    LOGPUSH_SRC: "resolver.test",
    LOGPUSH_ENABLED: "true",
    LOGPUSH_ANALYTICS: "true",
    LOGPUSH_ANSWER_COUNTRY: "true",
    GEOIP_URL: "https://geo.test/r1",
    GEOIP_V4_PIN: `${table.length}:${await digest(table)}`,
  },
  true
);
try {
  const res = await geo.dispatchFetch("https://resolver.test/dns-query", {
    method: "POST",
    headers: {
      "content-type": "application/dns-message",
      "authorization": "Bearer " + bearer,
    },
    body: mkQ(20, [{ name: "listed.example", type: "A" }]),
  });
  assert.equal(decode(await res.arrayBuffer()).answers[0].data, "192.0.2.10");
  const point = await Promise.race([
    written.promise,
    sleep(5000, null, { ref: false }),
  ]);
  assert.deepEqual(point, {
    indexes: ["demo"],
    blobs: ["A", "answered", "IN"],
  });
} finally {
  await geo.dispose();
}
