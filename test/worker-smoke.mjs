// SPDX-License-Identifier: MPL-2.0
// Execute the actual bundle under workerd; all subrequests are intercepted.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import { mkQ, decode, encode } from "../src/commons/dnsutil.js";
import { fixture } from "./unit/fixture.js";
let lookups = 0;
const build = (bindings = {}) =>
  new Miniflare(
    convertV4MiniflareOptions({
      name: "offline-dns",
      modules: true,
      script: readFileSync("dist/worker.js", "utf8"),
      compatibilityDate: "2023-03-21",
      bindings: {
        CLOUD_PLATFORM: "cloudflare",
        WORKER_ENV: "production",
        LOG_LEVEL: "error",
        ...bindings,
        CF_BLOCKLIST_URL: "https://fixture.test/",
        CF_DNS_RESOLVER_URL: "https://upstream.test/dns-query",
        CF_DNS_RESOLVER_URL_2: "",
      },
      outboundService: async (req) => {
        const url = new URL(req.url);
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
