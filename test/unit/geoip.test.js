// SPDX-License-Identifier: MPL-2.0
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { firstAnswerAddress } from "../../src/commons/dns-wire.js";
import { encode } from "../../src/commons/dnsutil.js";
import { GeoIP } from "../../src/plugins/observability/geoip.js";

const pin = (b) =>
  `${b.length}:${createHash("sha256").update(b).digest("hex")}`;
const addr = (...b) => Uint8Array.from(b);
const record = (bytes, cc) => Buffer.concat([bytes, Buffer.from(cc)]);
const ip4 = addr(192, 0, 2, 0);
const ip6 = Buffer.from("20010db8000000000000000000000000", "hex");
const v4 = Buffer.concat([
  record(ip4, "IN"),
  record(addr(192, 0, 2, 128), "NZ"),
  record(addr(192, 0, 3, 0), "ZZ"),
]);
const v6 = Buffer.concat([
  record(ip6, "DE"),
  record(Buffer.from("20010db8000100000000000000000000", "hex"), "JP"),
]);
const config = () =>
  new Map(
    Object.entries({
      GEOIP_URL: "https://tables.example/approved",
      GEOIP_V4_PIN: pin(v4),
      GEOIP_V6_PIN: pin(v6),
    })
  );
const name = "app.example";
const rr = (type, data) => ({ name, type, ttl: 300, data });
const wire = (answers, more = {}) =>
  encode({
    id: 12,
    type: "response",
    questions: [{ name, type: "A" }],
    answers,
    ...more,
  });

test("country input is just the first address from the served, successful Answer section", () => {
  const a = rr("A", "192.0.2.9");
  const aaaa = rr("AAAA", "2001:db8::beef");
  const cname = rr("CNAME", "203.0.113.1");
  assert.deepEqual(
    firstAnswerAddress(wire([cname, a, aaaa])),
    addr(192, 0, 2, 9)
  );
  const hint = (type, targetName, svcPriority = 1) =>
    rr(type, {
      targetName,
      svcPriority,
      svcParams: { ipv6hint: ["2001:db8::beef"] },
    });
  for (const type of ["SVCB", "HTTPS"]) {
    assert.deepEqual(
      firstAnswerAddress(wire([hint(type, "."), a])),
      firstAnswerAddress(wire([aaaa]))
    );
    assert.equal(firstAnswerAddress(wire([hint(type, "other.example")])), null);
    assert.equal(firstAnswerAddress(wire([hint(type, ".", 0)])), null);
  }
  const bytes = Buffer.from(wire([cname, aaaa, a]));
  const view = Buffer.concat([Buffer.alloc(7), bytes]).subarray(7);
  assert.equal(
    Buffer.from(firstAnswerAddress(view)).toString("hex"),
    "20010db800000000000000000000beef"
  );
  assert.equal(
    firstAnswerAddress(
      wire([cname], { authorities: [a], additionals: [aaaa] })
    ),
    null
  );
  assert.equal(firstAnswerAddress(wire([a], { flags: 0x0200 })), null);
  assert.equal(firstAnswerAddress(wire([a], { flags: 3 })), null);
  assert.equal(firstAnswerAddress(null), null);
});

test("GeoIP uses fixed table URLs and inclusive network-byte boundaries; it reuses only verified tables", async (t) => {
  const geo = new GeoIP();
  const env = config();
  const urls = [];
  t.mock.method(globalThis, "fetch", (url, opts) => {
    urls.push(url.href);
    assert.equal(opts.redirect, "manual");
    assert.equal(opts.headers, undefined);
    return new Response(url.pathname.endsWith(".v4") ? v4 : v6);
  });
  assert.equal(await geo.country(addr(0, 0, 0, 0), env), null);
  assert.equal(await geo.country(new Uint8Array(16), env), null);
  assert.equal(urls.length, 0);
  for (const [ip, expected] of [
    [addr(1, 2, 3, 4), null],
    [ip4, "IN"],
    [addr(192, 0, 2, 127), "IN"],
    [addr(192, 0, 2, 128), "NZ"],
    [addr(192, 0, 3, 5), null],
    [ip6, "DE"],
    [Buffer.from("20010db8000100000000000000000001", "hex"), "JP"],
  ]) {
    assert.equal(await geo.country(ip, env), expected);
  }
  assert.deepEqual(urls, [
    "https://tables.example/approved/dbip.v4",
    "https://tables.example/approved/dbip.v6",
  ]);
  // Changing to an unverified generation must not return a stale country.
  env.set("GEOIP_V4_PIN", `6:${"0".repeat(64)}`);
  assert.equal(await geo.country(ip4, env), null);
  assert.equal(urls.length, 3);
});

test("GeoIP refuses unsafe configuration and incomplete, unverified or malformed tables", async (t) => {
  const env = config();
  const fetcher = t.mock.method(globalThis, "fetch", () => new Response(v4));
  for (const badUrl of [
    "",
    "relative",
    "http://tables.test/",
    "https://user@tables.test/",
    "https://tables.test/?x=y",
    "https://tables.test/#a",
  ]) {
    env.set("GEOIP_URL", badUrl);
    assert.equal(await new GeoIP().country(ip4, env), null);
  }
  env.set("GEOIP_URL", "https://tables.test/");
  for (const bad of [
    "",
    "0:bad",
    `7:${"0".repeat(64)}`,
    `18000000:${"0".repeat(64)}`,
  ]) {
    env.set("GEOIP_V4_PIN", bad);
    assert.equal(await new GeoIP().country(ip4, env), null);
  }
  assert.equal(fetcher.mock.callCount(), 0);
  const unsorted = Buffer.concat([record(ip4, "IN"), record(ip4, "DE")]);
  const badCode = record(ip4, "i!");
  for (const [expected, response] of [
    [v4, () => new Response(v4.subarray(1))],
    [v4, () => new Response(Buffer.concat([v4, addr(0)]))],
    [v4, () => new Response(Buffer.alloc(v4.length))],
    [v4, () => new Response(v4, { status: 206 })],
    [
      v4,
      () => new Response(v4, { headers: { "content-range": "bytes 0-17/50" } }),
    ],
    [v4, () => Response.redirect("https://elsewhere.test/")],
    [unsorted, () => new Response(unsorted)],
    [badCode, () => new Response(badCode)],
  ]) {
    const geo = new GeoIP();
    env.set("GEOIP_V4_PIN", pin(expected));
    fetcher.mock.mockImplementation(response);
    const before = fetcher.mock.callCount();
    assert.equal(await geo.country(ip4, env), null);
    assert.equal(await geo.country(ip4, env), null);
    assert.equal(
      fetcher.mock.callCount(),
      before + 1,
      "back off after failure"
    );
  }
});

test("a cold concurrent request neither blocks on another request's I/O nor starts another download", async (t) => {
  const env = config();
  const geo = new GeoIP();
  const pending = Promise.withResolvers();
  const fetcher = t.mock.method(globalThis, "fetch", () => pending.promise);
  const first = geo.country(ip4, env);
  assert.equal(await geo.country(ip4, env), null);
  assert.equal(fetcher.mock.callCount(), 1);
  pending.resolve(new Response(v4));
  assert.equal(await first, "IN");
  assert.equal(await geo.country(ip4, env), "IN");
  assert.equal(fetcher.mock.callCount(), 1);
});

test("the offline CSV provisioner preserves inclusive ends and gaps in both families", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "sdns-country-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const csv = join(dir, "ranges.csv");
  const output = join(dir, "revision");
  const convert = (dest) =>
    spawnSync("python3", ["scripts/geoip-tables.py", csv, dest], {
      encoding: "utf8",
    });
  writeFileSync(
    csv,
    "192.0.2.1,192.0.2.2,IN\n192.0.2.4,192.0.2.5,NZ\n2001:db8::1,2001:db8::ffff,DE\n"
  );
  const build = convert(output);
  if (build.error?.code === "ENOENT") {
    return t.skip("CSV conversion requires Python 3");
  }
  assert.equal(build.status, 0, build.stderr);
  const env = config();
  for (const family of [4, 6]) {
    const bytes = readFileSync(join(output, "dbip.v" + family));
    const key = `GEOIP_V${family}_PIN`;
    assert.ok(build.stdout.split("\n").includes(`${key}=${pin(bytes)}`));
    env.set(key, pin(bytes));
  }
  t.mock.method(
    globalThis,
    "fetch",
    (url) =>
      new Response(readFileSync(join(output, url.pathname.split("/").pop())))
  );
  const geo = new GeoIP();
  for (const [address, cc] of [
    ["192.0.2.0", null],
    ["192.0.2.1", "IN"],
    ["192.0.2.2", "IN"],
    ["192.0.2.3", null],
    ["192.0.2.4", "NZ"],
    ["192.0.2.6", null],
    ["2001:db8::1", "DE"],
    ["2001:db8::ffff", "DE"],
    ["2001:db8::1:0", null],
  ]) {
    const rdata = firstAnswerAddress(
      wire([rr(address.includes(":") ? "AAAA" : "A", address)])
    );
    assert.equal(await geo.country(rdata, env), cc);
  }
  assert.notEqual(convert(output).status, 0); // version directories are immutable
  writeFileSync(csv, "192.0.2.1,192.0.2.12,IN\n192.0.2.9,192.0.2.15,DE\n");
  assert.notEqual(convert(join(dir, "bad")).status, 0);
});
