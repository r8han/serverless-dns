// SPDX-License-Identifier: MPL-2.0
import { spawnSync } from "node:child_process";
import { stat } from "node:fs/promises";
import { verifier } from "../../src/plugins/users/auth-token.js";
import assert from "node:assert/strict";
import { fixture as lists, fixtureMetadata } from "./fixture.js";
import {
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { generationDir } from "../../src/core/node/artifact-file.js";
import { prepareMetadata } from "../../scripts/metadata.mjs";

const first = lists.basicconfig.timestamp;
const next = "2024/1707100000000";
const filetag = lists.filetag;
function fixture(timestamp) {
  return fixtureMetadata(timestamp);
}

test("metadata preparation is pinned, validates both files and publishes them atomically", async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "sdns-metadata-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const output = join(dir, "metadata.json");
  const base = "https://store.test/blocklists";
  async function prepare(version, tagResponse = () => Response.json(filetag)) {
    await prepareMetadata({
      version,
      manifest: fixture(version).manifest,
      output,
      base,
      fetcher: async (url) => {
        if (url.href === `${base}/${version}/u6/basicconfig.json`) {
          return Response.json(fixture(version).basicconfig);
        }
        assert.equal(url.href, `${base}/${version}/u6/filetag.json`);
        return tagResponse();
      },
    });
  }
  await prepare(first);
  const original = await readFile(output, "utf8");
  assert.deepEqual(JSON.parse(original), fixture(first));
  await prepareMetadata({
    version: first,
    manifest: fixture(first).manifest,
    output,
    fetcher: () => assert.fail("cache hit made a request"),
  });

  for (const bad of [
    () => new Response(null, { status: 404 }),
    () => new Response("{"),
    () => Response.json({ OTHER: { value: 43 } }), // valid JSON from a different revision
  ]) {
    await assert.rejects(prepare(next, bad));
    assert.equal(await readFile(output, "utf8"), original);
  }
  for (const fields of [
    { timestamp: first },
    { useCodec6: false },
    { nodecount: 0 },
  ]) {
    await assert.rejects(
      prepareMetadata({
        version: next,
        manifest: fixture(next).manifest,
        output,
        fetcher: async () =>
          Response.json({ ...fixture(next).basicconfig, ...fields }),
      }),
      /invalid basicconfig/
    );
    assert.equal(await readFile(output, "utf8"), original);
  }
  await writeFile(
    output,
    JSON.stringify({ basicconfig: fixture(next).basicconfig })
  );
  await prepare(next); // same version but partial local metadata is not a hit
  assert.deepEqual(JSON.parse(await readFile(output, "utf8")), fixture(next));
});

test("asset preparation publishes complete read-only generations before metadata, with no writes through links", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "sdns-assets-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const output = join(root, "metadata.json");
  const assets = join(root, "assets");
  async function stage(version, failOn) {
    const m = fixture(version);
    await prepareMetadata({
      version,
      manifest: m.manifest,
      output,
      assets,
      fetcher: async (url) => {
        const name = url.pathname.split("/").at(-1);
        if (name === failOn) throw new Error("interrupted");
        if (name === "basicconfig.json") return Response.json(m.basicconfig);
        if (name === "filetag.json") return Response.json(m.filetag);
        return new Response(Buffer.from(lists[name.split(".")[0]], "base64"));
      },
    });
  }
  const g = (version) => generationDir(assets, version);
  await stage(first);
  const prev = await readFile(output, "utf8");
  await assert.rejects(stage(next, "td.txt"), /interrupted/);
  assert.equal(await readFile(output, "utf8"), prev);
  assert.deepEqual(await readdir(assets), [first.replace("/", "-")]);
  assert.deepEqual(
    await readFile(join(g(first), "td.txt")),
    Buffer.from(lists.td, "base64")
  );
  await stage(next);
  await assert.rejects(stage(first), /downgrade/);
  const saved = await readFile(output, "utf8");
  const original = join(g(next), "td.txt");
  const target = join(root, "protected");
  await rename(original, target);
  await symlink(target, original);
  await assert.rejects(stage(next), /unexpected blocklist path/);
  assert.equal(await readFile(output, "utf8"), saved);
  assert.deepEqual(await readFile(target), Buffer.from(lists.td, "base64"));
});

test("offline issuer creates a private new bearer file, never prints or overwrites it", async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "sdns-issuer-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const out = join(dir, "client");
  const host = "resolver.example";
  const issue = () =>
    spawnSync(process.execPath, ["scripts/access-key.mjs", host, out], {
      encoding: "utf8",
    });
  const r = issue();
  assert.equal(r.status, 0);
  const key = (await readFile(out, "utf8")).trim();
  assert.match(key, /^[A-Za-z0-9_-]{43}$/);
  const expected = await verifier(key, host);
  assert.ok(r.stdout.includes(expected));
  assert.ok(!r.stdout.includes(key));
  assert.equal((await stat(out)).mode & 0o777, 0o600);
  assert.notEqual(issue().status, 0);
  assert.equal((await readFile(out, "utf8")).trim(), key);
});
