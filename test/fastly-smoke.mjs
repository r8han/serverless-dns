// SPDX-License-Identifier: MPL-2.0
// Run the compiled WASM with no credentials or public backends.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { decode, mkQ } from "../src/commons/dnsutil.js";
const dir = await mkdtemp(join(tmpdir(), "sdns-fastly-"));
const url = "http://127.0.0.1:7676";
const config = join(dir, "fastly.toml");
await writeFile(
  config,
  `manifest_version = 2\nname = "offline"\n[local_server.dictionaries.env]\nformat = "inline-toml"\n[local_server.dictionaries.env.contents]\nCLOUD_PLATFORM = "fastly"\nFASTLY_ENV = "production"\nDISABLE_BLOCKLISTS = "true"\nCF_DNS_RESOLVER_URL = "https://127.0.0.1:1/dns-query"\n`
);
const proc = spawn(
  process.argv[2] || "viceroy",
  [
    "serve",
    "--addr",
    "127.0.0.1:7676",
    "-C",
    config,
    resolve("dist/fastly.wasm"),
  ],
  { stdio: ["ignore", "inherit", "inherit"] }
);
// Viceroy compiles the module before it listens. Cold CI runners can take
// longer than a request deadline. Retry only connections refused at startup,
// never a timeout, an HTTP error, or a failed Wasm response.
const closed = new Promise((resolve) => proc.once("close", resolve));
try {
  await once(proc, "spawn");
  const deadline = performance.now() + 60000;
  let r;
  for (;;) {
    if (proc.exitCode !== null || proc.signalCode !== null) {
      throw new Error(
        `Viceroy exited before listening: ${proc.signalCode ?? proc.exitCode}`
      );
    }
    try {
      r = await fetch(url + "/genaccesskey", {
        signal: AbortSignal.timeout(3000),
      });
      break;
    } catch (e) {
      if (e.cause?.code !== "ECONNREFUSED") throw e;
      if (performance.now() >= deadline) {
        throw new Error("Viceroy did not listen within 60s", { cause: e });
      }
      await delay(250);
    }
  }
  assert.equal(r.status, 410);
  assert.equal(r.headers.get("cache-control"), "private, no-store");
  const q = mkQ(14, [{ name: "listed.example", type: "A" }]);
  const failed = await fetch(url + "/1:AIAAgA", {
    method: "POST",
    body: q,
    headers: { "content-type": "application/dns-message" },
    signal: AbortSignal.timeout(5000),
  });
  assert.equal(failed.status, 200);
  const packet = decode(await failed.arrayBuffer());
  assert.equal(packet.id, 14);
  assert.equal(packet.rcode, "SERVFAIL");
} finally {
  if (proc.exitCode === null && proc.signalCode === null) proc.kill("SIGKILL");
  await closed;
  await rm(dir, { recursive: true, force: true });
}
