// SPDX-License-Identifier: MPL-2.0
// Short-lived loopback-only integration test. Requires fixture-built bundle
// (or Deno source graph); never reads a user's configured secrets or upstreams.
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { once } from "node:events";
import {
  chmod,
  mkdtemp,
  mkdir,
  rm,
  readFile,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { connect } from "node:tls";
import { request } from "node:http";
import { setTimeout as delay } from "node:timers/promises";
import { fixture } from "./unit/fixture.js";
import { mkQ, decode } from "../src/commons/dnsutil.js";
import { verifier } from "../src/plugins/users/auth-token.js";
import { generationDir } from "../src/core/node/artifact-file.js";

const runtime = process.argv[2] || "node";
assert.ok(["node", "bun", "deno"].includes(runtime));
const executable = process.argv[3] || runtime;
const cwd = await mkdtemp(join(tmpdir(), "sdns-ingress-"));
const dir = generationDir(
  join(cwd, "blocklists__"),
  fixture.basicconfig.timestamp
);
const testCrt = resolve("test/data/tls/dns.rethinkdns.localhost.crt");
const tempCrt = join(cwd, "ephemeral.crt");
const tempKey = join(cwd, "ephemeral.key");
const testKey = resolve("test/data/tls/dns.rethinkdns.localhost.key");
const denoApp = process.env.DENO_APP_DIR || ".";
const args =
  runtime === "deno"
    ? [
        "run",
        ...(process.env.DENO_APP_DIR
          ? ["--no-remote", "--no-npm"]
          : ["--cached-only"]),
        "--no-lock",
        "--config",
        resolve(denoApp, "deno.json"),
        "--allow-read",
        "--allow-net=127.0.0.1",
        "--allow-env",
        resolve(denoApp, "src/server-deno.ts"),
      ]
    : [resolve("dist", runtime === "bun" ? "bun.mjs" : "fly.mjs")];
const bearer = "b".repeat(43);
const host = "dns.rethinkdns.localhost";
const query = Buffer.from(mkQ(30, [{ name: "listed.example", type: "A" }]));
const base = {
  PATH: process.env.PATH,
  HOME: process.env.HOME,
  CLOUD_PLATFORM: "standalone",
  NODE_ENV: "production",
  BUN_ENV: "production",
  DENO_ENV_DOMAIN: "production",
  DENO_NO_UPDATE_CHECK: "1",
  TLS_CRT_PATH: testCrt,
  TLS_KEY_PATH: testKey,
  LOG_LEVEL: "info",
  TLS_BIND: "127.0.0.1",
  CF_DNS_RESOLVER_URL: "https://127.0.0.1:1/not-an-upstream",
  CF_BLOCKLIST_URL: "https://127.0.0.1:1/not-a-store",
};
if (process.env.DENO_DIR) base.DENO_DIR = process.env.DENO_DIR;
async function launch(vars, fn) {
  const p = spawn(executable, args, {
    cwd,
    env: { ...base, ...vars },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  const collect = (d) => {
    output = (output + d.toString()).slice(-8192);
  };
  p.stdout.on("data", collect);
  p.stderr.on("data", collect);
  const exit = once(p, "exit");
  const stop = setTimeout(() => p.kill("SIGKILL"), 10000);
  try {
    if (!fn) {
      const [code] = await exit;
      assert.ok(
        code > 0 && !/listening on:|Listening on http/i.test(output),
        "configuration should fail before listen"
      );
      return;
    }
    await new Promise((yes, no) => {
      const check = () => {
        if (/listening on:|up DoH|Listening on http/.test(output)) {
          p.stdout.off("data", check);
          p.stderr.off("data", check);
          yes();
        }
      };
      p.stdout.on("data", check);
      p.stderr.on("data", check);
      exit.then(() => no(new Error("exited before listening: " + output)), no);
    });
    await fn();
    assert.ok(!output.includes(bearer));
  } finally {
    clearTimeout(stop);
    if (p.exitCode === null && p.signalCode === null) {
      p.kill("SIGKILL");
      await exit;
    }
  }
}
function post(authorized = false) {
  return new Promise((yes, no) => {
    const req = request(
      {
        hostname: "127.0.0.1",
        port: 8055,
        path: "/1:AIAAgA",
        method: "POST",
        headers: {
          host,
          "content-type": "application/dns-message",
          ...(authorized ? { authorization: "Bearer " + bearer } : {}),
        },
        signal: AbortSignal.timeout(3000),
      },
      (res) => {
        const chunks = [];
        res.on("data", (b) => chunks.push(b));
        res.on("end", () => yes([res, Buffer.concat(chunks)]));
        res.on("error", no);
      }
    );
    req.on("error", no);
    req.end(query);
  });
}
const fakePsk = Buffer.alloc(32, 17);
async function dot(usePsk = false) {
  const framed = Buffer.concat([Buffer.from([0, query.length]), query]);
  const socket = connect({
    host: "127.0.0.1",
    port: 10000,
    servername: "1-acaabaa." + host,
    ca: await readFile(tempCrt),
    ...(usePsk
      ? {
          maxVersion: "TLSv1.2",
          ciphers: "PSK-AES128-GCM-SHA256",
          pskCallback: () => ({ identity: "sdns-static-v2", psk: fakePsk }),
          checkServerIdentity: () => undefined,
        }
      : {}),
  });
  const stop = setTimeout(() => socket.destroy(new Error("DoT timeout")), 3000);
  try {
    await once(socket, "secureConnect");
    if (usePsk) assert.match(socket.getCipher().name, /PSK/);
    socket.write(framed.subarray(0, 1));
    await delay(10);
    const second = Buffer.from(framed);
    second.writeUInt16BE(31, 2);
    socket.write(Buffer.concat([framed.subarray(1), second]));
    let bytes = Buffer.alloc(0);
    const ids = [];
    for await (const chunk of socket) {
      bytes = Buffer.concat([bytes, chunk]);
      while (bytes.length >= 2 && bytes.length >= 2 + bytes.readUInt16BE(0)) {
        const end = 2 + bytes.readUInt16BE(0);
        const packet = decode(bytes.subarray(2, end));
        ids.push(packet.id);
        assert.equal(packet.answers[0]?.data, "0.0.0.0");
        bytes = bytes.subarray(end);
      }
      if (ids.length >= 2) break;
    }
    assert.deepEqual(ids, [30, 31]);
  } finally {
    clearTimeout(stop);
    socket.destroy();
  }
}
try {
  await mkdir(dir, { recursive: true });
  for (const name of ["rd", "td"]) {
    await writeFile(
      join(dir, name + ".txt"),
      Buffer.from(fixture[name], "base64"),
      { mode: 0o444 }
    );
  }
  // The unprivileged listener cannot repair or replace its fixture inputs.
  await chmod(dir, 0o555);
  await chmod(join(cwd, "blocklists__"), 0o555);
  await launch({
    TLS_MODE: "terminate",
    TLS_CRT_PATH: join(cwd, "missing.crt"),
  });
  await launch({ TLS_MODE: "terminate" }); // reject public fixture identity in production
  await launch({ TLS_MODE: "offload", ACCESS_KEYS: "" });
  await launch(
    { TLS_MODE: "offload", ACCESS_KEYS: await verifier(bearer, host) },
    async () => {
      assert.equal((await post())[0].statusCode, 401);
      const [res, body] = await post(true);
      assert.equal(res.statusCode, 200);
      assert.equal(res.headers["cache-control"], "private, no-store");
      assert.equal(decode(body).answers[0]?.data, "0.0.0.0");
    }
  );
  execFileSync(
    "openssl",
    [
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-days",
      "1",
      "-subj",
      "/CN=" + host,
      "-addext",
      "subjectAltName=DNS:" + host + ",DNS:*." + host,
      "-keyout",
      tempKey,
      "-out",
      tempCrt,
    ],
    { stdio: "ignore" }
  );
  await launch(
    {
      TLS_KEY_PATH: tempKey,
      TLS_CRT_PATH: tempCrt,
      TLS_MODE: "terminate",
      TLS_BIND: "127.0.0.1",
      DOT_POLICY: "1:AIAAgA",
      ...(runtime === "node" ? { TLS_PSK: fakePsk.toString("hex") } : {}),
    },
    async () => {
      await dot();
      if (runtime === "node") await dot(true);
    }
  );
  console.log(
    runtime +
      ": production rejection, authenticated offload and pipelined/fragmented local TLS passed"
  );
} finally {
  await chmod(dir, 0o700).catch(() => {});
  await chmod(join(cwd, "blocklists__"), 0o700).catch(() => {});
  await rm(cwd, { recursive: true, force: true });
}
