// SPDX-License-Identifier: MPL-2.0
// Build-only, Linux x86-64. Never install a runtime or run a postinstall hook
// with a deployment token. Extract one known file after integrity verification.
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { readBounded } from "../src/commons/bounded.js";
const nodeVersion = readFileSync(
  new URL("../.node-version", import.meta.url),
  "utf8"
).trim();
const pins = {
  node: [
    `node-linux-x64/-/node-linux-x64-${nodeVersion}.tgz`,
    "PCkqT4dt05O59VMEPf1K1gG5wNuTom335o1D+603YoLJ/sZvofq3CzKZKmaaNjAImwYtBQH7twPwXYM0nViCXQ==",
    "package/bin/node",
  ],
  bun: [
    "@oven/bun-linux-x64/-/bun-linux-x64-1.4.5.tgz",
    "IWX9BELoGHAUtMonkeSaNaZwXzRk+oDw6Mk+HBFXd3KHYIBNBsIGRupMZPcgNoDbJpLu6gAJjIoIVPZtt1aJ1g==",
    "package/bin/bun",
  ],
};
const name = process.argv[2];
if (
  process.platform !== "linux" ||
  process.arch !== "x64" ||
  !Object.hasOwn(pins, name)
) {
  throw new Error("unsupported build platform");
}
const [path, hash, member] = pins[name];
const signal = AbortSignal.timeout(120000);
const r = await fetch("https://registry.npmjs.org/" + path, {
  redirect: "error",
  signal,
});
if (!r.ok) throw new Error("runtime download failed");
const tar = Buffer.from(await readBounded(r, 128 * 1024 * 1024, signal));
if (createHash("sha512").update(tar).digest("base64") !== hash) {
  throw new Error("unverified runtime");
}
const bin = execFileSync("tar", ["-xzOf", "-", member], {
  input: tar,
  maxBuffer: 256 * 1024 * 1024,
});
const out = (process.argv[3] || "/usr/local/bin") + "/" + name;
writeFileSync(out, bin, { flag: "wx", mode: 0o755 });
