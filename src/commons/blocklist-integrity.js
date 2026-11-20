// SPDX-License-Identifier: MPL-2.0
import { cancelScope, fetchSignal, openResponse } from "./cancel.js";
import { readBounded } from "./bounded.js";

export const files = ["basicconfig.json", "filetag.json", "td.txt", "rd.txt"];
const maxBinary = 192 * 1024 * 1024;
export const maxJson = 4 * 1024 * 1024;
export const jsonBytes = (value) =>
  new TextEncoder().encode(JSON.stringify(value));
export function validVersion(version) {
  if (typeof version !== "string" || !/^20\d\d\/\d{13}$/.test(version)) {
    return false;
  }
  const [year, ms] = version.split("/").map(Number);
  return new Date(ms).getUTCFullYear() === year;
}
export function validateManifest(m, version) {
  if (!validVersion(version) || m?.version !== version || m.codec !== "u6") {
    throw new Error("invalid manifest version/codec");
  }
  for (const name of files) {
    const pin = m.files?.[name];
    const max = name.endsWith(".json") ? maxJson : maxBinary;
    if (
      !pin ||
      !/^[0-9a-f]{64}$/.test(pin.sha256) ||
      !Number.isSafeInteger(pin.size) ||
      pin.size <= 0 ||
      pin.size > max
    ) {
      throw new Error("invalid artifact pin: " + name);
    }
  }
}
export function checkWorkerBlocklistBudget(manifest) {
  const total = manifest.files["td.txt"].size + manifest.files["rd.txt"].size;
  if (total > 48 * 1024 * 1024) {
    throw new Error("Worker blocklist budget exceeded");
  }
}
export async function digest(bytes) {
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return Array.from(hash, (x) => x.toString(16).padStart(2, "0")).join("");
}
export async function verify(bytes, pin) {
  if (bytes.byteLength !== pin.size || (await digest(bytes)) !== pin.sha256) {
    throw new Error("blocklist integrity check failed");
  }
}
export function validateConfig(b, version) {
  if (
    b?.timestamp !== version ||
    b.version !== 1 ||
    b.useCodec6 !== true ||
    !Number.isSafeInteger(b.nodecount) ||
    b.nodecount < 1 ||
    b.nodecount > 2 ** 30 ||
    !/^[0-9a-f]{32}$/.test(b.ftmd5)
  ) {
    throw new Error("invalid basicconfig");
  }
}
export async function fetchArtifact(base, m, name, fetcher = fetch, parent) {
  validateManifest(m, m.version);
  if (!files.includes(name)) throw new Error("unknown artifact");
  const url = new URL(`${base.replace(/\/$/, "")}/${m.version}/u6/${name}`);
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.search ||
    url.hash
  ) {
    throw new Error("invalid blocklist origin");
  }
  const { signal, close } = cancelScope([parent], 30000);
  try {
    const res = await openResponse(
      () => fetcher(url, { redirect: "manual", ...fetchSignal(signal) }),
      signal
    );
    // No range assembly: only an entire 200 representation can be published.
    if (res.status !== 200 || res.headers.has("content-range")) {
      res.body?.cancel().catch(() => {});
      throw new Error("blocklist fetch failed");
    }
    const pin = m.files[name];
    if (name.endsWith(".json")) {
      const item = JSON.parse(
        new TextDecoder().decode(await readBounded(res, maxJson, signal))
      );
      if (name === "basicconfig.json") validateConfig(item, m.version);
      await verify(jsonBytes(item), pin);
      return item;
    }
    const bytes = await readBounded(res, pin.size, signal, true);
    await verify(bytes, pin);
    return bytes;
  } finally {
    close();
  }
}
