// SPDX-License-Identifier: MPL-2.0
import { fromStr, hex, hex2buf } from "../../commons/bufutil.js";
import { hmackey, hmacsign, hmacverify } from "../../commons/crypto.js";

const context = fromStr("sdns-header-auth-v2");
const validBearer = /^[a-zA-Z0-9_-]{43,128}$/;
export const validPartition = /^[a-z0-9][a-z0-9_-]{0,31}$/;
function host(name) {
  return (
    typeof name === "string" &&
    name.length <= 253 &&
    name
      .split(".")
      .every((s) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(s))
  );
}

export function credentials(config) {
  // Unset is public DNS; present but malformed (even empty) is never public.
  if (config == null) return [];
  const entries = config.split(",");
  if (entries.length > 64) throw new Error("too many access keys");
  const seen = new Set();
  return entries.map((entry) => {
    const fields = entry.trim().split("|");
    const [domain, digest, partition, scope = "dns"] = fields;
    if (
      !host(domain) ||
      !/^[0-9a-f]{64}$/.test(digest || "") ||
      !(
        fields.length === 2 ||
        (fields.length === 4 &&
          validPartition.test(partition) &&
          ["write", "read"].includes(scope))
      ) ||
      seen.has(digest)
    ) {
      throw new Error("invalid ACCESS_KEYS configuration");
    }
    seen.add(digest);
    return { domain, mac: hex2buf(digest), partition, scope };
  });
}

function key(bearer, domain) {
  if (!host(domain) || !validBearer.test(bearer)) {
    throw new Error("invalid credential format");
  }
  return hmackey(fromStr(`${bearer}|${domain}`));
}

export async function verifier(bearer, domain) {
  return `${domain}|${hex(await hmacsign(await key(bearer, domain), context))}`;
}

export async function selfTest() {
  const k = await hmackey(new Uint8Array(20).fill(11));
  const msg = fromStr("Hi There");
  const mac = await hmacsign(k, msg);
  if (
    hex(mac) !==
      "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7" ||
    !(await hmacverify(k, mac, msg))
  ) {
    throw new Error("HMAC self-test failed");
  }
}

export async function auth(request, entries) {
  if (!entries.length) return { ok: true, scope: "public" };
  const domain = new URL(request.url).hostname.toLowerCase();
  const match = /^Bearer ([a-zA-Z0-9_-]{43,128})$/i.exec(
    request.headers.get("authorization") || ""
  );
  if (match && host(domain)) {
    const ck = await key(match[1], domain);
    for (const entry of entries) {
      if (
        entry.domain === domain &&
        (await hmacverify(ck, entry.mac, context))
      ) {
        return { ok: true, partition: entry.partition, scope: entry.scope };
      }
    }
  }
  return { ok: false };
}
