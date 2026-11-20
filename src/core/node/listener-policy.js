// SPDX-License-Identifier: MPL-2.0
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  X509Certificate,
} from "node:crypto";
import { isIP } from "node:net";

// Do not infer a trusted edge from NODE_ENV or from a missing certificate.
// Offload addresses must be literal private IPs.
/** @param {{production:boolean, platform?:string, mode?:string, privateBind?:string, tlsBind?:string}} options */
export function listenerPolicy({
  production,
  platform,
  mode,
  privateBind,
  tlsBind = undefined,
}) {
  if (!production) {
    mode ||= "terminate";
    platform ||= "local";
  }
  if (
    !["local", "fly", "standalone"].includes(platform) ||
    !["terminate", "offload"].includes(mode)
  ) {
    throw new Error("explicit CLOUD_PLATFORM and TLS_MODE required");
  }
  if (mode === "terminate") {
    const host = tlsBind || (production ? "::" : "127.0.0.1");
    if (!isIP(host)) throw new Error("TLS_BIND must be a literal address");
    return { mode, host };
  }
  const ip = privateBind || "127.0.0.1";
  const local =
    isIP(ip) === 4
      ? /^(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)/.test(ip)
      : isIP(ip) === 6 && (ip === "::1" || /^f[cd]/i.test(ip));
  if (!local) throw new Error("offload requires private literal bind address");
  return { mode, host: ip };
}

export function validateIdentity(key, cert, production) {
  const x509 = new X509Certificate(cert);
  if (
    production &&
    (Date.parse(x509.validFrom) > Date.now() ||
      Date.parse(x509.validTo) <= Date.now())
  ) {
    throw new Error("TLS identity outside validity period");
  }
  const format = { type: "spki", format: "der" };
  const spki = x509.publicKey.export(format);
  if (!spki.equals(createPublicKey(createPrivateKey(key)).export(format))) {
    throw new Error("certificate/key mismatch");
  }
  if (
    production &&
    createHash("sha256").update(spki).digest("hex") ===
      "9c13c8edd866c8056449da40d48c85587b40103507ca2f3d05c40bb19ee1f1ff"
  ) {
    throw new Error("development TLS identity forbidden");
  }
}
