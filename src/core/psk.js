// SPDX-License-Identifier: MPL-2.0
import { hex2buf } from "../commons/bufutil.js";
// Optional TLS transport optimization, not DNS authorization. Only a fixed,
// externally provisioned credential; no enrollment, identity cache or KDF.
export const identity = "sdns-static-v2";
export function staticPsk(hex) {
  if (hex == null || hex === "") return null;
  if (!/^(?:[a-fA-F0-9]{2}){32,64}$/.test(hex)) {
    throw new Error("TLS_PSK must be 32-64 bytes of hex");
  }
  return hex2buf(hex);
}
