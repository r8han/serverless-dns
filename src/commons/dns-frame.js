// SPDX-License-Identifier: MPL-2.0
import { validateSize } from "./dnsutil.js";
async function exact(conn, bytes) {
  for (let i = 0; i < bytes.length; ) {
    const n = await conn.read(bytes.subarray(i));
    if (n == null) {
      if (!i) return false;
      throw new Error("short DNS frame");
    }
    if (!Number.isInteger(n) || n <= 0 || n > bytes.length - i) {
      throw new Error("invalid DNS frame read");
    }
    i += n;
  }
  return true;
}
export async function readFrame(conn) {
  const header = new Uint8Array(2);
  if (!(await exact(conn, header))) return null;
  const size = new DataView(header.buffer).getUint16(0);
  if (!validateSize(size)) throw new Error("invalid DNS frame length");
  const body = new Uint8Array(size);
  if (!(await exact(conn, body))) throw new Error("missing DNS frame");
  return body;
}
