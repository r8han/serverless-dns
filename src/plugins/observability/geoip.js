// SPDX-License-Identifier: MPL-2.0
import { readBounded } from "../../commons/bounded.js";
import { digest } from "../../commons/blocklist-integrity.js";
import {
  cancelScope,
  checkAlive,
  fetchSignal,
  openResponse,
} from "../../commons/cancel.js";

// dbip.v4/v6: unsigned network-order range start, then two ASCII country
// letters. There is no per-IP network service or per-IP cache.
const maxTable = 16 * 1024 * 1024;
const retryMs = 60000;
const compare = (a, offset, b, other, width) => {
  for (let i = 0; i < width; i++) {
    const d = a[offset + i] - b[other + i];
    if (d) return d;
  }
  return 0;
};
export function validCountry(code) {
  return typeof code === "string" && /^[A-Z]{2}$/.test(code) && code !== "ZZ";
}

function lookup(table, address) {
  const width = address.length;
  const stride = width + 2;
  let lo = 0;
  let hi = table.length / stride;
  while (lo < hi) {
    const mid = Math.floor((lo + hi) / 2);
    if (compare(table, mid * stride, address, 0, width) <= 0) lo = mid + 1;
    else hi = mid;
  }
  if (!lo) return null; // before the first known range
  const offset = (lo - 1) * stride + width;
  const country = String.fromCharCode(table[offset], table[offset + 1]);
  return validCountry(country) ? country : null;
}

async function load(url, size, sha256, width) {
  // The background task outlives the DNS response but has its own deadline.
  const { signal, close } = cancelScope([], 5000);
  try {
    const res = await openResponse(
      () => fetch(url, { redirect: "manual", ...fetchSignal(signal) }),
      signal
    );
    if (res.status !== 200 || res.headers.has("content-range")) {
      res.body?.cancel().catch(() => {});
      throw new Error("incomplete GeoIP table");
    }
    const bytes = await readBounded(res, size, signal, true);
    if ((await digest(bytes)) !== sha256) {
      throw new Error("unverified GeoIP table");
    }
    checkAlive(signal);
    const table = new Uint8Array(bytes);
    const stride = width + 2;
    for (let off = 0; off < size; off += stride) {
      const a = table[off + width];
      const b = table[off + width + 1];
      if (
        a < 65 ||
        a > 90 ||
        b < 65 ||
        b > 90 ||
        (off && compare(table, off - stride, table, off, width) >= 0)
      ) {
        throw new Error("invalid GeoIP range table");
      }
    }
    return table;
  } finally {
    close();
  }
}

export class GeoIP {
  // Only publish fully verified tables. Never share request-owned I/O across
  // Workers requests: another cold request still records its ordinary metric.
  tables = new Map();
  loading = false;

  async country(address, env) {
    const width = address?.length;
    if (width !== 4 && width !== 16) return null;
    if (!address.some((b) => b !== 0)) return null; // unspecified/sinkhole
    const family = width === 4 ? "V4" : "V6";
    const pin = env.get(`GEOIP_${family}_PIN`);
    const base = env.get("GEOIP_URL");
    if (!base || !pin) return null;
    let state = this.tables.get(width);
    if (!state || state.pin !== pin || state.base !== base) {
      const m = /^([1-9]\d{0,7}):([a-f0-9]{64})$/.exec(pin);
      if (!m) return null;
      const size = Number(m[1]);
      if (size > maxTable || size % (width + 2) !== 0) return null;
      let url;
      try {
        url = new URL(base);
      } catch {
        return null;
      }
      if (
        url.protocol !== "https:" ||
        url.username ||
        url.password ||
        url.search ||
        url.hash
      ) {
        return null;
      }
      url.pathname =
        url.pathname.replace(/\/?$/, "/") + "dbip." + family.toLowerCase();
      state = { base, pin, url, size, sha256: m[2], retry: 0, table: null };
      this.tables.set(width, state);
    }
    if (!state.table) {
      if (this.loading || Date.now() < state.retry) return null;
      this.loading = true;
      try {
        state.table = await load(state.url, state.size, state.sha256, width);
      } catch {
        state.retry = Date.now() + retryMs;
        return null;
      } finally {
        this.loading = false;
      }
    }
    return lookup(state.table, address);
  }
}
