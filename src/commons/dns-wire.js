// SPDX-License-Identifier: MPL-2.0
// Inspect just the DNS fields the resolver uses. Preserve upstream RDATA on the
// wire: moving opaque records can invalidate compressed names and signatures.
import { Buffer } from "node:buffer";
import * as types from "@serverless-dns/dns-parser/types.js";
import * as classes from "@serverless-dns/dns-parser/classes.js";
import * as rcodes from "@serverless-dns/dns-parser/rcodes.js";
import { ip } from "@serverless-dns/dns-parser/lib/ip.js";

export const maxSize = 4096;
function requireWire(ok) {
  if (!ok) throw new Error("invalid DNS message");
}

export function inspect(bytes, queryOnly = false, onAnswerAddress = null) {
  requireWire(bytes?.byteLength >= 17 && bytes.byteLength <= maxSize);
  const b = ArrayBuffer.isView(bytes)
    ? Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength)
    : Buffer.from(bytes);
  const flags = b.readUInt16BE(2);
  const response = (flags & 0x8000) !== 0;
  const counts = [6, 8, 10].map((i) => b.readUInt16BE(i));
  requireWire(b.readUInt16BE(4) === 1 && (flags & 0x7800) === 0);
  requireWire(17 + counts.reduce((n, count) => n + count * 11, 0) <= b.length);
  if (queryOnly || !response) {
    requireWire(
      !response &&
        (flags & ~0x0130) === 0 &&
        counts[0] === 0 &&
        counts[1] === 0 &&
        counts[2] <= 1
    );
  }
  let pos = 12;
  // Each pointer must refer to an earlier name; also bound expanded work,
  // including many records that repeatedly refer to the same suffix.
  let budget = maxSize * 16;
  function name(end) {
    let i = pos;
    let resume = 0;
    let ceiling = end;
    let expanded = 1;
    const labels = [];
    for (;;) {
      requireWire(i < ceiling && --budget >= 0);
      const n = b[i++];
      if (n === 0) break;
      if ((n & 192) === 192) {
        requireWire(i < ceiling);
        const target = ((n & 63) << 8) | b[i];
        requireWire(target >= 12 && target < i - 1);
        if (!resume) resume = i + 1;
        ceiling = i - 1;
        i = target;
      } else {
        expanded += n + 1;
        requireWire(n <= 63 && i + n <= ceiling && expanded <= 255);
        budget -= n;
        const label = b.toString("latin1", i, i + n);
        // The filtering/stamp representation uses dot-separated ASCII labels.
        requireWire(/^[a-zA-Z0-9_*\-]+$/.test(label));
        labels.push(label);
        i += n;
      }
    }
    pos = resume || i;
    return labels.join(".") || ".";
  }
  const qname = name(b.length);
  requireWire(pos + 4 <= b.length);
  const question = {
    name: qname,
    type: types.toString(b.readUInt16BE(pos)),
    class: classes.toString(b.readUInt16BE(pos + 2)),
  };
  const qtype = b.readUInt16BE(pos);
  requireWire(qtype > 0 && qtype !== 41 && !(qtype >= 249 && qtype <= 254));
  pos += 4;
  requireWire(question.class === "IN");
  const p = {
    id: b.readUInt16BE(0),
    type: response ? "response" : "query",
    flags: flags & 0x7fff,
    opcode: "QUERY",
    rcode: rcodes.toString(flags & 15),
    flag_tc: !!(flags & 512),
    flag_ad: !!(flags & 32),
    questions: [question],
    answers: [],
    authorities: [],
    additionals: [],
  };
  const sections = [p.answers, p.authorities, p.additionals];
  let opt = false;
  for (const [section, count] of counts.entries()) {
    for (let j = 0; j < count; j++) {
      const owner = name(b.length);
      requireWire(pos + 10 <= b.length);
      const code = b.readUInt16BE(pos);
      const klass = b.readUInt16BE(pos + 2);
      const ttlOffset = pos + 4;
      const ttl = b.readUInt32BE(ttlOffset);
      const length = b.readUInt16BE(pos + 8);
      pos += 10;
      const end = pos + length;
      requireWire(end <= b.length && (response || code === 41));
      const rr = {
        name: owner,
        type: types.toString(code),
        class: classes.toString(klass),
        ttlOffset,
        ttl,
      };
      if (code !== 41) requireWire(klass === 1);
      if (code === 41) {
        requireWire(
          !opt && owner === "." && section === 2 && (ttl & ~0x8000) === 0
        );
        opt = true;
        Object.assign(rr, {
          udpPayloadSize: klass,
          flags: ttl,
          flag_do: !!ttl,
          options: [],
        });
        while (pos < end) {
          requireWire(pos + 4 <= end);
          const key = b.readUInt16BE(pos);
          const size = b.readUInt16BE(pos + 2);
          pos += 4;
          requireWire(pos + size <= end);
          rr.options.push({ code: key, start: pos - 4, end: pos + size });
          pos += size;
        }
      } else if (code === 1 || code === 28) {
        requireWire(length === (code === 1 ? 4 : 16));
        rr.data = ip.toString(b, pos, length);
        if (section === 0) onAnswerAddress?.(b, pos, length);
      } else if ([2, 5, 12, 39].includes(code)) {
        rr.data = name(end);
        requireWire(pos === end);
      } else if (code === 6) {
        const mname = name(end);
        const rname = name(end);
        requireWire(pos + 20 === end);
        rr.data = { mname, rname, minimum: b.readUInt32BE(end - 4) };
      } else if (code === 64 || code === 65) {
        requireWire(pos + 2 < end);
        const svcPriority = b.readUInt16BE(pos);
        pos += 2;
        rr.data = { svcPriority, targetName: name(end), svcParams: {} };
        let last = -1;
        while (pos < end) {
          requireWire(pos + 4 <= end);
          const key = b.readUInt16BE(pos);
          const size = b.readUInt16BE(pos + 2);
          pos += 4;
          requireWire(key > last && pos + size <= end);
          last = key;
          if (key === 4 || key === 6) {
            const width = key === 4 ? 4 : 16;
            requireWire(size > 0 && size % width === 0);
            if (
              section === 0 &&
              svcPriority > 0 &&
              rr.data.targetName === "."
            ) {
              onAnswerAddress?.(b, pos, width); // first hint in this SvcParam
            }
            const hints = [];
            for (let k = 0; k < size; k += width) {
              hints.push(ip.toString(b, pos + k, width));
            }
            rr.data.svcParams[key === 4 ? "ipv4hint" : "ipv6hint"] = hints;
          }
          pos += size;
        }
      }
      // All other RDATA remains opaque, including DNSSEC records. It is
      // forwarded unchanged, never interpreted as an object or re-serialized.
      pos = end;
      sections[section].push(rr);
    }
  }
  requireWire(pos === b.length);
  return p;
}

// Return only validated address RDATA from the served Answer section. As in
// the old metric, self-target service bindings can supply an IP hint; text,
// aliases, glue and the requester's address never become a lookup key.
export function firstAnswerAddress(wire) {
  if (!wire) return null;
  let address = null;
  const packet = inspect(wire, false, (bytes, offset, width) => {
    address ??= Uint8Array.from(bytes.subarray(offset, offset + width));
  });
  return packet.type === "response" &&
    !packet.flag_tc &&
    packet.rcode === "NOERROR"
    ? address
    : null;
}
