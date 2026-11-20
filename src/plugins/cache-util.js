// SPDX-License-Identifier: MPL-2.0
import * as dns from "../commons/dnsutil.js";
import * as env from "../commons/envutil.js";

export function sameQuestion(answer, query) {
  const a = answer.questions[0];
  const q = query.questions[0];
  return (
    answer.type === "response" &&
    query.type === "query" &&
    answer.opcode === query.opcode &&
    a.type === q.type &&
    a.class === q.class &&
    dns.normalizeName(a.name) === dns.normalizeName(q.name)
  );
}

// The sole answer-cache admission type. Neither a policy hit nor a synthesized
// response travels this path. Validate the actual bytes, not a caller's object.
export class UpstreamAnswer {
  constructor(bytes, query) {
    const packet = dns.decode(bytes);
    if (
      packet.id !== query.id ||
      !sameQuestion(packet, query) ||
      packet.flag_tc ||
      !["NOERROR", "NXDOMAIN"].includes(packet.rcode)
    ) {
      throw new Error("unusable upstream DNS response");
    }
    this.bytes = bytes;
    this.packet = packet;
  }
}

export function cacheKey(packet, revision, preferred = "") {
  if (
    !revision ||
    packet.type !== "query" ||
    packet.additionals.some((a) => a.options?.length)
  ) {
    return null;
  }
  const q = packet.questions[0];
  const view = [env.forceDoh(), preferred || "", ...env.dohResolvers()];
  const fields = [
    revision,
    env.blockSubdomains(),
    ...view,
    q.name,
    q.type,
    q.class,
    packet.opcode,
    packet.flags,
    packet.additionals[0]?.udpPayloadSize,
    dns.hasDnssecOk(packet),
  ];
  return new URL(
    "https://caches.rethinkdns.com/verified-v2/" +
      encodeURIComponent(JSON.stringify(fields))
  );
}

function records(p) {
  return [...p.answers, ...p.authorities, ...p.additionals].filter(
    (r) => r.type !== "OPT"
  );
}

function negative(p) {
  return (
    p.rcode === "NXDOMAIN" ||
    !p.answers.length ||
    (p.authorities.some((r) => r.type === "SOA") &&
      !p.answers.some((r) => r.type === p.questions[0].type))
  );
}

export function lifetime(p) {
  if (
    p.flag_tc ||
    !["NOERROR", "NXDOMAIN"].includes(p.rcode) ||
    p.additionals.some((a) => a.options?.length)
  ) {
    return 0;
  }
  const rr = records(p);
  if (!rr.length || rr.some((r) => r.ttl > 0x7fffffff)) return 0;
  let ttl = Math.min(604800, ...rr.map((r) => r.ttl));
  if (negative(p)) {
    const soa = p.authorities.find((r) => r.type === "SOA");
    ttl = Math.min(ttl, soa?.data.minimum ?? 0);
  }
  return ttl;
}

export function replay(entry, query) {
  const bytes = entry.bytes.slice(0);
  const packet = dns.decode(bytes);
  if (!sameQuestion(packet, query) || !Number.isSafeInteger(entry.time)) {
    return null;
  }
  const age = Math.floor((Date.now() - entry.time) / 1000);
  const live = lifetime(packet);
  if (age < 0 || age >= live) return null;
  const wire = new DataView(bytes);
  wire.setUint16(0, (packet.id = query.id));
  for (const r of records(packet)) {
    // RFC 2308: negative SOA TTL is also bounded by MINIMUM.
    if (r.type === "SOA" && negative(packet)) {
      r.ttl = Math.min(r.ttl, r.data.minimum);
    }
    wire.setUint32(r.ttlOffset, (r.ttl -= age));
  }
  return { packet, bytes, stamps: entry.stamps };
}
