/*
 * Copyright (c) 2021 RethinkDNS and its authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

import { Buffer } from "node:buffer";
import { inspect } from "./dns-wire.js";
import * as dnslib from "@serverless-dns/dns-parser";
import * as bufutil from "./bufutil.js";
import * as envutil from "./envutil.js";
import * as util from "./util.js";

// dns packet constants (in bytes)
// tcp msgs prefixed with 2-octet headers indicating request len in bytes
export const dnsHeaderSize = 2;
export const dnsPacketHeaderSize = 12;
export const minDNSPacketSize = dnsPacketHeaderSize + 5;
export const maxDNSPacketSize = 4096;

const _dnsCacheSize = 30000;
// Retained memory for cached upstream answers. A cached answer may be a full
// DNS packet (maxDNSPacketSize), so the entry cap alone does not bound memory;
// see docs/security/2026-11-20/audit.md (MEM-01).
const _dnsCacheBytes = 16 * 1024 * 1024; // 16 MiB

const _minRequestTimeout = 4000; // 4s
const _maxRequestTimeout = 30000; // 30s

export function cacheSize() {
  return _dnsCacheSize;
}

export function cacheBytes() {
  return _dnsCacheBytes;
}

export function isAnswer(packet) {
  if (util.emptyObj(packet)) return false;

  return packet.type === "response";
}

export function mkQ(qid, qs) {
  if (util.emptyArray(qs)) return null;

  return encode({
    id: qid || 0,
    type: "query",
    questions: qs,
  });
}

export function servfail(qid, qs) {
  // qid == 0 is valid; in fact qid is set to 0 by most doh clients
  if (qid == null || qid < 0 || util.emptyArray(qs)) return bufutil.ZEROAB;

  return encode({
    id: qid,
    type: "response",
    flags: 0x182, // servfail
    questions: qs,
  });
}

export function servfailQ(q) {
  if (bufutil.emptyBuf(q)) return bufutil.ZEROAB;

  try {
    const p = decode(q);
    return servfail(p.id, p.questions);
  } catch (_) {
    return bufutil.ZEROAB;
  }
}

export function requestTimeout() {
  const t = envutil.workersTimeout();
  return t > _minRequestTimeout
    ? Math.min(t, _maxRequestTimeout)
    : _minRequestTimeout;
}

export function truncated(ans) {
  if (bufutil.emptyBuf(ans)) return false;
  if (ans.byteLength < dnsPacketHeaderSize) return false;
  // first 2 bytes are query-id
  const flags = ans.readUInt16BE(2);
  // github.com/mafintosh/dns-packet/blob/8e6d91c0/index.js#L147
  const tc = (flags >> 9) & 0x1;
  return tc === 1;
}

export function validResponseSize(r) {
  return r && validateSize(r.byteLength);
}

export function validateSize(sz) {
  return sz >= minDNSPacketSize && sz <= maxDNSPacketSize;
}

export function hasAnswers(packet) {
  return !util.emptyObj(packet) && !util.emptyArray(packet.answers);
}

export function hasSingleQuestion(packet) {
  return (
    !util.emptyObj(packet) &&
    !util.emptyArray(packet.questions) &&
    packet.questions.length === 1
  );
}

export function rcodeNoError(packet) {
  if (util.emptyObj(packet)) return false;
  // github.com/mafintosh/dns-packet/blob/8e6d91c07/rcodes.js
  return packet.rcode === "NOERROR";
}

export function hasDnssecOk(packet) {
  if (util.emptyObj(packet)) return false;
  if (util.emptyArray(packet.additionals)) return false;
  // github.com/mafintosh/dns-packet/blob/31d3caf3/index.js#L1440
  // github.com/mafintosh/dns-packet/blob/31d3caf3/index.js#L1523
  // github.com/mafintosh/dns-packet/blob/31d3caf3/test.js#L407
  for (const a of packet.additionals) {
    if (a.flag_do || ((a.flags >> 15) & 0x1) === 1) return true;
  }
  return false;
}

// Queries have at most one OPT, at the end. Preserve the DO flag and all
// other EDNS bytes when removing ECS, without decoding/re-encoding options.
export function stripClientSubnet(bytes, query) {
  const opt = query.additionals[0];
  if (!opt?.options.some((o) => o.code === 8)) return bytes;
  const wire = new Uint8Array(bytes);
  const start = opt.ttlOffset + 6;
  const rest = opt.options
    .filter((o) => o.code !== 8)
    .map((o) => wire.subarray(o.start, o.end));
  const result = bufutil.concat([wire.subarray(0, start), ...rest]);
  new DataView(result).setUint16(start - 2, result.byteLength - start);
  return result;
}

export function decode(bytes) {
  return inspect(bytes);
}

export function decodeQuery(bytes) {
  return inspect(bytes, true);
}

// Only application-generated packets go through the legacy encoder. Never
// return its allocation (or encode an upstream packet with opaque records).
export function encode(packet) {
  const size = dnslib.encodingLength(packet);
  if (size > maxDNSPacketSize + 1) {
    throw new RangeError("DNS message too large");
  }
  const buf = Buffer.alloc(size);
  dnslib.encode(packet, buf);
  const written = dnslib.encode.bytes;
  if (!validateSize(written) || written > size) {
    throw new Error("invalid encoding");
  }
  return bufutil.arrayBufferOf(buf.subarray(0, written));
}

// List membership is checked for *all* questions. Only address and service
// types get a synthetic sinkhole; all other blocked types are refused.
export function canSinkhole(q) {
  return ["A", "AAAA", "HTTPS", "SVCB"].includes(q?.type);
}

/**
 * @param {any} dnsPacket
 * @returns {string[]}
 */
export function extractDomains(dnsPacket) {
  if (!hasSingleQuestion(dnsPacket)) return [];

  /** @type {string} */
  const names = new Set();
  const answers = dnsPacket.answers;

  const q = normalizeName(dnsPacket.questions[0].name);
  names.add(q);

  if (util.emptyArray(answers)) return [...names];

  // name                    ttl  cls  type    data
  // aws.amazon.com          57   IN   CNAME   frontier.amazon.com
  // frontier.amazon.com     57   IN   CNAME   3n1n2s.cloudfront.net
  // 3n1n2s.cloudfront.net   57   IN   A       54.230.149.75
  for (const a of answers) {
    if (a && !util.emptyString(a.name)) {
      const n = normalizeName(a.name);
      names.add(n);
    }
    if (
      (a.type === "CNAME" || a.type === "DNAME") &&
      !util.emptyString(a.data)
    ) {
      const n = normalizeName(a.data);
      names.add(n);
    } else if (
      (a.type === "HTTPS" || a.type === "SVCB") &&
      a.data &&
      !util.emptyString(a.data.targetName)
    ) {
      const n = normalizeName(a.data.targetName);
      // when ".", then target-domain is same as the question-domain
      if (n !== ".") names.add(n);
    } // else: name in answer not blockable
  }

  return [...names];
}

/**
 * @param {string?} n
 * @returns {string}
 */
export function normalizeName(n) {
  if (util.emptyString(n)) return n;

  return n.trim().toLowerCase();
}
