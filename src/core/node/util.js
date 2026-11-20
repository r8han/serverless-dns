/*
 * Copyright (c) 2021 RethinkDNS and its authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

import { readBounded } from "../../commons/bounded.js";
import { validateIdentity } from "./listener-policy.js";
import { Buffer } from "node:buffer";
import { X509Certificate } from "node:crypto";
import * as bufutil from "../../commons/bufutil.js";
import { decryptAesGcm, hmacsign, svckeys } from "../../commons/crypto.js";
import * as envutil from "../../commons/envutil.js";
import * as util from "../../commons/util.js";
import { log } from "../log.js";

/**
 * @param {String} TLS_CRT_KEY - Contains base64 (no wrap) encoded key and
 * certificate files seprated by a newline (\n) and described by `KEY=` and
 * `CRT=` respectively. Ex: `TLS_="KEY=encoded_string\nCRT=encoded_string"`
 * @return {[BufferSource, BufferSource]} [TLS_KEY, TLS_CRT]
 */
export function getCertKeyFromEnv(TLS_CRT_KEY) {
  const parts = new Map();
  for (const line of (TLS_CRT_KEY ?? "")
    .trim()
    .replace(/\\n/g, "\n")
    .split(/\r?\n/)) {
    const match = /^(KEY|CRT)=([a-zA-Z0-9+/]+={0,2})$/.exec(line);
    if (!match || parts.has(match[1])) {
      throw new Error("malformed TLS identity");
    }
    parts.set(match[1], Buffer.from(match[2], "base64"));
  }
  if (parts.size !== 2) throw new Error("incomplete TLS identity");
  return [parts.get("KEY"), parts.get("CRT")];
}

/**
 * @param {X509Certificate} replacing - The X509Certificate to replace the existing one
 * @returns {Promise<[BufferSource|null, BufferSource|null]>} - The key and certificate as ArrayBuffers
 */
export async function replaceKeyCert(replacing) {
  const nokeycert = [null, null];

  const names = replacing?.subjectAltName?.split(", ").sort();
  if (
    !names?.length ||
    !names.every((n) =>
      /^DNS:(?:\*\.)?(?:[a-z0-9-]+\.)*rethinkdns\.com$/i.test(n)
    )
  ) {
    return nokeycert;
  }

  try {
    const [aeskey, mackey] = await keys();
    if (!aeskey || !mackey) {
      log.e("certfile: key missing");
      return nokeycert;
    }

    const now = Date.now();
    const u = "https://redir.nile.workers.dev/x/crt/" + now;
    const url = new URL(u);
    // TODO: bind "who" to msg?
    const msg = bufutil.fromStr(url.pathname);
    const authz = await hmacsign(mackey, msg);
    const who = envutil.hostId(); // may be empty on Workers
    const req = new Request(url, {
      method: "GET",
      redirect: "error",
      signal: AbortSignal.timeout(5000),
      headers: {
        "x-rethinkdns-xsvc-authz": bufutil.hex(authz),
        "x-rethinkdns-xsvc-who": who,
      },
    });
    const r = await fetch(req);

    if (r.status !== 200) {
      r.body?.cancel().catch(() => {});
      log.e("certfile: fetch failed", r.status);
      return nokeycert;
    }

    const crthex = new TextDecoder().decode(
      await readBounded(r, 65536, req.signal)
    );
    if (util.emptyString(crthex)) {
      log.e("certfile: empty response");
      return nokeycert;
    }

    const crtkey = await decryptText(req, crthex);
    if (util.emptyString(crtkey)) {
      log.e("certfile: empty enc(crtkey)");
      return nokeycert;
    }
    const [key, cert] = getCertKeyFromEnv(crtkey);
    if (bufutil.emptyBuf(key) || bufutil.emptyBuf(cert)) {
      log.e("certfile: key/cert empty");
      return nokeycert;
    }

    validateIdentity(key, cert, true);
    const latest = new X509Certificate(cert);
    if (latest.subjectAltName?.split(", ").sort().join() !== names.join()) {
      log.e("certfile: replacement SAN mismatch");
      return nokeycert;
    }

    if (latest.serialNumber === replacing.serialNumber) {
      log.d("certfile: latest cert same as replacing", latest.serialNumber);
      return [key, cert];
    }

    const latestUntil = new Date(latest.validTo);
    const replacingUntil = new Date(replacing.validTo);
    if (
      latestUntil.getTime() < Date.now() ||
      latestUntil.getTime() <= replacingUntil.getTime()
    ) {
      log.d(
        "certfile: err latestUntil < replacingUntil",
        latestUntil,
        replacingUntil,
        "now",
        Date.now()
      );
      return nokeycert;
    }

    log.i("certfile: latest cert", latest.serialNumber, "until", latestUntil);

    return [key, cert];
  } catch (err) {
    log.e("certfile: renewal failed");
  }
  return nokeycert;
}

/**
 * @param {Request} req - The request that got us ivciphertaghex
 * @param {string} ivciphertaghex - The cipher text as hex to decrypt as utf8
 * @returns {Promise<Uint8Array|null>} - Encrypted hex string with iv (96 bits) prepended and tag appended; or null on failure
 */
export async function decryptText(req, ivciphertaghex) {
  const now = new Date();
  const u = new URL(req.url);
  const authn = req.headers.get("x-rethinkdns-xsvc-who");
  const ivciphertag = bufutil.hex2buf(ivciphertaghex);
  if (bufutil.emptyBuf(ivciphertag)) {
    log.e("decrypt: ivciphertag empty");
    return null;
  }

  try {
    const iv = ivciphertag.slice(0, 12); // first 12 bytes are iv
    const ciphertag = ivciphertag.slice(12); // rest is cipher text + tag
    // crypto.junod.info/posts/recursive-hash/#data-serialization
    // 1 Aug 2025 => "5/7/2025" => Friday, 7th month (0-indexed), 2025
    const aadstr =
      authn +
      "/" +
      now.getUTCDay() +
      "/" +
      now.getUTCMonth() +
      "/" +
      now.getUTCFullYear() +
      "/" +
      u.hostname +
      "/" +
      u.pathname +
      "/" +
      req.method;
    const aad = bufutil.fromStr(aadstr);

    const [aeskey, mackey] = await keys();
    if (!aeskey || !mackey) {
      log.e("decrypt: key missing");
      return null;
    }

    const plain = await decryptAesGcm(aeskey, iv, ciphertag, aad);
    if (bufutil.emptyBuf(plain)) {
      log.e("decrypt: failed to decrypt", ivciphertaghex.length);
      return null;
    }
    return bufutil.toStr(plain);
  } catch (err) {
    log.e("decrypt: failed");
    return null;
  }
}

/**
 * @returns {Promise<[CryptoKey|null]>} - Returns CryptoKeys or null if the key is missing or invalid
 */
async function keys() {
  return svckeys();
}

// Use only an origin-form target. HTTP/2 permits a Host header alongside
// :authority; if both exist they must identify the same origin.
export function requestUrl(headers, target) {
  const origin = (host) => {
    if (
      typeof host !== "string" ||
      !host ||
      host.length > 320 ||
      /[\s\\/?#@%]/.test(host)
    ) {
      throw new Error("invalid authority");
    }
    return new URL("https://" + host).origin;
  };
  const base = origin(headers[":authority"] ?? headers.host);
  if (
    (headers.host != null && origin(headers.host) !== base) ||
    !target.startsWith("/") ||
    target.startsWith("//") ||
    /[\\#\r\n\t]/.test(target)
  ) {
    throw new Error("invalid request target");
  }
  const url = new URL(target, base);
  if (url.origin !== base) throw new Error("origin mismatch");
  return url;
}

/**
 * @param {Object} headers
 * @return {Object}
 */
export function copyNonPseudoHeaders(headers) {
  // nodejs req headers may be of form
  // ':authority': 'localhost:8080'
  // ':method': 'GET'
  // ':path': '/1:AAIAgA==?dns=AAABAAABAAAAAAAACnJldGhpbmtkbnMDY29tAAABAAE'
  // ':scheme': 'https'
  // accept: 'application/dns-message'
  // 'user-agent': 'Go-http-client/2.0'
  // [Symbol(nodejs.http2.sensitiveHeaders)]: []

  const out = {};

  if (!headers) return out;

  // drop http/2 pseudo-headers
  for (const name in headers) {
    if (name.startsWith(":")) continue;
    out[name] = headers[name];
  }

  return out;
}
