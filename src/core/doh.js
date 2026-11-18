/*
 * Copyright (c) 2021 RethinkDNS and its authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

import { cancelScope, checkAlive, whileAlive } from "../commons/cancel.js";
import * as dnsutil from "../commons/dnsutil.js";
import * as util from "../commons/util.js";
import { services } from "./svc.js";
import IOState from "./io-state.js";
import RethinkPlugin from "./plugin.js";

// TODO: define FetchEventLike
/**
 * @typedef {any} FetchEventLike
 */

/**
 * Per-isolate request admission.
 */
let active = 0;
const maxRequests = 256;
const privateHeaders = {
  "cache-control": "private, no-store",
  "referrer-policy": "no-referrer",
};

export async function handleRequest(event) {
  const req = event.request;
  if (req.url.length > 8192) {
    return new Response(null, { status: 414, headers: privateHeaders });
  }
  if (!services.ready || active >= maxRequests) {
    return new Response(null, { status: 503, headers: privateHeaders });
  }
  if (["OPTIONS", "HEAD"].includes(req.method)) {
    return new Response(null, {
      status: 204,
      headers: { ...util.corsHeaders(), ...privateHeaders },
    });
  }
  const wait = dnsutil.requestTimeout();
  const deadline = Math.min(event.deadline ?? Infinity, Date.now() + wait);
  const ctl = cancelScope([req.signal], deadline - Date.now());
  if (Date.now() >= deadline) ctl.close();
  active++;
  try {
    const signal = ctl.signal;
    checkAlive(signal);
    const io = new IOState();
    const plugin = new RethinkPlugin(event);
    plugin.addCtx("deadline", deadline);
    plugin.addCtx("signal", signal);
    const work = async () => {
      await plugin.initIoState(io);
      if (!io.httpResponse) await plugin.execute();
      return io.httpResponse;
    };
    const r = await whileAlive(work(), signal);
    const headers = new Headers(r.headers);
    for (const [k, v] of Object.entries(privateHeaders)) headers.set(k, v);
    if (r.ok && util.fromBrowser(req.headers.get("user-agent"))) {
      for (const [k, v] of Object.entries(util.corsHeaders())) {
        headers.set(k, v);
      }
    }
    return new Response(r.body, { status: r.status, headers });
  } catch {
    return new Response(null, {
      status: ctl.signal.aborted ? 408 : 503,
      headers: privateHeaders,
    });
  } finally {
    active--;
    ctl.close();
  }
}
