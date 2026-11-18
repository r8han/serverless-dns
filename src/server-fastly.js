// eslint-disable-next-line spaced-comment
/// <reference types="@fastly/js-compute" />

/*
 * Copyright (c) 2022 RethinkDNS and its authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

import "./core/fastly/config.js";
import { requestTimeout } from "./commons/dnsutil.js";
import { handleRequest } from "./core/doh.js";
import * as system from "./system.js";

addEventListener("fetch", (event) => {
  return event.respondWith(serveDoh(event));
});

/**
 * @param {FetchEvent} event
 * @returns {Response}
 */
async function serveDoh(event) {
  // on Fastly, the network-context is only available in an event listener
  // and so, publish system prepare from here instead of from main which
  // runs in global-scope.
  const start = Date.now();
  system.pub("prepare");

  try {
    await system.when("go", 10000);
    return await handleRequest({
      request: event.request,
      waitUntil: event.waitUntil.bind(event),
      deadline: start + requestTimeout(),
    });
  } catch (e) {
    return new Response(null, {
      status: 503,
      headers: { "cache-control": "private, no-store" },
    });
  }
}
