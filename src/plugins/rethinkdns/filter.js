/*
 * Copyright (c) 2021 RethinkDNS and its authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

import { FrozenTrie } from "@serverless-dns/trie/ftrie.js";
import * as dnsutil from "../../commons/dnsutil.js";
import { log } from "../../core/log.js";

export class BlocklistFilter {
  constructor() {
    // see: src/helpers/node/blocklists.js:hasBlocklistFiles
    /** @type {FrozenTrie} */
    this.ftrie = null;
    /** @type {Object} */
    this.filetag = null;
  }

  /**
   * @param {FrozenTrie} frozentrie
   * @param {Object} filetag
   */
  load(frozentrie, filetag) {
    this.ftrie = frozentrie;
    this.filetag = filetag;
  }

  blockstamp(domainName) {
    const n = dnsutil.normalizeName(domainName);

    return this.lookup(n);
  }

  lookup(n) {
    const t = this.ftrie;
    if (t == null) {
      log.w("blocklist filter not loaded");
      return null;
    }

    // A codec/trie failure must not silently become an allow decision.
    return t.lookup(t.transform(n));
  }

  extract(ids) {
    const r = {};
    if (this.filetag) {
      for (const id of ids) r[id] = this.filetag[id];
    }
    return r;
  }
}
