/*
 * Copyright (c) 2021 RethinkDNS and its authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

import {
  files,
  checkWorkerBlocklistBudget,
  validateConfig,
  validateManifest,
  jsonBytes,
  verify,
  fetchArtifact,
} from "../../commons/blocklist-integrity.js";
import { cancelScope } from "../../commons/cancel.js";
import { createTrie } from "@serverless-dns/trie/ftrie.js";
import * as envutil from "../../commons/envutil.js";
import * as cfg from "../../core/cfg.js";
import { log } from "../../core/log.js";
import * as pres from "../plugin-response.js";
import * as rdnsutil from "../rdns-util.js";
import { BlocklistFilter } from "./filter.js";
import { withDefaults } from "./trie-config.js";

export class BlocklistWrapper {
  constructor() {
    /** @type {BlocklistFilter} */
    this.blocklistFilter = new BlocklistFilter();
    this.revision = [
      cfg.timestamp(),
      ...files.map((name) => cfg.manifest().files[name].sha256),
    ].join(":");
    this.pending = null;
    this.noop = envutil.disableBlocklists();

    this.log = log.withTags("BlocklistWrapper");

    if (this.noop) this.log.w("disabled?", this.noop);
  }

  async init(rxid) {
    if (this.disabled() || this.isBlocklistFilterSetup()) {
      return pres.emptyResponse();
    }
    if (!this.pending) {
      this.pending = this.download().finally(() => {
        this.pending = null;
      });
    }
    await this.pending;
    return pres.emptyResponse();
  }

  disabled() {
    return this.noop;
  }

  getBlocklistFilter() {
    return this.blocklistFilter;
  }

  isBlocklistFilterSetup() {
    return rdnsutil.isBlocklistFilterSetup(this.blocklistFilter);
  }

  async install(td, rd) {
    const manifest = cfg.manifest();
    validateManifest(manifest, cfg.timestamp());
    validateConfig(cfg.orig(), manifest.version);
    await Promise.all([
      verify(td, manifest.files["td.txt"]),
      verify(rd, manifest.files["rd.txt"]),
      verify(jsonBytes(cfg.orig()), manifest.files["basicconfig.json"]),
      verify(jsonBytes(cfg.filetag()), manifest.files["filetag.json"]),
    ]);
    const next = new BlocklistFilter();
    next.load(createTrie(td, rd, withDefaults(cfg.orig())), cfg.filetag());
    this.blocklistFilter = next; // all-or-nothing, even after a failed reload
  }

  async download() {
    const manifest = cfg.manifest();
    // Leave headroom for the trie, response caches and active requests.
    if (envutil.isWorkers()) checkWorkerBlocklistBudget(manifest);
    const base = envutil.blocklistUrl();
    const scope = cancelScope();
    try {
      const [td, rd] = await Promise.all(
        ["td.txt", "rd.txt"].map((name) =>
          fetchArtifact(base, manifest, name, fetch, scope.signal)
        )
      );
      await this.install(td, rd);
    } finally {
      // When either artifact fails, do not leave its sibling downloading
      // in parallel with the next installation attempt.
      scope.close();
    }
  }

  timestamp() {
    return cfg.timestamp();
  }

  cacheTimestamp() {
    // In a cold isolate, use only flags computed with the bundled lists,
    // never entries from an isolate that ran with filtering disabled.
    return this.disabled() ? "disabled" : this.revision;
  }
}
