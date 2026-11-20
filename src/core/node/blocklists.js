// SPDX-License-Identifier: MPL-2.0
import * as cfg from "../cfg.js";
import { validateManifest } from "../../commons/blocklist-integrity.js";
import { generationDir, readBinary } from "./artifact-file.js";

export async function setup(bw, root = "blocklists__") {
  if (bw.disabled()) return;
  const manifest = cfg.manifest();
  validateManifest(manifest, cfg.timestamp());
  const dir = generationDir(root, manifest.version);
  try {
    const read = (name) => readBinary(dir, name, manifest.files[name].size);
    await bw.install(...(await Promise.all([read("td.txt"), read("rd.txt")])));
  } catch {
    // Fallback must meet exactly the same compiled-in manifest, or fail.
    await bw.init("verified-download");
  }
}
