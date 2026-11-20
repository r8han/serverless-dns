// SPDX-License-Identifier: MPL-2.0
import process from "node:process";
import { createHash, randomUUID } from "node:crypto";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import {
  fetchArtifact,
  jsonBytes,
  maxJson,
  validateConfig,
  validateManifest,
  verify,
} from "../src/commons/blocklist-integrity.js";

import { generationDir, readBinary } from "../src/core/node/artifact-file.js";

async function stageBinaries(root, base, manifest, fetcher) {
  root = resolve(root);
  await mkdir(root, { recursive: true });
  if ((await realpath(root)) !== root) {
    throw new Error("unexpected assets directory");
  }
  const dir = generationDir(root, manifest.version);
  const names = ["rd.txt", "td.txt"];
  const exists = await lstat(dir).catch((e) => {
    if (e.code !== "ENOENT") throw e;
  });
  if (exists) {
    for (const name of names) {
      const pin = manifest.files[name];
      await verify(await readBinary(dir, name, pin.size), pin);
    }
    return;
  }
  const stage = await mkdtemp(join(root, ".staging-"));
  try {
    for (const name of names) {
      const bytes = await fetchArtifact(base, manifest, name, fetcher);
      await writeFile(join(stage, name), new Uint8Array(bytes), {
        flag: "wx",
        mode: 0o444,
      });
    }
    await chmod(stage, 0o755); // final image is non-root
    await rename(stage, dir);
  } finally {
    await rm(stage, { recursive: true, force: true });
  }
}

export async function prepareMetadata({
  version,
  manifest,
  base = "https://cfstore.rethinkdns.com/blocklists",
  output = "src/blocklist-metadata.json",
  fetcher = fetch,
  assets = null,
}) {
  validateManifest(manifest, version);
  const check = async ({ basicconfig, filetag }) => {
    validateConfig(basicconfig, version);
    await verify(jsonBytes(basicconfig), manifest.files["basicconfig.json"]);
    await verify(jsonBytes(filetag), manifest.files["filetag.json"]);
    if (
      !filetag ||
      !Object.keys(filetag).length ||
      createHash("md5").update(jsonBytes(filetag)).digest("hex") !==
        basicconfig.ftmd5
    ) {
      throw new Error("inconsistent filetag");
    }
  };
  let current;
  try {
    const st = await lstat(output);
    if (st.isFile() && st.size <= 3 * maxJson) {
      current = JSON.parse(await readFile(output, "utf8"));
    }
  } catch {
    /* missing or incomplete generation */
  }
  if (current?.manifest?.version > version) {
    throw new Error("blocklist downgrade refused");
  }
  if (
    current?.manifest?.version === version &&
    JSON.stringify(current.manifest.files) !== JSON.stringify(manifest.files)
  ) {
    throw new Error("blocklist version reused with different pins");
  }
  let reusable = false;
  if (JSON.stringify(current?.manifest) === JSON.stringify(manifest)) {
    try {
      await check(current);
      reusable = true;
    } catch {
      /* reconstruct */
    }
  }
  if (reusable) {
    if (assets) await stageBinaries(assets, base, manifest, fetcher);
    return;
  }
  const basicconfig = await fetchArtifact(
    base,
    manifest,
    "basicconfig.json",
    fetcher
  );
  const filetag = await fetchArtifact(base, manifest, "filetag.json", fetcher);
  const result = { basicconfig, filetag, manifest };
  await check(result);
  if (assets) await stageBinaries(assets, base, manifest, fetcher);
  await mkdir(dirname(output), { recursive: true });
  const tmp = output + "." + randomUUID();
  try {
    await writeFile(tmp, JSON.stringify(result), { flag: "wx" });
    await rename(tmp, output);
  } finally {
    await rm(tmp, { force: true });
  }
}

if (
  process.argv[1] &&
  pathToFileURL(resolve(process.argv[1])).href === import.meta.url
) {
  const version =
    process.env.BLOCKLIST_VERSION ||
    (await readFile("scripts/blocklist-version.txt", "utf8")).trim();
  const manifestPath =
    process.env.BLOCKLIST_MANIFEST || "config/blocklist-manifest.json";
  let manifest;
  try {
    manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  } catch {
    throw new Error(
      "A trusted local BLOCKLIST_MANIFEST is required (see docs/security/rollout.md)."
    );
  }
  const base =
    process.env.BLOCKLIST_BASE_URL ||
    "https://cfstore.rethinkdns.com/blocklists";
  await prepareMetadata({
    version,
    manifest,
    base,
    assets: process.argv.includes("--assets") ? "blocklists__" : null,
  });
}
