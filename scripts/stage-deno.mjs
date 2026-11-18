// SPDX-License-Identifier: MPL-2.0
// Deploy the checked graph as local files: a provider must not have to trust
// a mutable module cache or implement deno.lock verification on our behalf.
import { createHash } from "node:crypto";
import {
  copyFile,
  mkdir,
  readdir,
  readFile,
  writeFile,
} from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
const json = async (p) => JSON.parse(await readFile(p, "utf8"));
const dest = process.argv[2];
if (!dest) throw new Error("pass a new release directory");
await mkdir(dest); // refuse to merge into an existing release
const deps = (await json("package.json")).dependencies;
const pins = (await json("deno.lock")).remote;
const map = await json("import_map.json");
const prefixes = new Map();
for (const lib of ["dns-parser", "lfu-cache", "trie"]) {
  const tar = `https://codeload.github.com/serverless-dns/${lib}/tar.gz/`;
  const dep = deps["@serverless-dns/" + lib];
  if (!dep.startsWith(tar) || !/^[a-f0-9]{40}$/.test(dep.slice(tar.length))) {
    throw new Error("unpinned core library");
  }
  prefixes.set(
    `https://raw.githubusercontent.com/serverless-dns/${lib}/${dep.slice(
      tar.length
    )}/`,
    lib
  );
}
function relative(url) {
  for (const [prefix, lib] of prefixes) {
    if (!url.startsWith(prefix)) continue;
    const sub = url.slice(prefix.length);
    if (sub && !/^(?:[a-z0-9_-]+\/)*(?:[a-z0-9_-]+\.js)?$/i.test(sub)) {
      throw new Error("unexpected dependency path");
    }
    return lib + "/" + sub;
  }
  throw new Error("unknown remote Deno dependency");
}
for (const [url, expected] of Object.entries(pins)) {
  const path = relative(url);
  const bytes = await readFile(join("node_modules/@serverless-dns", path));
  if (createHash("sha256").update(bytes).digest("hex") !== expected) {
    throw new Error("Deno module hash mismatch: " + path);
  }
  const target = join(dest, "vendor", path);
  await mkdir(dirname(target), { recursive: true });
  await writeFile(target, bytes, { flag: "wx" });
}
for (const [name, url] of Object.entries(map.imports)) {
  if (!url.startsWith("node:")) map.imports[name] = "./vendor/" + relative(url);
}
await writeFile(join(dest, "import_map.json"), JSON.stringify(map, null, 2));
// Do not ship dependencies, package scripts or a prepare task in the release.
await writeFile(
  join(dest, "package.json"),
  JSON.stringify({ private: true, type: "module" })
);
await writeFile(
  join(dest, "deno.json"),
  JSON.stringify({
    importMap: "import_map.json",
    nodeModulesDir: "manual",
    lock: { path: "deno.lock", frozen: true },
  })
);
for (const lib of prefixes.values()) {
  await copyFile(
    join("node_modules/@serverless-dns", lib, "LICENSE"),
    join(dest, "vendor", lib, "LICENSE")
  );
}
for (const p of ["deno.lock", "LICENSE"]) {
  await copyFile(p, join(dest, p));
}
// Only application sources and the one prepared input, never dotfiles,
// credentials, build-tool dependencies, fixtures or an entire checkout.
async function sources(dir) {
  for (const file of await readdir(dir, { withFileTypes: true })) {
    if (file.name.startsWith(".")) continue;
    const path = join(dir, file.name);
    if (file.isDirectory()) await sources(path);
    else if (
      file.isFile() &&
      (/\.(js|ts)$/.test(path) || path === "src/blocklist-metadata.json")
    ) {
      const target = resolve(dest, path);
      await mkdir(dirname(target), { recursive: true });
      await copyFile(path, target);
    }
  }
}
await sources("src");
