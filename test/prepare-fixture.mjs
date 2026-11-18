// SPDX-License-Identifier: MPL-2.0
// Explicit CI-only helper. Refuse to overwrite existing build inputs.
import { fixtureMetadata, fixture } from "./unit/fixture.js";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
const dest = process.argv[2];
if (!dest) throw new Error("pass an empty fixture directory");
await mkdir(dest, { recursive: true });
const data = fixtureMetadata();
for (const [file, contents] of [
  ["blocklist-metadata.json", JSON.stringify(data)],
  ["manifest.json", JSON.stringify(data.manifest)],
  ["td.txt", Buffer.from(fixture.td, "base64")],
  ["rd.txt", Buffer.from(fixture.rd, "base64")],
]) {
  await writeFile(join(dest, file), contents, { flag: "wx" });
}
