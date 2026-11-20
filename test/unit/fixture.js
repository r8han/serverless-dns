// SPDX-License-Identifier: MPL-2.0
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

export const fixture = JSON.parse(
  readFileSync(new URL("../fixtures/two-lists.json", import.meta.url), "utf8")
);

// A trusted, deliberately tiny generation, never a production default.
export function fixtureMetadata(version = fixture.basicconfig.timestamp) {
  const basicconfig = { ...fixture.basicconfig, timestamp: version };
  const filetag = fixture.filetag;
  const files = {};
  for (const [name, bytes] of Object.entries({
    "basicconfig.json": Buffer.from(JSON.stringify(basicconfig)),
    "filetag.json": Buffer.from(JSON.stringify(filetag)),
    "td.txt": Buffer.from(fixture.td, "base64"),
    "rd.txt": Buffer.from(fixture.rd, "base64"),
  })) {
    files[name] = {
      size: bytes.length,
      sha256: createHash("sha256").update(bytes).digest("hex"),
    };
  }
  return { basicconfig, filetag, manifest: { version, codec: "u6", files } };
}
