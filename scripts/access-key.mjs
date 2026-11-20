// SPDX-License-Identifier: MPL-2.0
import { randomBytes } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { selfTest, verifier } from "../src/plugins/users/auth-token.js";

const [domain, output] = process.argv.slice(2);
if (!domain || !output) {
  throw new Error(
    "usage: npm run access-key -- canonical.hostname NEW-PRIVATE-FILE"
  );
}
await selfTest();
const bearer = randomBytes(32).toString("base64url");
const entry = await verifier(bearer, domain);
await writeFile(output, bearer + "\n", { flag: "wx", mode: 0o600 });
console.log(
  "ACCESS_KEYS entry (bearer saved to the new private file):\n" + entry
);
