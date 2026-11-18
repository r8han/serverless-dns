// SPDX-License-Identifier: MPL-2.0
// Deliberately small cross-runtime contract: exercise the same byte reader,
// writer and HMAC used by the resolver; no network, adversarial corpus or timer.
import assert from "node:assert/strict";
import { selfTest } from "../src/plugins/users/auth-token.js";
import { decode, decodeQuery, encode, mkQ } from "../src/commons/dnsutil.js";
import {
  blockstampFromUrl,
  getB64Flag,
  unstamp,
} from "../src/plugins/rdns-util.js";
await selfTest();
// Supported aliases and padded stamps still round-trip to the selected bits.
for (const path of [
  "rec",
  "sec",
  "pec",
  "pr",
  "rs",
  "ps",
  "prs",
  "1:AIAAgA==",
]) {
  const selected = blockstampFromUrl("https://resolver.test/" + path, true);
  const p = unstamp(selected);
  assert.equal(
    getB64Flag(p.userBlocklistFlagUint, p.flagVersion),
    selected.replace(/=+$/, "")
  );
}
const query = mkQ(17, [{ name: "example.org.", type: "A" }]);
assert.equal(query.byteLength, 29);
const q = decodeQuery(query);
assert.equal(q.questions[0].name, "example.org");
for (const [type, data] of [
  ["A", "192.0.2.1"],
  ["AAAA", "2001:db8::1"],
  ["CNAME", "alias.example"],
  [
    "HTTPS",
    {
      svcPriority: 1,
      targetName: "alias.example",
      svcParams: { ipv4hint: ["192.0.2.1"] },
    },
  ],
  ["SVCB", { svcPriority: 1, targetName: ".", svcParams: {} }],
]) {
  const bytes = encode({
    id: q.id,
    type: "response",
    questions: q.questions,
    answers: [{ name: "example.org", type, ttl: 30, data }],
  });
  assert.deepEqual(decode(bytes).answers[0].data, data);
  assert.throws(() => decodeQuery(bytes));
  assert.throws(() => decode(bytes.slice(0, -1)));
}
// Ordinary compressed owner name referring to "example.org" at offset 12.
const full = new Uint8Array(query.byteLength + 16);
full.set(new Uint8Array(query));
new DataView(full.buffer).setUint16(2, 0x8180);
new DataView(full.buffer).setUint16(6, 1);
full.set(
  [192, 12, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 0, 2, 9],
  query.byteLength
);
assert.equal(decode(full).answers[0].data, "192.0.2.9");
