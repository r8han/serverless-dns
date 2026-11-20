// SPDX-License-Identifier: MPL-2.0
import assert from "node:assert/strict";
import { test } from "node:test";
import { AnswerCache, charge } from "../../src/plugins/dns-op/answer-cache.js";

const answer = (size, stamps = null) => ({
  bytes: new Uint8Array(size).fill(7),
  time: Date.now(),
  stamps,
});

// a key shaped like the real one: a URL with encoded question fields
const key = (n) =>
  "https://caches.rethinkdns.com/verified-v2/" +
  encodeURIComponent(JSON.stringify(["rev", false, n]));

test("charges wire bytes, key and stamps", () => {
  const one = charge(key(1), answer(64));
  const two = charge(key(1), answer(1024));
  assert.ok(two > one, "larger wire bytes cost more");
  assert.ok(two - one >= 960, "cost tracks byteLength");

  const stamped = charge(
    key(1),
    answer(64, { "a.example": Uint16Array.of(1, 2) })
  );
  assert.ok(stamped > one, "stamps are charged");

  assert.equal(charge(key(1), { time: 0 }), 0, "no bytes, no charge");
  assert.equal(
    charge(key(1), { bytes: new Uint8Array(0) }),
    0,
    "empty is free"
  );
});

test("never exceeds the byte budget", () => {
  const budget = 64 * 1024;
  const cache = new AnswerCache(100000, budget);
  for (let i = 0; i < 10000; i++) {
    cache.put(key(i), answer(4096)); // worst case: a full DNS packet each
    assert.ok(cache.bytes <= budget, `charged ${cache.bytes} > ${budget}`);
  }
  // at most budget/4096 full-sized entries fit
  assert.ok(cache.size <= Math.ceil(budget / 4096));
  assert.ok(cache.size > 0);
});

test("never exceeds the entry budget", () => {
  const cache = new AnswerCache(10, 1024 * 1024);
  for (let i = 0; i < 100; i++) cache.put(key(i), answer(16));
  assert.equal(cache.size, 10);
  assert.ok(cache.bytes <= 1024 * 1024);
});

test("evicts least recently used, counting reads as use", () => {
  const cache = new AnswerCache(3, 1024 * 1024);
  cache.put("a", answer(8));
  cache.put("b", answer(8));
  cache.put("c", answer(8));
  assert.ok(cache.get("a"), "a is cached");
  cache.put("d", answer(8)); // b is now the oldest
  assert.equal(cache.get("b"), null, "b was evicted");
  assert.ok(cache.get("a"), "a survived");
  assert.ok(cache.get("c"), "c survived");
  assert.ok(cache.get("d"), "d is cached");
  assert.equal(cache.size, 3);
});

test("replacing a key is charged once", () => {
  const cache = new AnswerCache(4, 1024 * 1024);
  cache.put("a", answer(64));
  const first = cache.bytes;
  cache.put("a", answer(64));
  assert.equal(cache.bytes, first, "same size, same charge");
  cache.put("a", answer(4096));
  assert.ok(cache.bytes > first, "charge follows the larger value");
  assert.equal(cache.size, 1);
});

test("refuses an entry that cannot fit the whole budget", () => {
  const cache = new AnswerCache(100, 2048);
  assert.equal(cache.put("big", answer(4096)), false);
  assert.equal(cache.size, 0, "nothing admitted");
  assert.equal(cache.bytes, 0, "nothing charged");
  assert.equal(cache.get("big"), null);

  assert.equal(cache.put("small", answer(64)), true);
  assert.ok(cache.get("small"));
});

test("mixed sizes keep both limits", () => {
  const budget = 16 * 1024;
  const cache = new AnswerCache(50, budget);
  for (let i = 0; i < 500; i++) {
    cache.put(key(i), answer(i % 2 ? 4096 : 64));
    assert.ok(cache.bytes <= budget);
    assert.ok(cache.size <= 50);
  }
});

test("the returned answer is the stored one", () => {
  const cache = new AnswerCache(4, 1024 * 1024);
  const value = answer(32, { "x.example": Uint16Array.of(3) });
  cache.put("k", value);
  const hit = cache.get("k");
  assert.deepEqual(hit.bytes, value.bytes);
  assert.equal(hit.time, value.time);
  assert.deepEqual(hit.stamps, value.stamps);
  assert.equal(typeof hit.cost, "number");
});
