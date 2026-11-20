// SPDX-License-Identifier: MPL-2.0

/**
 * Retained memory, not the number of entries, is what has to be bounded in
 * the answer cache: a single cached upstream answer can be as large as a DNS
 * packet (4 KiB), so an entry-count cap of 30000 admits ~120 MB of payload
 * inside a 128 MB isolate. See docs/security/2026-11-20/audit.md (MEM-01).
 */

// bytes not attributable to a single field: the entry object, its Map slot,
// the value's property storage and the JS string holding the key
const bookkeeping = 128;

// bytes for one stamps field: key string, Uint16Array header and backing store
const stampOverhead = 48;
const stampWidth = 2; // Uint16Array elements are 2 bytes each; strings 2/char

/**
 * @typedef {{bytes: Uint8Array, time: number, stamps: any}} CachedAnswer
 * @typedef {CachedAnswer & {cost: number}} ChargedAnswer
 */

/**
 * Charge an entry its wire bytes plus the memory needed to hold them and the
 * key. Approximate by design: the cache only needs a monotonic, conservative
 * estimate, and stamps are small (one Uint16Array per name in the answer).
 *
 * @param {string} key
 * @param {CachedAnswer} answer
 * @returns {number} bytes to charge, or 0 if the answer is not chargeable
 */
export function charge(key, answer) {
  const len = answer?.bytes?.byteLength;
  if (!Number.isSafeInteger(len) || len <= 0 || typeof key !== "string") {
    return 0;
  }
  let stamps = 0;
  for (const [name, flags] of Object.entries(answer.stamps || {})) {
    stamps += (name.length + flags.length) * stampWidth + stampOverhead;
  }
  return len + key.length * stampWidth + stamps + bookkeeping;
}

/**
 * Least-recently-used cache of upstream answers bounded by both entries and
 * bytes. Both limits hold after every put; an entry too large for the whole
 * budget is refused instead of being admitted and immediately evicted.
 */
export class AnswerCache {
  /**
   * @param {number} maxEntries
   * @param {number} maxBytes
   */
  constructor(maxEntries, maxBytes) {
    this.maxEntries = Math.max(1, Math.trunc(maxEntries) || 1);
    this.maxBytes = Math.max(0, Math.trunc(maxBytes) || 0);
    /** @type {Map<string, ChargedAnswer>} */
    this.entries = new Map();
    // bytes currently charged to this cache
    this.charged = 0;
  }

  get size() {
    return this.entries.size;
  }

  get bytes() {
    return this.charged;
  }

  /**
   * @param {string} key
   * @returns {CachedAnswer?}
   */
  get(key) {
    const answer = this.entries.get(key);
    if (!answer) return null;
    // Map iterates in insertion order: re-inserting the same object moves it
    // to the newest end, which is the recency update without a second store.
    this.entries.delete(key);
    this.entries.set(key, answer);
    return answer;
  }

  /**
   * @param {string} key
   * @param {CachedAnswer} answer
   * @returns {boolean} whether the answer is now cached
   */
  put(key, answer) {
    const cost = charge(key, answer);
    // never trade the whole cache for one answer
    if (cost <= 0 || cost > this.maxBytes) return false;
    this.drop(key); // replacing must not charge the same key twice
    this.entries.set(key, { ...answer, cost });
    this.charged += cost;
    this.trim();
    return true;
  }

  /**
   * @param {string} key
   */
  drop(key) {
    const answer = this.entries.get(key);
    if (!answer) return;
    this.entries.delete(key);
    this.charged -= answer.cost;
  }

  trim() {
    for (const [key, answer] of this.entries) {
      if (
        this.entries.size <= this.maxEntries &&
        this.charged <= this.maxBytes
      ) {
        return;
      }
      // deleting the current entry is safe while iterating a Map
      this.entries.delete(key);
      this.charged -= answer.cost;
    }
  }
}
