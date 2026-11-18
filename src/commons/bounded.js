// SPDX-License-Identifier: MPL-2.0
import { checkAlive } from "./cancel.js";
// A declared length is only an early rejection hint. Count delivered bytes,
// stop pulling on overflow, and abort a stalled read at the request deadline.
export async function readBounded(message, limit, signal, exact = false) {
  const body = message.body;
  const length = message.headers.get("content-length");
  if (length !== null && (!/^\d+$/.test(length) || Number(length) > limit)) {
    body?.cancel().catch(() => {});
    throw new RangeError("body too large");
  }
  if (!body) {
    if (exact && limit) throw new RangeError("incomplete body");
    return new ArrayBuffer(0);
  }
  const reader = body.getReader();
  const abort = () => reader.cancel().catch(() => {});
  signal?.addEventListener("abort", abort, { once: true });
  let n = 0;
  // Do not keep a distinct object for every chunk: a byte limit alone
  // otherwise permits millions of chunk references for one JSON artifact.
  let buffer = new Uint8Array(exact ? limit : Math.min(4096, limit));
  try {
    for (;;) {
      checkAlive(signal);
      const { done, value } = await reader.read();
      checkAlive(signal);
      if (done) break;
      const needed = n + value.byteLength;
      if (needed > limit) throw new RangeError("body too large");
      if (needed > buffer.length) {
        const grown = new Uint8Array(
          Math.min(limit, Math.max(needed, buffer.length * 2))
        );
        grown.set(buffer.subarray(0, n));
        buffer = grown;
      }
      buffer.set(value, n);
      n = needed;
    }
    if (exact && n !== limit) throw new RangeError("incomplete body");
    return n === buffer.length ? buffer.buffer : buffer.buffer.slice(0, n);
  } catch (error) {
    abort();
    throw error;
  } finally {
    signal?.removeEventListener("abort", abort);
    reader.releaseLock();
  }
}

// Node's HTTP/1 and HTTP/2 request streams arrive before a Fetch Request
// exists. Pause immediately on rejection; the caller closes the stream.
export function readIncoming(req, limit, signal) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    function finish(error) {
      req.pause();
      req.off("data", data);
      req.off("end", end);
      req.off("error", failed);
      req.off("aborted", failed);
      signal.removeEventListener("abort", failed);
      if (error) reject(error);
      else resolve(chunks);
    }
    const failed = () => finish(new Error("read aborted"));
    const end = () => finish();
    const data = (chunk) => {
      size += chunk.byteLength;
      if (size > limit) finish(new RangeError("body too large"));
      else chunks.push(chunk);
    };
    const declared = req.headers["content-length"];
    if (
      declared != null &&
      (!/^\d+$/.test(declared) || Number(declared) > limit)
    ) {
      return finish(new RangeError("body too large"));
    }
    if (signal.aborted) return failed();
    signal.addEventListener("abort", failed, { once: true });
    req
      .on("error", failed)
      .on("aborted", failed)
      .on("end", end)
      .on("data", data);
  });
}
