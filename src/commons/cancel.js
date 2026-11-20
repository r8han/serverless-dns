// SPDX-License-Identifier: MPL-2.0
// One owner for a deadline and its parent listeners. Prefer native fetch
// cancellation. Some edge hosts do not implement Fetch's signal option:
// still stop application work and stream reads, with backend I/O limits.
export function cancelScope(parents = [], timeout = null) {
  const callbacks = new Set();
  const controller =
    typeof AbortController === "function" ? new AbortController() : null;
  const signal = controller?.signal ?? {
    aborted: false,
    addEventListener(_, fn) {
      callbacks.add(fn);
    },
    removeEventListener(_, fn) {
      callbacks.delete(fn);
    },
  };
  let timer;
  function close() {
    clearTimeout(timer);
    for (const parent of parents) parent?.removeEventListener("abort", close);
    if (signal.aborted) return;
    if (controller) controller.abort();
    else {
      signal.aborted = true;
      for (const fn of callbacks) fn();
      callbacks.clear();
    }
  }
  for (const p of parents) p?.addEventListener("abort", close, { once: true });
  if (timeout != null) timer = setTimeout(close, Math.max(0, timeout));
  if (parents.some((p) => p?.aborted)) close();
  return { signal, close };
}
export function checkAlive(signal) {
  if (signal?.aborted) throw new Error("operation cancelled");
}
export function fetchSignal(signal) {
  return typeof AbortSignal !== "undefined" && signal instanceof AbortSignal
    ? { signal }
    : {};
}
// Provider APIs without signal support may continue until the host deadline;
// don't start any dependent operation after our caller has left.
export function whileAlive(promise, signal) {
  if (!signal) return promise;
  return new Promise((resolve, reject) => {
    const abort = () => reject(new Error("operation cancelled"));
    if (signal.aborted) abort();
    else signal.addEventListener("abort", abort, { once: true });
    Promise.resolve(promise)
      .then(resolve, reject)
      .finally(() => signal.removeEventListener("abort", abort));
  });
}

// Opening a response may outlive a timeout on hosts without native signal
// support (including cache/object-storage APIs). Release its unread body if
// headers arrive after the owner has left; never start a dependent fetch.
export function openResponse(open, signal) {
  checkAlive(signal);
  if (!signal) return open();
  return whileAlive(
    Promise.resolve(open()).then((res) => {
      if (signal.aborted) {
        res?.body?.cancel().catch(() => {});
        checkAlive(signal);
      }
      return res;
    }),
    signal
  );
}
