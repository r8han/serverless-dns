/*
 * Copyright (c) 2021 RethinkDNS and its authors.
 * SPDX-License-Identifier: MPL-2.0
 */
// Only idle, connected sockets belong to the pool. A transaction exclusively
// owns a checked-out socket. Node close/error listeners receive an error or
// a flag, *not* the socket that emitted it: capture the actual owner.
export class IdlePool {
  constructor(tcp, capacity, ttl) {
    this.tcp = tcp;
    this.capacity = capacity;
    this.ttl = ttl;
    this.idle = new Map();
  }

  usable(sock) {
    return (
      !!sock &&
      (!this.tcp || (sock.readyState === "open" && !sock.readableLength))
    );
  }

  give(sock) {
    if (!this.usable(sock)) return false;
    if (this.idle.has(sock)) return true;
    if (this.idle.size >= this.capacity) return false;
    const evict = () => this.discard(sock);
    const expires = Date.now() + this.ttl;
    const timer = setTimeout(evict, this.ttl);
    timer.unref?.();
    this.idle.set(sock, { evict, expires, timer });
    sock.once("close", evict).once("error", evict);
    // An unsolicited message is not a reply to the next pool user.
    sock.once(this.tcp ? "data" : "message", evict);
    if (this.tcp) sock.once("end", evict);
    return true;
  }

  remove(sock) {
    const entry = this.idle.get(sock);
    if (!entry) return;
    this.idle.delete(sock);
    clearTimeout(entry.timer);
    const fn = entry.evict;
    sock
      .off("close", fn)
      .off("error", fn)
      .off(this.tcp ? "data" : "message", fn);
    if (this.tcp) sock.off("end", fn);
  }

  take() {
    for (const [sock, entry] of this.idle) {
      if (Date.now() < entry.expires && this.usable(sock)) {
        this.remove(sock);
        return sock;
      }
      this.discard(sock);
    }
    return null;
  }

  discard(sock) {
    if (!sock) return;
    this.remove(sock);
    // Also used for a transaction's connect/I/O failure. Do not emit an
    // unhandled asynchronous error while closing a partially opened socket.
    sock.on("error", () => {});
    if (this.tcp) sock.destroy();
    else {
      try {
        sock.close();
      } catch {
        /* already closed, or bind did not succeed */
      }
    }
  }

  drain() {
    for (const sock of this.idle.keys()) this.discard(sock);
  }
}
