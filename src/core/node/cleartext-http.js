// SPDX-License-Identifier: MPL-2.0

import http from "node:http";
import http2 from "node:http2";
import net from "node:net";

/**
 * Cleartext HTTP/1.1 and h2c on one port, for the private backend interface
 * of a TLS-offloading frontend. Node cannot serve both from one server
 * (nodejs/node#34296), so the first bytes of a connection select the parser.
 *
 * The selection is anchored on the RFC 9113 §3.4 connection preface rather
 * than on the string "HTTP/2.0" appearing anywhere in the chunk: an HTTP/1.1
 * request may carry that string in a header value, a URL or an early body
 * part, and whether it does is up to how the frontend coalesces writes.
 */

// exactly 24 bytes; a client must send all of it before any frame
const preface = Buffer.from("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", "latin1");

// events an application may listen for on the wrapper, forwarded to whichever
// protocol server owns the connection
const forwarded = new Set([
  "checkContinue",
  "checkExpectation",
  "clientError",
  "connect",
  "request",
  "session",
  "sessionError",
  "stream",
  "timeout",
  "unknownProtocol",
]);

export class CleartextServer extends net.Server {
  /**
   * @param {net.ServerOpts} options
   * @param {http.RequestListener} requestListener
   */
  constructor(options, requestListener) {
    super(options);
    this.http = http.createServer(options, requestListener);
    this.http2 = http2.createServer(options, requestListener);
    // this server parses nothing: it owns the sockets only long enough to
    // decide which of the two servers above serves them, and to close them
    // on shutdown (an http2 server has no closeAllConnections)
    /** @type {Set<net.Socket>} */
    this.sockets = new Set();
    this.on("connection", (socket) => {
      this.sockets.add(socket);
      socket.once("close", () => this.sockets.delete(socket));
      this.sniff(socket);
    });
    // listeners added here (error, timeout, ...) must reach the real servers
    this.on("newListener", (event, listener) => {
      if (forwarded.has(event)) {
        this.http.on(event, listener);
        this.http2.on(event, listener);
      }
    });
    this.on("removeListener", (event, listener) => {
      if (forwarded.has(event)) {
        this.http.off(event, listener);
        this.http2.off(event, listener);
      }
    });
  }

  /**
   * Peek at the first bytes without consuming them, then replay them to the
   * selected server. Stays flowing while the bytes so far are still a prefix
   * of the preface, so a preface split across writes is not misread as
   * HTTP/1.1.
   *
   * @param {net.Socket} socket
   */
  sniff(socket) {
    /** @type {Buffer[]} */
    const chunks = [];
    let head = Buffer.alloc(0);

    /** @param {boolean} h2 */
    const handoff = (h2) => {
      socket.off("data", onData);
      socket.off("end", onClose);
      socket.off("close", onClose);
      // the socket is paused, so this is the only writer to its buffer
      socket.pause();
      for (let i = chunks.length - 1; i >= 0; i--) socket.unshift(chunks[i]);
      if (h2) {
        this.http2.emit("connection", socket);
      } else {
        // resume() defers reads to the next tick, after the HTTP/1.1 server
        // has attached its listeners to the unshifted bytes
        socket.resume();
        this.http.emit("connection", socket);
      }
    };

    const onClose = () => socket.destroy();

    /** @param {Buffer} chunk */
    const onData = (chunk) => {
      chunks.push(chunk);
      // only the preface's worth of bytes decides the protocol
      head = Buffer.concat([
        head,
        chunk.subarray(0, Math.max(0, preface.length - head.length)),
      ]);
      if (
        head.length < preface.length &&
        preface.subarray(0, head.length).equals(head)
      ) {
        return; // still undecided; keep the socket flowing
      }
      handoff(head.length === preface.length && head.equals(preface));
    };

    socket.on("data", onData);
    socket.once("end", onClose);
    socket.once("close", onClose);
  }

  setTimeout(...args) {
    this.http.setTimeout(...args);
    this.http2.setTimeout(...args);
    return this;
  }

  close(cb) {
    // stop the sockets before waiting on the handle, so a keep-alive or h2
    // session cannot hold shutdown open
    for (const socket of this.sockets) socket.destroy();
    this.sockets.clear();
    super.close(cb);
    // neither sub-server ever listens, but both hold live sessions
    this.http.close();
    this.http2.close();
  }
}

/**
 * @param {net.ServerOpts} options
 * @param {http.RequestListener} requestListener
 * @returns {CleartextServer}
 */
export function createServer(options, requestListener) {
  return new CleartextServer(options, requestListener);
}
