// SPDX-License-Identifier: MPL-2.0
import assert from "node:assert/strict";
import http from "node:http";
import http2 from "node:http2";
import net from "node:net";
import { setTimeout as delay } from "node:timers/promises";
import { test } from "node:test";
import { createServer } from "../../src/core/node/cleartext-http.js";

const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
// an empty SETTINGS frame: length 0, type 4, no flags, stream 0
const settings = Uint8Array.of(0, 0, 0, 4, 0, 0, 0, 0, 0);

const handler = (_req, res) => {
  res.writeHead(200, { "content-type": "text/plain" });
  res.end("cleartext-ok");
};

/** @returns {Promise<{server: import("node:net").Server, port: number}>} */
async function listen() {
  const server = createServer({ keepAlive: true, noDelay: true }, handler);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { server, port: server.address().port };
}

const close = (server) => new Promise((resolve) => server.close(resolve));

test("serves HTTP/1.1", async (t) => {
  const { server, port } = await listen();
  t.after(() => close(server));

  const body = await new Promise((resolve, reject) => {
    const req = http.request(
      { host: "127.0.0.1", port, path: "/dns-query", method: "POST" },
      (res) => {
        let text = "";
        res.setEncoding("utf8");
        res.on("data", (d) => (text += d));
        res.on("end", () => resolve({ status: res.statusCode, text }));
      }
    );
    req.on("error", reject);
    req.end("hello");
  });

  assert.equal(body.status, 200);
  assert.equal(body.text, "cleartext-ok");
});

test("HTTP/1.1 is not misread when a header contains HTTP/2.0", async (t) => {
  const { server, port } = await listen();
  t.after(() => close(server));

  // the old selection scanned the first write for "HTTP/2.0" and handed such
  // a request to the HTTP/2 parser, which fails closed; it is valid HTTP/1.1
  const res = await new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: "127.0.0.1",
        port,
        path: "/dns-query?prior=HTTP/2.0",
        method: "GET",
        headers: { "user-agent": "HTTP/2.0 compat probe" },
      },
      (res) => {
        res.resume();
        res.on("end", () => resolve(res.statusCode));
      }
    );
    req.on("error", reject);
    req.end();
  });

  assert.equal(res, 200);
});

test("serves h2c", async (t) => {
  const { server, port } = await listen();
  t.after(() => close(server));

  const session = http2.connect(`http://127.0.0.1:${port}`);
  t.after(() => session.close());

  const reply = await new Promise((resolve, reject) => {
    const req = session.request({ ":path": "/dns-query", ":method": "POST" });
    let status = 0;
    let text = "";
    req.on("response", (headers) => (status = headers[":status"]));
    req.setEncoding("utf8");
    req.on("data", (d) => (text += d));
    req.on("end", () => resolve({ status, text }));
    req.on("error", reject);
    req.end("hello");
  });

  assert.equal(reply.status, 200);
  assert.equal(reply.text, "cleartext-ok");
});

test("a preface split across writes is still h2c", async (t) => {
  const { server, port } = await listen();
  t.after(() => close(server));

  const socket = net.connect(port, "127.0.0.1");
  t.after(() => socket.destroy());
  await new Promise((resolve) => socket.once("connect", resolve));

  socket.write(preface.slice(0, 9)); // "PRI * HT"
  await delay(30);
  socket.write(preface.slice(9));
  socket.write(settings);

  const frame = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("no h2 frame")), 2000);
    socket.once("data", (buf) => {
      clearTimeout(timer);
      resolve(buf);
    });
    socket.once("error", reject);
  });

  // server SETTINGS: length(3) type(1) flags(1) stream id(4)
  assert.ok(frame.length >= 9, "frame header received");
  assert.equal(frame[3], 4, "frame type 4 is SETTINGS");
});

test("a TLS ClientHello is refused, not parsed as DNS", async (t) => {
  const { server, port } = await listen();
  t.after(() => close(server));

  const socket = net.connect(port, "127.0.0.1");
  t.after(() => socket.destroy());
  await new Promise((resolve) => socket.once("connect", resolve));

  // record type 22 (handshake); no certificate is configured on this listener
  socket.write(Buffer.from([22, 3, 1, 0, 5, 1, 2, 3, 4, 5]));
  socket.resume();

  const closed = await new Promise((resolve) => {
    const timer = setTimeout(() => resolve("open"), 2000);
    socket.once("close", () => {
      clearTimeout(timer);
      resolve("closed");
    });
  });

  assert.equal(closed, "closed", "the handshake is dropped");
});

test("request handlers and server errors are forwarded", async (t) => {
  const { server, port } = await listen();
  t.after(() => close(server));

  assert.equal(server.http.listenerCount("request") > 0, true);
  assert.equal(server.http2.listenerCount("request") > 0, true);

  const log = [];
  server.on("clientError", () => log.push("clientError"));
  // forwarded to both protocol servers, so garbage is reported, not ignored
  const socket = net.connect(port, "127.0.0.1");
  t.after(() => socket.destroy());
  await new Promise((resolve) => socket.once("connect", resolve));
  socket.write("NOT A REQUEST\r\n\r\n");
  socket.resume();
  await delay(100);

  assert.deepEqual(log, ["clientError"]);
});
