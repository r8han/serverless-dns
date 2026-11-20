// SPDX-License-Identifier: MPL-2.0
import { constants } from "node:fs";
import { open, realpath } from "node:fs/promises";
import { join, resolve } from "node:path";
import { validVersion } from "../../commons/blocklist-integrity.js";

export function generationDir(root, version) {
  if (!validVersion(version)) throw new Error("invalid blocklist version");
  return resolve(root, version.replace("/", "-"));
}

// The generation is read-only to the service user. Check the file handle,
// not just a path stat; do not follow links or block opening a FIFO.
export async function readBinary(dir, name, size) {
  if (name !== "td.txt" && name !== "rd.txt") throw new Error("unknown binary");
  const path = join(dir, name);
  if ((await realpath(path)) !== path) {
    throw new Error("unexpected blocklist path");
  }
  const file = await open(
    path,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK
  );
  try {
    const st = await file.stat();
    if (!st.isFile() || st.size !== size) {
      throw new Error("invalid blocklist size");
    }
    const data = new Uint8Array(size);
    for (let i = 0; i < size;) {
      const { bytesRead } = await file.read(data, i, size - i, i);
      if (!bytesRead) throw new Error("short blocklist file");
      i += bytesRead;
    }
    return data.buffer;
  } finally {
    await file.close();
  }
}
