#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Offline conversion of a reviewed DB-IP-style country CSV, never a downloader."""
import argparse
import csv
import hashlib
import ipaddress
import re
from pathlib import Path


class Ranges:
    def __init__(self, width):
        self.width = width
        self.end = -1
        self.code = None
        self.data = bytearray()

    def mark(self, start, code):
        if code == self.code:
            return  # coalesce adjacent ranges of the same country
        if len(self.data) + self.width + 2 > 16 * 1024 * 1024:
            raise ValueError("table exceeds the runtime's 16 MiB limit")
        self.data.extend(start.to_bytes(self.width, "big") + code)
        self.code = code

    def add(self, start, end, code):
        if start <= self.end or end < start:
            raise ValueError("reversed, overlapping or unsorted range")
        if start > self.end + 1:
            self.mark(self.end + 1, b"ZZ")  # don't extend a country across a gap
        self.mark(start, code)
        self.end = end

    def finish(self):
        if self.end + 1 < 1 << (8 * self.width):
            self.mark(self.end + 1, b"ZZ")
        return self.data


def convert(source, dest):
    tables = {}
    if not source.is_file() or source.stat().st_size > 256 * 1024 * 1024:
        raise ValueError("expected a local, uncompressed country CSV of at most 256 MiB")
    with source.open("rb") as f:
        for n, line in enumerate(iter(lambda: f.readline(256), b""), 1):
            try:
                if len(line) >= 256 or b"%" in line:
                    raise ValueError("invalid address row")
                first, last, cc = next(csv.reader([line.decode("ascii")], strict=True))
                a, b = ipaddress.ip_address(first), ipaddress.ip_address(last)
                if a.version != b.version or not re.fullmatch("[A-Z]{2}", cc):
                    raise ValueError("invalid family or code")
                if a.version not in tables:
                    tables[a.version] = Ranges(len(a.packed))
                tables[a.version].add(int(a), int(b), cc.encode("ascii"))
            except (ValueError, csv.Error) as e:
                raise ValueError(f"invalid country CSV at line {n}: {e}") from e
    if not tables:
        raise ValueError("empty country CSV")
    outputs = [(v, t.finish()) for v, t in sorted(tables.items())]
    dest.mkdir()  # new version directory only; never overwrite an approved table
    for v, data in outputs:
        with (dest / f"dbip.v{v}").open("xb") as out:
            out.write(data)
    for v, data in outputs:
        print(f"GEOIP_V{v}_PIN={len(data)}:{hashlib.sha256(data).hexdigest()}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv", type=Path, help="start IP,end IP,two-letter country; no header")
    parser.add_argument("output", type=Path, help="new directory for versioned reference files")
    args = parser.parse_args()
    try:
        convert(args.csv, args.output)
    except (OSError, ValueError) as error:
        parser.exit(1, f"{error}\n")
