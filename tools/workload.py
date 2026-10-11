"""Workloads with exact ground truth, shared by the sample builder and the benchmark.

Each version of each file starts with a unique token, so recovery is scored by
finding tokens in what the tool returns rather than by trusting recovered
names. A truth file lists every version together with its final state. Whether
a version still physically exists is decided later, straight from the raw
image, which keeps two different questions apart. Did the flash keep the data,
and did the tool find it.

Run it with the mounted command on a Linux host to drive a real kernel
filesystem, which is how the nandsim benches for JFFS2 and UBIFS are produced.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import struct
import sys
import zlib
from dataclasses import dataclass
from pathlib import Path

WORDS = ("sensor", "reading", "temp", "humidity", "retry", "uplink", "gateway", "battery",
         "status", "event", "door", "motion", "frame", "config", "session", "wifi")

LFS_CONFIG = dict(block_size=4096, block_count=128, read_size=16, prog_size=16,
                  cache_size=256, lookahead_size=16)


@dataclass
class Version:
    path: str
    token: str
    content: bytes
    state: str = "live"
    phase: str = "main"


class Tracker:
    """Records every version written and settles each one's final state."""

    def __init__(self, prefix: str, seed: int):
        self.rng = random.Random(seed)
        self.prefix = prefix
        self.counter = 0
        self.current: dict[str, Version] = {}
        self.versions: list[Version] = []
        self.phase = "main"

    def content(self, size: int) -> tuple[str, bytes]:
        self.counter += 1
        token = f"RVN-{self.prefix}-{self.counter:05d}-{self.rng.getrandbits(40):010x}"
        parts, length = [token], len(token)
        while length < size:
            word = f"{self.rng.choice(WORDS)}{self.rng.randint(0, 999)}"
            parts.append(word)
            length += len(word) + 1
        return token, " ".join(parts).encode()[:max(size, len(token))]

    def wrote(self, path: str, token: str, data: bytes) -> None:
        prev = self.current.get(path)
        if prev is not None:
            prev.state = "obsolete"
        version = Version(path, token, data, "live", self.phase)
        self.current[path] = version
        self.versions.append(version)

    def deleted(self, path: str) -> None:
        version = self.current.pop(path, None)
        if version is not None:
            version.state = "deleted"

    def truth(self, image: str, filesystem: str, generator: str, **extra) -> dict:
        items = [{"path": v.path, "state": v.state, "token": v.token,
                  "sha256": hashlib.sha256(v.content).hexdigest(), "size": len(v.content),
                  "phase": v.phase} for v in self.versions]
        return {"image": image, "filesystem": filesystem, "generator": generator, "items": items, **extra}


def _pool(tracker: Tracker, dirs) -> list[str]:
    return [p for p in tracker.current if p.rsplit("/", 1)[0] in dirs]


# LittleFS through the reference implementation.
def littlefs_workload(seed: int, ops: int = 60, churn: int = 0, config: dict | None = None):
    from littlefs import LittleFS

    cfg = dict(LFS_CONFIG, **(config or {}))
    fs = LittleFS(**cfg)
    t = Tracker(f"L{seed:04d}", seed)
    rng = t.rng
    for d in ("/logs", "/cfg", "/noise"):
        fs.mkdir(d)

    def step(dirs, prefix, max_live):
        live = _pool(t, dirs)
        r = rng.random()
        try:
            if not live or (r < 0.4 and len(live) < max_live) or len(live) < 3:
                path = f"{rng.choice(dirs)}/{prefix}{t.counter:05d}.dat"
            elif r < 0.7:
                path = rng.choice(live)
            else:
                path = rng.choice(live)
                fs.remove(path)
                t.deleted(path)
                return
            size = rng.randint(24, 200) if rng.random() < 0.6 else rng.randint(600, 6000)
            token, data = t.content(size)
            with fs.open(path, "wb") as fh:
                fh.write(data)
            t.wrote(path, token, data)
        except Exception:
            pass  # a full filesystem simply skips the step

    for _ in range(ops):
        step(["", "/logs", "/cfg"], "f", 30)
    t.phase = "churn"
    for _ in range(churn):
        step(["/noise"], "n", 12)
    return bytes(fs.context.buffer), t, cfg


def littlefs_live_view(raw: bytes, cfg: dict) -> dict[str, bytes]:
    """Mount an image with the reference implementation and read every live file.

    This is the baseline a conventional extractor gives you, the live tree and
    nothing else.
    """
    from littlefs import LittleFS
    from littlefs.context import UserContext

    ctx = UserContext(len(raw))
    ctx.buffer[:] = raw
    fs = LittleFS(context=ctx, **cfg)
    out = {}
    for root, _, files in fs.walk("/"):
        for name in files:
            path = f"{root.rstrip('/')}/{name}"
            with fs.open(path, "rb") as fh:
                out[path] = fh.read()
    return out


# JFFS2 nodes written by hand with the kernel's CRC convention.
def _jcrc(data: bytes) -> int:
    return zlib.crc32(data, 0xFFFFFFFF) ^ 0xFFFFFFFF


class JFFS2Writer:
    """Appends spec conformant JFFS2 nodes to a log, like a filesystem that never ran GC."""

    def __init__(self):
        self.buf = bytearray()
        self.next_ino = 2
        self.ino_version: dict[int, int] = {}
        self.dir_version: dict[int, int] = {}
        self.nodes: dict[int, list[int]] = {}
        self.clock = 1_750_000_000

    def _emit(self, node: bytes) -> int:
        offset = len(self.buf)
        self.buf += node + b"\xff" * ((-len(node)) % 4)
        return offset

    def dirent(self, pino: int, ino: int, name: str, dtype: int = 8) -> int:
        nb = name.encode()
        self.dir_version[pino] = self.dir_version.get(pino, 0) + 1
        hdr = struct.pack("<HHI", 0x1985, 0xE001, 40 + len(nb))
        pre = hdr + struct.pack("<I", _jcrc(hdr)) + struct.pack(
            "<IIIIBBH", pino, self.dir_version[pino], ino, self.clock, len(nb), dtype, 0)
        return self._emit(pre + struct.pack("<II", _jcrc(pre), _jcrc(nb)) + nb)

    def inode(self, ino: int, data: bytes, doff: int, isize: int, compress: bool = False, mode=0o100644) -> int:
        self.ino_version[ino] = self.ino_version.get(ino, 0) + 1
        self.clock += 1
        payload, compr = (zlib.compress(data), 6) if compress and data else (data, 0)
        hdr = struct.pack("<HHI", 0x1985, 0xE002, 68 + len(payload))
        pre = hdr + struct.pack("<I", _jcrc(hdr)) + struct.pack(
            "<IIIHHIIIIIIIBBH", ino, self.ino_version[ino], mode, 0, 0, isize, self.clock,
            self.clock, self.clock, doff, len(payload), len(data), compr, 0, 0)
        off = self._emit(pre + struct.pack("<II", _jcrc(payload), _jcrc(pre)) + payload)
        self.nodes.setdefault(ino, []).append(off)
        return off

    def new_ino(self) -> int:
        self.next_ino += 1
        return self.next_ino - 1

    def mkdir(self, pino: int, name: str) -> int:
        ino = self.new_ino()
        self.inode(ino, b"", 0, 0, mode=0o040755)
        self.dirent(pino, ino, name, dtype=4)
        return ino

    def write_file(self, ino: int, data: bytes, compress: bool = False) -> None:
        for start in range(0, max(len(data), 1), 4096):
            self.inode(ino, data[start:start + 4096], start, len(data), compress)

    def truncate(self, ino: int, size: int = 0) -> None:
        self.inode(ino, b"", size, size)

    def mark_obsolete(self, offset: int) -> None:
        """Clear the accurate bit the way the kernel does on NOR flash."""
        ntype = struct.unpack_from("<H", self.buf, offset + 2)[0]
        struct.pack_into("<H", self.buf, offset + 2, ntype & ~0x2000)

    def image(self, tail: int = 4096) -> bytes:
        return bytes(self.buf) + b"\xff" * tail


def jffs2_workload(seed: int, ops: int = 60):
    t = Tracker(f"J{seed:04d}", seed)
    rng = t.rng
    w = JFFS2Writer()
    dirs = {"": 1, "/logs": w.mkdir(1, "logs")}
    inode_of: dict[str, int] = {}
    for _ in range(ops):
        live = list(t.current)
        r = rng.random()
        size = rng.randint(24, 400) if rng.random() < 0.6 else rng.randint(1000, 10000)
        if not live or r < 0.4 or len(live) < 3:
            parent = rng.choice(list(dirs))
            path = f"{parent}/f{t.counter:05d}.dat"
            ino = w.new_ino()
            token, data = t.content(size)
            w.write_file(ino, data, compress=rng.random() < 0.3)
            w.dirent(dirs[parent], ino, path.rsplit("/", 1)[1])
            inode_of[path] = ino
            t.wrote(path, token, data)
        elif r < 0.7:
            path = rng.choice(live)
            ino = inode_of[path]
            old = list(w.nodes.get(ino, []))
            w.truncate(ino, 0)
            token, data = t.content(size)
            w.write_file(ino, data, compress=rng.random() < 0.3)
            if rng.random() < 0.3:
                for off in old:
                    w.mark_obsolete(off)
            t.wrote(path, token, data)
        else:
            path = rng.choice(live)
            parent, name = path.rsplit("/", 1)
            w.dirent(dirs[parent], 0, name, dtype=0)
            t.deleted(path)
    return w.image(), t


# UBIFS nodes written by hand, for parser checks only.
def _ucrc(data: bytes) -> int:
    return zlib.crc32(data) ^ 0xFFFFFFFF


class UBIFSWriter:
    def __init__(self):
        self.buf = bytearray()
        self.sqnum = 0

    def _node(self, ntype: int, body: bytes) -> int:
        self.sqnum += 1
        rest = struct.pack("<QIBBxx", self.sqnum, 24 + len(body), ntype, 0) + body
        node = struct.pack("<II", 0x06101831, _ucrc(rest)) + rest
        offset = len(self.buf)
        self.buf += node + b"\x00" * ((-len(node)) % 8)
        return offset

    def ino(self, inum: int, size: int, nlink: int = 1, mode: int = 0o100644) -> int:
        key = struct.pack("<II", inum, 0) + bytes(8)
        body = key + struct.pack("<QQQQQIIIIIIIIIII4sIH26s", self.sqnum, size, 1_750_000_000,
                                 1_750_000_000, 1_750_000_000, 0, 0, 0, nlink, 0, 0, mode, 0, 0, 0, 0,
                                 bytes(4), 0, 0, bytes(26))
        return self._node(0, body)

    def data(self, inum: int, block: int, payload: bytes, compress: bool = False) -> int:
        key = struct.pack("<II", inum, (1 << 29) | block) + bytes(8)
        if compress:
            c = zlib.compressobj(6, zlib.DEFLATED, -15)
            stored, ctype = c.compress(payload) + c.flush(), 2
        else:
            stored, ctype = payload, 0
        return self._node(1, key + struct.pack("<IHH", len(payload), ctype, 0) + stored)

    def dent(self, parent: int, name: str, inum: int, itype: int = 0) -> int:
        nb = name.encode()
        key = struct.pack("<II", parent, (2 << 29) | (zlib.crc32(nb) & 0x1FFFFFFF)) + bytes(8)
        return self._node(2, key + struct.pack("<QBBHI", inum, 0, itype, len(nb), 0) + nb + b"\x00")

    def image(self, tail: int = 4096) -> bytes:
        return bytes(self.buf) + b"\xff" * tail


def mounted_workload(directory: str, seed: int, ops: int, churn: int) -> Tracker:
    """Drive a real mounted filesystem with ordinary file calls, for nandsim benches."""
    base = Path(directory)
    t = Tracker(f"H{seed:04d}", seed)
    rng = t.rng
    for sub in ("logs", "cfg", "noise"):
        (base / sub).mkdir(exist_ok=True)

    def step(dirs, prefix, max_live):
        live = _pool(t, dirs)
        r = rng.random()
        if not live or (r < 0.4 and len(live) < max_live) or len(live) < 3:
            path = f"{rng.choice(dirs)}/{prefix}{t.counter:05d}.dat"
        elif r < 0.7:
            path = rng.choice(live)
        else:
            path = rng.choice(live)
            os.remove(base / path.lstrip("/"))
            t.deleted(path)
            return
        size = rng.randint(24, 200) if rng.random() < 0.6 else rng.randint(600, 12000)
        token, data = t.content(size)
        with open(base / path.lstrip("/"), "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        t.wrote(path, token, data)

    for _ in range(ops):
        step(["", "/logs", "/cfg"], "f", 30)
    t.phase = "churn"
    for _ in range(churn):
        step(["/noise"], "n", 12)
    os.sync()
    return t


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Run a ground truth workload on a mounted filesystem.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("mounted", help="write files into a mounted filesystem and save the truth file")
    m.add_argument("--dir", required=True)
    m.add_argument("--seed", type=int, default=1)
    m.add_argument("--ops", type=int, default=60)
    m.add_argument("--churn", type=int, default=0)
    m.add_argument("--image-name", required=True)
    m.add_argument("--filesystem", required=True)
    m.add_argument("--truth", required=True)
    m.add_argument("--compressed", action="store_true",
                   help="the filesystem compresses data, so raw token search cannot prove survival")
    args = ap.parse_args(argv)
    t = mounted_workload(args.dir, args.seed, args.ops, args.churn)
    truth = t.truth(args.image_name, args.filesystem, "kernel filesystem on nandsim",
                    seed=args.seed, churn=args.churn)
    truth["survival"] = "unknown" if args.compressed else "scan"
    Path(args.truth).write_text(json.dumps(truth, indent=2))
    print(f"wrote {len(truth['items'])} truth items to {args.truth}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
