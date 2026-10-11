"""LittleFS carver.

LittleFS keeps its metadata in pairs of blocks. Each block holds a revision
count followed by a log of commits, and every commit ends with a CRC. A change
is appended as one more commit until the block fills, and then the pair is
compacted into its other block with a higher revision. Earlier commits are
never edited in place, so a block usually still carries the older names and
contents that later commits replaced or deleted.

This carver replays that history the way littlefs does itself. It trusts only
commits whose CRC checks out, it follows the create and delete tags that shift
entry ids around, and it reads larger files through their CTZ skip lists. The
newest revision of every reachable pair gives the live tree. Everything else
the logs still hold is reported as deleted, obsolete, or orphaned.
"""

from __future__ import annotations

import struct
import zlib
from collections import deque
from dataclasses import dataclass, field
from typing import Iterator, Optional

from ..models import Artifact, ArtifactState, Confidence, ScanStats
from ..security import BoundedReader, Limits
from .base import FilesystemCarver

_TYPE_REG = 0x001
_TYPE_DIR = 0x002
_TYPE_SUPERBLOCK = 0x0FF
_TYPE_CREATE = 0x401
_TYPE_DELETE = 0x4FF
_TYPE_DIRSTRUCT = 0x200
_TYPE_INLINESTRUCT = 0x201
_TYPE_CTZSTRUCT = 0x202
_NULL_SIZE = 0x3FF
_NULL_ID = 0x3FF


def _lfs_crc(crc: int, data) -> int:
    # littlefs keeps the running register without the final inversion zlib adds.
    return zlib.crc32(data, crc ^ 0xFFFFFFFF) ^ 0xFFFFFFFF


def _ctz(n: int) -> int:
    return (n & -n).bit_length() - 1 if n else 0


def _popc(n: int) -> int:
    return bin(n).count("1")


def _ctz_index(pos: int, block_size: int) -> tuple[int, int]:
    """Block index and in block offset of a file position, mirroring lfs_ctz_index."""
    b = block_size - 8
    i = pos // b
    if i == 0:
        return 0, pos
    i = (pos - 4 * (_popc(i - 1) + 2)) // b
    return i, pos - b * i - 4 * _popc(i)


def _newer(a: int, b: int) -> bool:
    """Revision counts wrap around, so they are compared as sequence numbers."""
    return a != b and ((a - b) & 0xFFFFFFFF) < 0x80000000


def _skips_agree(reader: BoundedReader, chain: list, bs: int) -> bool:
    """Check every extra skip pointer against the chain it should describe.

    Block i of a CTZ list stores pointers to blocks i minus 1, i minus 2, i
    minus 4 and so on, as many as its trailing zero count allows. The first
    pointer is how the chain was walked, so the others are free evidence.
    """
    for i in range(2, len(chain)):
        n = _ctz(i) + 1
        if n < 2:
            continue
        ptrs = reader.read_at(chain[i] * bs, 4 * n)
        for k in range(1, n):
            if int.from_bytes(ptrs[4 * k:4 * k + 4], "little") != chain[i - (1 << k)]:
                return False
    return True


_ERASED_TAIL = b"\xff" * 16


def _opens_with_pointer(reader: BoundedReader, block: int, bs: int, bc: int) -> bool:
    """True when a block starts with a plausible block number.

    The first block of a CTZ file holds file data only, while every later block
    starts with a back pointer. A supposed first block that begins with a valid
    block number is therefore more likely the middle of some other chain. File
    data can start with a small number by chance, so this only lowers trust.
    """
    return int.from_bytes(reader.read_at(block * bs, 4), "little") < bc


def walk_commits(block: bytes, base: int = 0, max_commits: int = 0):
    """Return the tags of every CRC valid commit in one metadata block.

    Each tag comes back with its absolute data offset and its data. The walk
    stops at the first tag that fails validation, which is exactly where
    littlefs itself stops trusting a block.
    """
    n = len(block)
    if n < 12:
        return [], 0
    crc = _lfs_crc(0xFFFFFFFF, block[0:4])
    ptag = 0xFFFFFFFF
    off = 4
    commits = 0
    tags: list = []
    pending: list = []
    while off + 4 <= n:
        raw = block[off:off + 4]
        tag = int.from_bytes(raw, "big") ^ ptag
        if tag & 0x80000000:
            break
        size = tag & 0x3FF
        dlen = 0 if size == _NULL_SIZE else size
        if off + 4 + dlen > n:
            break
        crc = _lfs_crc(crc, raw)
        if (tag & 0x78000000) == 0x50000000:
            if off + 8 > n or crc != int.from_bytes(block[off + 4:off + 8], "little"):
                break
            tags.extend(pending)
            pending = []
            commits += 1
            if max_commits and commits >= max_commits:
                break
            # The low bit of a commit tag flips the valid bit expected next.
            ptag = tag ^ (((tag >> 20) & 1) << 31)
            crc = 0xFFFFFFFF
            off += 4 + dlen
            continue
        data = block[off + 4:off + 4 + dlen]
        crc = _lfs_crc(crc, data)
        pending.append((tag, base + off + 4, bytes(data)))
        ptag = tag
        off += 4 + dlen
    return tags, commits


@dataclass
class _Version:
    kind: str                  # inline or ctz
    data: bytes = b""
    head: int = 0
    size: int = 0
    offset: int = 0

    def key(self) -> tuple:
        return ("inline", self.data) if self.kind == "inline" else ("ctz", self.head, self.size)


@dataclass
class _Entry:
    name: Optional[str] = None
    ftype: Optional[int] = None
    version: Optional[_Version] = None
    history: list = field(default_factory=list)
    dirpair: Optional[tuple] = None


@dataclass
class _Meta:
    index: int
    rev: int
    entries: list
    removed: list
    softtails: list
    hardtails: list


class LittleFSCarver(FilesystemCarver):
    name = "littlefs"
    maturity = "replays CRC checked commits, follows id shifts and CTZ skip lists"

    def detect(self, reader: BoundedReader) -> bool:
        return self._geometry(reader) is not None

    def carve(self, reader: BoundedReader, stats: ScanStats) -> Iterator[Artifact]:
        geom = self._geometry(reader)
        if geom is None:
            return
        bs, bc = geom
        bc = min(bc, len(reader) // bs)
        metas: dict[int, _Meta] = {}
        for index in range(bc):
            block = reader.read_at(index * bs, bs)
            tags, commits = walk_commits(block, base=index * bs)
            if commits:
                stats.records_seen += len(tags)
                metas[index] = self._replay(index, block, tags)
        stats.bytes_scanned = bc * bs
        yield from self._classify(reader, metas, bs, bc)

    def _geometry(self, reader: BoundedReader) -> Optional[tuple[int, int]]:
        """Find the superblock by its name and read the geometry from it."""
        head = reader.read_at(0, min(len(reader), 4 * 1024 * 1024))
        pos = head.find(b"littlefs")
        while pos != -1:
            start = pos - 8
            if start >= 0:
                tags, _ = walk_commits(head[start:], max_commits=1)
                for tag, _, data in tags:
                    if ((tag >> 20) & 0x7FF) == _TYPE_INLINESTRUCT and ((tag >> 10) & 0x3FF) == 0 \
                            and len(data) >= 12:
                        _, bs, bc = struct.unpack_from("<III", data, 0)
                        if 128 <= bs <= 16 * 1024 * 1024 and bc >= 2 and start % bs == 0 \
                                and start // bs <= 1:
                            return bs, bc
            pos = head.find(b"littlefs", pos + 1)
        return None

    def _replay(self, index: int, block: bytes, tags: list) -> _Meta:
        """Replay the commits of one block, shifting ids the way littlefs does."""
        entries: list[_Entry] = []
        removed: list[_Entry] = []
        soft: list = []
        hard: list = []
        for tag, doff, data in tags:
            t3 = (tag >> 20) & 0x7FF
            tid = (tag >> 10) & 0x3FF
            group = t3 & 0x700
            if group == 0x400:
                if t3 == _TYPE_CREATE and tid < _NULL_ID:
                    while len(entries) < tid:
                        entries.append(_Entry())
                    entries.insert(tid, _Entry())
                elif t3 == _TYPE_DELETE and tid < len(entries):
                    removed.append(entries.pop(tid))
                continue
            if tid == _NULL_ID:
                if group == 0x600 and len(data) >= 8:
                    pair = tuple(sorted(struct.unpack_from("<II", data, 0)))
                    (hard if t3 & 1 else soft).append(pair)
                continue
            while len(entries) <= tid:
                entries.append(_Entry())
            ent = entries[tid]
            if group == 0x000:
                ent.name = data.decode("utf-8", "replace")
                ent.ftype = t3 & 0xFF
            elif group == 0x200:
                if t3 == _TYPE_DIRSTRUCT and len(data) >= 8:
                    ent.dirpair = tuple(sorted(struct.unpack_from("<II", data, 0)))
                    continue
                new = None
                if t3 == _TYPE_INLINESTRUCT:
                    new = _Version("inline", data=data, offset=doff)
                elif t3 == _TYPE_CTZSTRUCT and len(data) >= 8:
                    head, size = struct.unpack_from("<II", data, 0)
                    new = _Version("ctz", head=head, size=size, offset=doff)
                if new is not None:
                    old = ent.version
                    if old is not None and old.key() != new.key() and (old.kind == "ctz" or old.data):
                        ent.history.append(old)
                        del ent.history[:-Limits.MAX_VERSIONS_PER_FILE]
                    ent.version = new
        return _Meta(index, int.from_bytes(block[0:4], "little"), entries, removed, soft, hard)

    def _read_ctz(self, reader: BoundedReader, head: int, size: int, bs: int, bc: int):
        """Follow a CTZ skip list backwards from its head and rebuild the file.

        Returns the bytes, the chain of blocks, whether the walk completed, and
        whether every skip pointer still agrees with the chain. A block reused
        by something else breaks that agreement, which is the clearest sign the
        recovered bytes are no longer the original ones.
        """
        size = min(size, Limits.MAX_ARTIFACT_BYTES)
        if size == 0:
            return b"", [], True, True
        last, last_off = _ctz_index(size - 1, bs)
        if last >= bc:
            return b"", [], False, False
        chain = [0] * (last + 1)
        cur, seen = head, set()
        for i in range(last, -1, -1):
            if cur >= bc or cur in seen:
                return b"", [], False, False
            seen.add(cur)
            chain[i] = cur
            if i:
                cur = int.from_bytes(reader.read_at(cur * bs, 4), "little")
        out = bytearray()
        for i, blk in enumerate(chain):
            start = 0 if i == 0 else 4 * (_ctz(i) + 1)
            end = bs if i < last else last_off + 1
            out += reader.read_at(blk * bs + start, end - start)
        return bytes(out[:size]), chain, len(out) >= size, _skips_agree(reader, chain, bs)

    def _classify(self, reader: BoundedReader, metas: dict, bs: int, bc: int) -> Iterator[Artifact]:
        root = (0, 1)
        pairs = {root}
        for m in metas.values():
            for ent in m.entries + m.removed:
                if ent.dirpair:
                    pairs.add(ent.dirpair)
            pairs.update(m.softtails)
            pairs.update(m.hardtails)
        pair_of: dict[int, tuple] = {}
        for p in sorted(pairs):
            for b in p:
                if b < bc:
                    pair_of.setdefault(b, p)

        def current(pair):
            best = None
            for b in pair:
                m = metas.get(b)
                if m is not None and (best is None or _newer(m.rev, best.rev)):
                    best = m
            return best

        # Walk the live tree from the root pair, following directories and hard tails.
        live_meta, live_pairs, live_files = set(), set(), {}
        dir_path = {root: ""}
        queue, visited = deque([(root, "", 0)]), set()
        while queue:
            pair, path, depth = queue.popleft()
            if pair in visited or depth > Limits.MAX_PARSE_DEPTH:
                continue
            visited.add(pair)
            meta = current(pair)
            if meta is None:
                continue
            live_meta.add(meta.index)
            live_pairs.add(pair)
            dir_path.setdefault(pair, path)
            for ent in meta.entries:
                if not ent.name or ent.ftype == _TYPE_SUPERBLOCK:
                    continue
                full = f"{path}/{ent.name}"
                if ent.ftype == _TYPE_DIR and ent.dirpair:
                    queue.append((ent.dirpair, full, depth + 1))
                elif ent.ftype == _TYPE_REG and ent.version is not None:
                    live_files[full] = ent.version
            for tail in meta.hardtails:
                queue.append((tail, path, depth + 1))

        # Give paths to pairs outside the live tree, such as deleted directories.
        for _ in range(Limits.MAX_PARSE_DEPTH):
            changed = False
            for m in metas.values():
                base = dir_path.get(pair_of.get(m.index))
                if base is None:
                    continue
                for ent in m.entries + m.removed:
                    if ent.ftype == _TYPE_DIR and ent.dirpair and ent.name and ent.dirpair not in dir_path:
                        dir_path[ent.dirpair] = f"{base}/{ent.name}"
                        changed = True
                for tail in m.hardtails:
                    if tail not in dir_path:
                        dir_path[tail] = base
                        changed = True
            if not changed:
                break

        # Blocks the live filesystem still uses, for spotting reused remnants.
        in_use: set[int] = set(metas)
        for p in live_pairs:
            in_use.update(p)
        live_chains = {}
        for path, ver in live_files.items():
            if ver.kind == "ctz":
                live_chains[path] = self._read_ctz(reader, ver.head, ver.size, bs, bc)
                in_use.update(live_chains[path][1])
        claimed: set[int] = set(in_use)
        live_by_key = {ver.key(): path for path, ver in live_files.items()}

        emitted: set = set()
        count = 0

        def build(path, ver, state, note, meta) -> Optional[Artifact]:
            key = (path, ver.key())
            if key in emitted:
                return None
            emitted.add(key)
            conf = Confidence.HIGH
            if ver.kind == "inline":
                data, offset = ver.data[:Limits.MAX_ARTIFACT_BYTES], ver.offset
            else:
                data, chain, ok, agree = (live_chains[path] if state == ArtifactState.LIVE and path in live_chains
                                          else self._read_ctz(reader, ver.head, ver.size, bs, bc))
                offset = chain[0] * bs if chain else ver.offset
                if not ok:
                    conf = Confidence.LOW
                    note += ", the skip list is damaged so content is partial"
                elif not agree:
                    conf = Confidence.LOW
                    note += ", its skip pointers no longer agree so blocks were reused"
                elif state != ArtifactState.LIVE:
                    reused = [b for b in chain if b in in_use]
                    hijacked = _opens_with_pointer(reader, chain[0], bs, bc)
                    overrun = data.endswith(_ERASED_TAIL)
                    conf = Confidence.LOW if (reused or hijacked or overrun) else Confidence.MEDIUM
                    if reused:
                        note += f", {len(reused)} of its blocks are in use again so content may be overwritten"
                    elif hijacked:
                        note += ", its first block opens with a pointer, so the walk ran into another file's blocks"
                    elif overrun:
                        note += ", erased space sits inside its recorded length, so a shorter later file reused its blocks"
                    else:
                        claimed.update(chain)
                note += f", ctz head block {ver.head}"
            if not data and state != ArtifactState.LIVE:
                return None  # an empty stub from a create commit carries nothing to recover
            name = path.rsplit("/", 1)[-1] or "unnamed"
            return Artifact(name=name, filesystem="littlefs", state=state, confidence=conf,
                            offset=offset, size=len(data), data=data, path=path,
                            note=f"{note}, metadata block {meta.index} revision {meta.rev}")

        # Live files first, so the remnant pass can skip exact duplicates.
        for index in sorted(live_meta):
            meta = metas[index]
            base = dir_path.get(pair_of.get(index), "")
            for ent in meta.entries:
                if ent.ftype == _TYPE_REG and ent.name and ent.version is not None:
                    art = build(f"{base}/{ent.name}", ent.version, ArtifactState.LIVE, "live file", meta)
                    if art:
                        count += 1
                        yield art

        for index in sorted(metas):
            meta = metas[index]
            base = dir_path.get(pair_of.get(index))
            live_block = index in live_meta
            candidates = [(e, False) for e in meta.entries] + [(e, True) for e in meta.removed]
            for ent, was_removed in candidates:
                if ent.ftype != _TYPE_REG or not ent.name:
                    continue
                path = f"{base}/{ent.name}" if base is not None else ent.name
                live_ver = live_files.get(path) if base is not None else None
                if ent.version is not None and (was_removed or not live_block):
                    same = live_ver is not None and live_ver.key() == ent.version.key()
                    if not same:
                        if was_removed:
                            state, note = ArtifactState.DELETED, "removed by a delete tag"
                            moved = live_by_key.get(ent.version.key())
                            if moved:
                                note += f", identical content is live as {moved} so this may be a rename"
                        elif live_ver is not None:
                            state, note = ArtifactState.OBSOLETE, "older revision of a live file"
                        elif base is None:
                            state, note = ArtifactState.ORPHANED, "in a metadata block no directory points to"
                        else:
                            state, note = ArtifactState.DELETED, "present in an older revision, gone from the live tree"
                        art = build(path, ent.version, state, note, meta)
                        if art:
                            count += 1
                            yield art
                for old in ent.history:
                    if live_ver is not None and live_ver.key() == old.key():
                        continue
                    state = ArtifactState.OBSOLETE if base is not None else ArtifactState.ORPHANED
                    art = build(path, old, state, "superseded by a later commit", meta)
                    if art:
                        count += 1
                        yield art
                if not self._guard_count(count):
                    return

        for art in self._orphans(reader, bs, bc, claimed):
            count += 1
            yield art
            if not self._guard_count(count):
                return

    def _orphans(self, reader: BoundedReader, bs: int, bc: int, claimed: set) -> Iterator[Artifact]:
        """Recover CTZ data that no surviving commit references any more.

        Compaction erases the commits that pointed at a deleted or superseded
        file, yet its data blocks stay on flash until they are allocated again.
        Every block after the first opens with a back pointer, so chains can be
        rebuilt from the blocks themselves, and the extra skip pointers then
        confirm or reject each rebuilt chain. The file length is not recorded
        anywhere once the metadata is gone, so the last block is cut where its
        erased space begins.
        """
        cand: dict[int, int] = {}
        for b in range(bc):
            if b in claimed:
                continue
            block = reader.read_at(b * bs, bs)
            if not block.strip(b"\xff"):
                continue
            cand[b] = int.from_bytes(block[:4], "little")
        back = {b: p for b, p in cand.items() if p in cand and p != b}
        has_next = set(back.values())
        for head in sorted(b for b in cand if b not in has_next):
            chain, seen, cur = [head], {head}, head
            while cur in back and back[cur] not in seen and len(chain) < bc:
                cur = back[cur]
                chain.append(cur)
                seen.add(cur)
            chain.reverse()
            out = bytearray()
            for i, blk in enumerate(chain):
                start = 0 if i == 0 else 4 * (_ctz(i) + 1)
                out += reader.read_at(blk * bs + start, bs - start)
            data = bytes(out).rstrip(b"\xff")[:Limits.MAX_ARTIFACT_BYTES]
            if len(data) < 16:
                continue
            starts_clean = not _opens_with_pointer(reader, chain[0], bs, bc)
            agree = len(chain) < 3 or _skips_agree(reader, chain, bs)
            if not starts_clean:
                conf, how = Confidence.LOW, "the tail of a file whose earlier blocks were reused"
            elif not agree:
                conf, how = Confidence.LOW, f"{len(chain)} blocks whose skip pointers disagree"
            elif len(chain) == 1:
                conf, how = Confidence.MEDIUM, "a lone first block, later blocks may be missing"
            else:
                conf, how = Confidence.MEDIUM, f"a {len(chain)} block chain whose pointers check out"
            yield Artifact(name=f"orphan_block_{chain[0]}.bin", filesystem="littlefs",
                           state=ArtifactState.ORPHANED, confidence=conf, offset=chain[0] * bs,
                           size=len(data), data=data, path=None,
                           note=f"data no surviving commit references, {how}, length taken from where erased space begins")
