"""Defense in depth helpers used across the whole tool.

Every layer here assumes the layer below it might be hostile. An evidence image
is untrusted input, a crafted image may try to make a parser loop or allocate
without end, and a recovered filename may try to climb out of the output
folder. The guardrails sit in one module so every part of the tool applies the
same checks in the same way.
"""

from __future__ import annotations

import hashlib
import logging
import mmap
import os
import re
import threading
import zlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

log = logging.getLogger("revenant.security")


class Limits:
    """Hard ceilings that keep a hostile or corrupt image from exhausting the host."""

    MAX_IMAGE_BYTES = 8 * 1024 * 1024 * 1024      # refuse anything larger than 8 GiB
    MAX_ARTIFACTS = 200_000                         # stop collecting past this point
    MAX_ARTIFACT_BYTES = 256 * 1024 * 1024          # cap for one recovered payload
    MAX_RECORDS = 5_000_000                         # cap on records walked per carver
    READ_CHUNK = 1024 * 1024                        # streaming read size
    MAX_NAME_LEN = 255                              # cap on recovered names
    MAX_PARSE_DEPTH = 64                            # guard for nested structures
    MAX_NODE_OUTPUT = 1024 * 1024                   # cap for one decompressed node
    MAX_VERSIONS_PER_FILE = 32                      # historic versions rebuilt per file


class SecurityError(Exception):
    """Raised when a guardrail refuses to go on."""


class OperationCancelled(Exception):
    """Raised when the examiner cancels a scan or an acquisition."""


_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_RESERVED_WINDOWS = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


def sanitise_filename(name: str, fallback: str = "recovered.bin") -> str:
    """Turn an untrusted recovered name into something safe to write to disk.

    Readability matters, but the priority is a result with no separators, no
    traversal, and no reserved Windows device name.
    """
    if not name:
        return fallback
    base = str(name).replace("\\", "/").split("/")[-1]
    base = base[: Limits.MAX_NAME_LEN]
    cleaned = _SAFE_NAME.sub("_", base).strip("._")
    if not cleaned:
        return fallback
    if cleaned.split(".")[0].upper() in _RESERVED_WINDOWS:
        cleaned = "_" + cleaned
    return cleaned


def clean_display_name(name, limit: int = Limits.MAX_NAME_LEN) -> str:
    """Make an untrusted name safe to show in a table, a log, or a report.

    Control characters become question marks and the length is capped, so a
    crafted name cannot break a layout or push escape sequences into a terminal.
    """
    if name is None:
        return ""
    text = _CONTROL.sub("?", str(name))[:limit]
    return text or "unnamed"


def csv_safe(value) -> str:
    """Stop a recovered string from being read as a formula by a spreadsheet."""
    text = "" if value is None else str(value)
    if text[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + text
    return text


def safe_output_path(output_dir: Path, filename: str) -> Path:
    """Resolve a write target and prove it stays inside the output folder.

    This is the last line against a recovered path that tries to climb out
    with dot dot segments or an absolute path. It never clobbers an existing
    file, a numeric suffix is added instead.
    """
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    candidate = (output_dir / sanitise_filename(filename)).resolve()
    if candidate.parent != output_dir:
        raise SecurityError("Resolved output path escaped the output folder")
    final = candidate
    counter = 1
    while final.exists():
        final = output_dir / f"{candidate.stem}_{counter}{candidate.suffix}"
        counter += 1
    return final


def validate_source_path(path: str) -> Path:
    """Check a source file before it is opened as evidence."""
    p = Path(path)
    if not p.exists():
        raise SecurityError(f"Source does not exist: {path}")
    if p.is_symlink():
        real = p.resolve()
        log.warning("Source is a symlink, following it to %s", real)
        p = real
    if p.is_file():
        size = p.stat().st_size
        if size > Limits.MAX_IMAGE_BYTES:
            raise SecurityError("Source image exceeds the maximum supported size")
        if size == 0:
            raise SecurityError("Source image is empty")
    return p


class BoundedReader:
    """A read only window over evidence bytes with bounds checking.

    Parsers reach evidence only through this object. It refuses reads outside
    the image and it never hands out anything writable, which is how the
    source stays strictly read only from the parsers' point of view.
    """

    def __init__(self, data: memoryview, source_hint: str = ""):
        self._data = data
        self._len = len(data)
        self.source_hint = source_hint

    def __len__(self) -> int:
        return self._len

    def read_at(self, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0:
            raise SecurityError("Negative read requested")
        if offset > self._len:
            raise SecurityError("Read offset past the end of the evidence")
        end = min(offset + length, self._len)
        return bytes(self._data[offset:end])

    def slice(self, offset: int, length: int) -> memoryview:
        if offset < 0 or offset > self._len:
            raise SecurityError("Slice offset out of range")
        return self._data[offset:min(offset + length, self._len)]

    def haystack(self):
        """The read only backing object, for fast searching without a full copy.

        It is either a memory map opened for reading or an immutable bytes
        object, so a parser cannot write through it even by accident.
        """
        obj = self._data.obj
        if isinstance(obj, (bytes, mmap.mmap)):
            return obj
        return bytes(self._data)

    def iter_blocks(self, block_size: int) -> Iterator[tuple[int, memoryview]]:
        if block_size <= 0:
            raise SecurityError("Block size must be positive")
        pos = 0
        while pos < self._len:
            yield pos, self._data[pos: pos + block_size]
            pos += block_size


def inflate_bounded(data: bytes, wbits: int, max_out: int) -> Optional[bytes]:
    """Inflate a zlib or raw deflate stream without letting it grow past a cap.

    A crafted node can claim a tiny size and expand enormously, so the output
    limit is enforced inside the decompressor rather than checked afterwards.
    """
    try:
        return zlib.decompressobj(wbits).decompress(data, max(1, max_out))
    except zlib.error:
        return None


def hash_stream(path: Path, algorithms: tuple[str, ...] = ("sha256", "md5")) -> dict[str, str]:
    """Hash a file in bounded chunks so a large image never sits in memory whole."""
    digests = {name: hashlib.new(name) for name in algorithms}
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(Limits.READ_CHUNK)
            if not chunk:
                break
            for d in digests.values():
                d.update(chunk)
    return {name: d.hexdigest() for name, d in digests.items()}


def hash_bytes(data: bytes, algorithm: str = "sha256") -> str:
    return hashlib.new(algorithm, data).hexdigest()


@dataclass
class _AuditEntry:
    when_utc: str
    action: str
    detail: str


class AuditLog:
    """An append only trail of what the tool did during a session.

    It feeds the chain of custody in the report. It stores sizes and hashes,
    never recovered content, so the trail can be shared without leaking data.
    """

    def __init__(self) -> None:
        self._entries: list[_AuditEntry] = []
        self._lock = threading.Lock()

    def record(self, action: str, detail: str = "") -> None:
        entry = _AuditEntry(datetime.now(timezone.utc).isoformat(), action, clean_display_name(detail, 2048))
        with self._lock:
            self._entries.append(entry)
        log.info("audit %s %s", action, entry.detail)

    def entries(self) -> list[dict]:
        with self._lock:
            return [vars(e).copy() for e in self._entries]


def have_admin_rights() -> bool:
    """Report whether this session can likely read a raw device.

    Reading a physical drive needs elevation on every platform. Checking up
    front lets the interface warn plainly instead of failing deep inside a read.
    """
    if os.name == "nt":
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False
