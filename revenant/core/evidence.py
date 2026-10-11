"""Evidence sources, meaning image files and devices acquired into image files.

Whatever the source, the rest of the tool sees the same read only window of
bytes plus an integrity record. Images are memory mapped for reading only, so a
large image never has to sit in memory whole. Attached devices are never
parsed in place. They are first copied into an image file with hashes computed
during the copy, the copy is hashed again from disk, and only then does the
analysis begin. Nothing in this module writes to a source.
"""

from __future__ import annotations

import hashlib
import logging
import mmap
import os
from pathlib import Path
from typing import Callable, Optional

from .models import EvidenceInfo
from .security import (
    BoundedReader,
    Limits,
    OperationCancelled,
    SecurityError,
    hash_bytes,
    hash_stream,
    validate_source_path,
)

log = logging.getLogger("revenant.evidence")


class Evidence:
    """A read only handle over a source, with a bounded reader for parsers."""

    def __init__(self, info: EvidenceInfo, mv: memoryview, closer=None):
        self.info = info
        self._mv = mv
        self._closer = closer
        self.reader = BoundedReader(mv, source_hint=info.source_path)

    def __enter__(self) -> "Evidence":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        try:
            if self._closer:
                self._closer()
                self._closer = None
        except Exception as exc:  # closing must never raise into the caller
            log.debug("evidence close raised: %s", exc)

    @classmethod
    def from_image(cls, path: str, compute_hash: bool = True) -> "Evidence":
        """Open an image file through a read only memory map."""
        p = validate_source_path(path)
        if not p.is_file():
            raise SecurityError("Evidence must be an image file, acquire devices first")
        size = p.stat().st_size
        digests = hash_stream(p) if compute_hash else {}

        fh = open(p, "rb")
        try:
            mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        except (ValueError, OSError) as exc:
            fh.close()
            raise SecurityError(f"Could not map the source image: {exc}")
        mv = memoryview(mm)

        def _close():
            mv.release()
            mm.close()
            fh.close()

        info = EvidenceInfo(
            source_kind="image",
            source_path=str(p),
            size_bytes=size,
            sha256=digests.get("sha256"),
            md5=digests.get("md5"),
        )
        log.info("opened image %s size=%d", p, size)
        return cls(info, mv, closer=_close)

    @classmethod
    def from_bytes(cls, data: bytes, label: str = "in-memory") -> "Evidence":
        """Wrap bytes as evidence, mainly for tests and the sample tools."""
        if len(data) > Limits.MAX_IMAGE_BYTES:
            raise SecurityError("In memory evidence exceeds the maximum supported size")
        blob = bytes(data)  # an immutable copy keeps this evidence read only too
        mv = memoryview(blob)
        info = EvidenceInfo(
            source_kind="image",
            source_path=label,
            size_bytes=len(blob),
            sha256=hash_bytes(blob),
            md5=hash_bytes(blob, "md5"),
        )
        return cls(info, mv, closer=mv.release)


def _open_device(device_path: str):
    """Open a raw device for reading only, on any of the supported platforms."""
    if os.name == "nt":
        return open(device_path, "rb", buffering=0)
    fd = os.open(device_path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    return os.fdopen(fd, "rb", buffering=0)


def acquire_device(
    device_path: str,
    image_path: str,
    length: Optional[int] = None,
    progress: Optional[Callable[[float], None]] = None,
    cancel=None,
) -> dict:
    """Copy a device into a new image file and hash it during the copy.

    The destination is created exclusively, so an existing file is never
    overwritten. Reads are sector aligned because Windows insists on that for
    raw drives. A partial image left by a failure or a cancel is removed, since
    an incomplete copy would be misleading evidence.
    """
    dest = Path(image_path)
    limit = min(length, Limits.MAX_IMAGE_BYTES) if length else Limits.MAX_IMAGE_BYTES
    sha, md5 = hashlib.sha256(), hashlib.md5()
    total = 0
    created = False  # only a file this call created may ever be removed
    src = _open_device(device_path)
    try:
        with open(dest, "xb") as out:
            created = True
            while total < limit:
                if cancel is not None and cancel.is_set():
                    raise OperationCancelled("Acquisition cancelled by the examiner")
                want = min(Limits.READ_CHUNK, limit - total)
                want = ((want + 4095) // 4096) * 4096
                try:
                    chunk = src.read(want)
                except OSError:
                    if total == 0:
                        raise
                    break  # several platforms report the end of a raw device this way
                if not chunk:
                    break
                chunk = chunk[: limit - total]
                out.write(chunk)
                sha.update(chunk)
                md5.update(chunk)
                total += len(chunk)
                if progress and length:
                    progress(min(1.0, total / length))
        if total == 0:
            raise SecurityError("The device returned no data")
    except BaseException:
        if created:
            try:
                dest.unlink()
            except OSError:
                pass
        raise
    finally:
        src.close()
    log.info("acquired %s bytes from %s into %s", total, device_path, dest)
    return {"bytes": total, "sha256": sha.hexdigest(), "md5": md5.hexdigest(), "image": str(dest)}
