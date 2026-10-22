"""The contract every filesystem carver follows.

A carver receives a read only reader over the evidence and yields
artifacts. It must treat the bytes as hostile, bound every read, and
never trust a length field without checking it against the image. The
engine handles the orchestration, so a carver only has to know its own
on disk format.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Iterator

from ..models import Artifact, ScanStats
from ..security import BoundedReader, Limits

log = logging.getLogger("revenant.fs")


class FilesystemCarver(ABC):
    """Subclass this for each supported filesystem."""

    name: str = "base"
    # A short label describing how complete this parser is, shown in the report.
    maturity: str = "experimental"

    @abstractmethod
    def detect(self, reader: BoundedReader) -> bool:
        """Return True when this filesystem is present in the image."""

    @abstractmethod
    def carve(self, reader: BoundedReader, stats: ScanStats) -> Iterator[Artifact]:
        """Yield artifacts, both live and recovered, from the image."""

    # Shared helper so no carver forgets the artifact ceiling.
    @staticmethod
    def _guard_count(count: int) -> bool:
        """Return True while it is still safe to keep collecting artifacts."""
        return count < Limits.MAX_ARTIFACTS

    @staticmethod
    def _clamp_size(size: int) -> int:
        """Never honour a length that would blow past the per artifact cap."""
        if size < 0:
            return 0
        return min(size, Limits.MAX_ARTIFACT_BYTES)
