"""Work out which filesystems are present before carving.

Detection reads only a bounded opening region, so every carver can be asked
cheaply whether it recognises the layout. The signature carver always runs,
since raw content can sit in any image whatever filesystem surrounds it.

LittleFS, JFFS2, and UBIFS are recognised from checksummed structures, so a
match is dependable. YAFFS and SPIFFS are recognised from softer layout hints
and are more prone to a false match, which is why they only engage when none
of the strong carvers claimed the image.
"""

from __future__ import annotations

import logging

from ..security import BoundedReader
from .base import FilesystemCarver
from .jffs2 import JFFS2Carver
from .littlefs import LittleFSCarver
from .signature_carver import SignatureCarver
from .spiffs import SPIFFSCarver
from .ubifs import UBIFSCarver
from .yaffs import YAFFSCarver

log = logging.getLogger("revenant.detect")

STRONG_CARVERS: list[type[FilesystemCarver]] = [JFFS2Carver, UBIFSCarver, LittleFSCarver]
HEURISTIC_CARVERS: list[type[FilesystemCarver]] = [YAFFSCarver, SPIFFSCarver]
ALL_CARVERS: list[type[FilesystemCarver]] = STRONG_CARVERS + HEURISTIC_CARVERS


def _detect(reader: BoundedReader, group) -> list[type[FilesystemCarver]]:
    hits = []
    for cls in group:
        try:
            if cls().detect(reader):
                hits.append(cls)
        except Exception as exc:
            log.warning("detection error in %s: %s", cls.__name__, exc)
    return hits


def _detect_all(reader: BoundedReader) -> list[type[FilesystemCarver]]:
    return _detect(reader, STRONG_CARVERS) or _detect(reader, HEURISTIC_CARVERS)


def select_carvers(reader: BoundedReader) -> tuple[list[FilesystemCarver], list[str]]:
    """Return the carvers to run and the names of the detected filesystems."""
    carvers = [cls() for cls in _detect_all(reader)]
    names = [c.name for c in carvers]
    carvers.append(SignatureCarver())
    return carvers, names


def detected_names(reader: BoundedReader) -> list[str]:
    return [cls.name for cls in _detect_all(reader)]
