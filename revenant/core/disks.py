"""List the physical disks attached to this machine.

This only enumerates devices, it does not read them. Reading happens later
through the evidence layer and needs elevation. Enumeration is best effort
per platform and returns a plain list the interface can show.

A note worth keeping in mind. On a normal laptop the internal drive is
managed flash behind a controller, so its wear leveling remnants are not
reachable without chip off. This list is most useful for attached raw
flash devices and for confirming what the machine can see, which matches
the scope set out in the project proposal.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

log = logging.getLogger("revenant.disks")


@dataclass
class DiskInfo:
    """One device the operating system reports."""

    path: str                    # the path the evidence layer would open
    model: str = ""
    size_bytes: Optional[int] = None
    removable: bool = False
    note: str = ""

    def human_size(self) -> str:
        if not self.size_bytes:
            return "unknown"
        units = ["B", "KB", "MB", "GB", "TB"]
        value = float(self.size_bytes)
        for u in units:
            if value < 1024 or u == units[-1]:
                return f"{value:.1f} {u}"
            value /= 1024
        return f"{self.size_bytes} B"


def list_disks() -> list[DiskInfo]:
    """Return the attached disks, dispatching on the platform."""
    try:
        if os.name == "nt":
            return _list_windows()
        if os.uname().sysname == "Darwin":
            return _list_macos()
        return _list_linux()
    except Exception as exc:
        log.warning("disk enumeration failed: %s", exc)
        return []


def _list_linux() -> list[DiskInfo]:
    """Read block devices from sysfs, which needs no elevation to enumerate."""
    disks: list[DiskInfo] = []
    block = Path("/sys/block")
    if not block.exists():
        return disks
    for dev in sorted(block.iterdir()):
        name = dev.name
        # Skip nodes that are not physical media. MTD block nodes are skipped too,
        # since the MTD character devices below expose the same flash more directly.
        if name.startswith(("loop", "ram", "dm-", "sr", "zram", "mtdblock")):
            continue
        size_sectors = _read_int(dev / "size")
        removable = _read_int(dev / "removable") == 1
        model = _read_text(dev / "device" / "model")
        info = DiskInfo(
            path=f"/dev/{name}",
            model=model or name,
            size_bytes=(size_sectors * 512) if size_sectors else None,
            removable=removable,
        )
        if name.startswith("mmcblk"):
            info.note = "managed flash, its controller hides the raw remnants this tool looks for"
        disks.append(info)
    # MTD character devices expose raw NAND and NOR, the main target of this tool.
    mtd_class = Path("/sys/class/mtd")
    if mtd_class.exists():
        for node in sorted(mtd_class.iterdir(), key=lambda n: int(n.name[3:]) if n.name[3:].isdigit() else 0):
            if not re.fullmatch(r"mtd\d+", node.name):
                continue  # mtdNro nodes duplicate the same flash read only
            kind = _read_text(node / "type") or "flash"
            label = _read_text(node / "name")
            disks.append(DiskInfo(path=f"/dev/{node.name}", model=f"MTD {kind} {label}".strip(),
                                  size_bytes=_read_int(node / "size"),
                                  note="raw flash, the main target for this tool"))
    return disks


def _list_macos() -> list[DiskInfo]:
    """Use diskutil to list devices on macOS."""
    disks: list[DiskInfo] = []
    try:
        out = subprocess.run(
            ["diskutil", "list"], capture_output=True, text=True, timeout=10
        ).stdout
    except Exception as exc:
        log.warning("diskutil failed: %s", exc)
        return disks
    for line in out.splitlines():
        m = re.match(r"^(/dev/disk\d+)", line.strip())
        if m:
            disks.append(DiskInfo(path=m.group(1), model="disk"))
    # De-duplicate while keeping order.
    seen = set()
    unique = []
    for d in disks:
        if d.path not in seen:
            seen.add(d.path)
            unique.append(d)
    return unique


def _list_windows() -> list[DiskInfo]:
    """Enumerate physical drives on Windows through WMI over ctypes free calls.

    We shell out to a small PowerShell query rather than pull in a WMI
    dependency, which keeps the install light. Reading a drive still needs
    an elevated process, this only lists them.
    """
    disks: list[DiskInfo] = []
    query = (
        "Get-CimInstance Win32_DiskDrive | "
        "Select-Object DeviceID,Model,Size,MediaType | ConvertTo-Csv -NoTypeInformation"
    )
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command", query],
            capture_output=True, text=True, timeout=15,
        ).stdout
    except Exception as exc:
        log.warning("powershell disk query failed: %s", exc)
        return disks
    lines = [ln for ln in out.splitlines() if ln.strip()]
    for ln in lines[1:]:  # skip the header row
        parts = _split_csv(ln)
        if len(parts) < 3:
            continue
        device_id, model, size = parts[0], parts[1], parts[2]
        media = parts[3] if len(parts) > 3 else ""
        try:
            size_bytes = int(size) if size else None
        except ValueError:
            size_bytes = None
        disks.append(
            DiskInfo(
                path=device_id,
                model=model or "disk",
                size_bytes=size_bytes,
                removable="Removable" in media,
                note=media,
            )
        )
    return disks


def _split_csv(line: str) -> list[str]:
    """Tiny CSV splitter for the quoted PowerShell output."""
    out, cur, inq = [], [], False
    for ch in line:
        if ch == '"':
            inq = not inq
        elif ch == "," and not inq:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    out.append("".join(cur))
    return out


def _read_int(path: Path) -> Optional[int]:
    try:
        return int(path.read_text().strip())
    except Exception:
        return None


def _read_text(path: Path) -> str:
    try:
        return path.read_text().strip()
    except Exception:
        return ""
