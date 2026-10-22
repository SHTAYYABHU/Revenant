"""Qt table model and filter for recovered artifacts."""

from __future__ import annotations

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QSortFilterProxyModel, Qt
from PySide6.QtGui import QColor

from ..core.models import Artifact
from .theme import STATE_COLOURS

COLUMNS = ["Path Or Name", "Filesystem", "State", "Confidence", "Offset", "Size", "SHA-256"]
_STATE_ORDER = {"deleted": 0, "obsolete": 1, "orphaned": 2, "carved": 3, "live": 4}
_CONF_ORDER = {"high": 0, "medium": 1, "low": 2}


class ArtifactTableModel(QAbstractTableModel):
    def __init__(self, artifacts: list[Artifact] | None = None):
        super().__init__()
        self._items: list[Artifact] = artifacts or []

    def set_items(self, artifacts: list[Artifact]) -> None:
        self.beginResetModel()
        self._items = list(artifacts)
        self.endResetModel()

    def artifact_at(self, row: int) -> Artifact | None:
        return self._items[row] if 0 <= row < len(self._items) else None

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._items)

    def columnCount(self, parent=QModelIndex()) -> int:
        return len(COLUMNS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return COLUMNS[section]
        return None

    def data(self, index: QModelIndex, role=Qt.DisplayRole):
        a = self.artifact_at(index.row())
        if a is None:
            return None
        col = index.column()
        if role == Qt.DisplayRole:
            return [a.path or a.name, a.filesystem, a.state.value, a.confidence.value,
                    f"0x{a.offset:x}", f"{a.size:,}", (a.sha256 or "")[:16]][col]
        if role == Qt.ToolTipRole:
            return a.note or None
        if role == Qt.ForegroundRole and col == 2:
            return QColor(STATE_COLOURS.get(a.state.value, "#1D2A36"))
        if role == Qt.TextAlignmentRole and col in (4, 5):
            return int(Qt.AlignRight | Qt.AlignVCenter)
        if role == Qt.UserRole:
            return [(a.path or a.name).lower(), a.filesystem, _STATE_ORDER.get(a.state.value, 9),
                    _CONF_ORDER.get(a.confidence.value, 9), a.offset, a.size, a.sha256 or ""][col]
        return None


class ArtifactFilterProxy(QSortFilterProxyModel):
    """Filters by free text and by state, and sorts on raw values."""

    def __init__(self):
        super().__init__()
        self._text = ""
        self._state = "all"
        self.setSortRole(Qt.UserRole)

    def _change(self, apply) -> None:
        # Qt 6.10 replaced invalidateFilter with a begin and end pair. Older
        # releases, which the requirements still allow, only have the old call.
        begin = getattr(self, "beginFilterChange", None)
        if begin is None:
            apply()
            self.invalidateFilter()
            return
        begin()
        apply()
        self.endFilterChange()

    def set_text(self, text: str) -> None:
        self._change(lambda: setattr(self, "_text", text.strip().lower()))

    def set_state(self, state: str) -> None:
        self._change(lambda: setattr(self, "_state", state))

    def filterAcceptsRow(self, row, parent) -> bool:
        a = self.sourceModel().artifact_at(row)
        if a is None:
            return False
        if self._state == "recovered" and a.state.value == "live":
            return False
        if self._state not in ("all", "recovered") and a.state.value != self._state:
            return False
        if self._text:
            hay = " ".join([a.name, a.path or "", a.filesystem, a.sha256 or "", a.note or ""]).lower()
            return self._text in hay
        return True
