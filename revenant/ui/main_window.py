"""The main window of the desktop interface.

The layout follows the examiner's path through a case. The sidebar holds the
evidence source and the case details, the centre shows what was recovered, and
the lower pane shows one item in depth. Scans and acquisitions run on a worker
thread so the window stays responsive, and every run can be cancelled.
Attached devices are never parsed in place. They are copied into an image the
examiner names, the copy is verified by hash, and only the verified image is
analysed.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional

from PySide6.QtCore import QObject, QThread, Qt, QUrl, Signal
from PySide6.QtGui import QDesktopServices, QFontDatabase, QKeySequence, QPixmap, QShortcut
from PySide6.QtWidgets import (
    QAbstractItemView, QComboBox, QDialog, QDialogButtonBox, QFileDialog, QFormLayout, QFrame,
    QGridLayout, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QListWidget, QListWidgetItem,
    QMainWindow, QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QSplitter,
    QStackedWidget, QTableView, QTabWidget, QVBoxLayout, QWidget,
)

from ..core.disks import DiskInfo, list_disks
from ..core.engine import ScanEngine
from ..core.export import export_artifacts
from ..core.models import Artifact, CaseInfo, ScanResult
from ..core.report import build_report
from ..core.security import AuditLog, OperationCancelled, SecurityError, have_admin_rights
from ..version import APP_NAME, APP_TAGLINE, __version__
from .models import ArtifactFilterProxy, ArtifactTableModel
from .theme import STATE_COLOURS, stylesheet

log = logging.getLogger("revenant.ui")
ASSETS = Path(__file__).resolve().parent.parent / "assets"


class ScanWorker(QObject):
    """Runs one scan or acquisition off the interface thread."""

    progress = Signal(str, float)
    finished = Signal(object)
    failed = Signal(str)

    def __init__(self, engine: ScanEngine, mode: str, source: str, case: CaseInfo,
                 image_path: Optional[str] = None, length: Optional[int] = None):
        super().__init__()
        self.engine, self.mode, self.source, self.case = engine, mode, source, case
        self.image_path, self.length = image_path, length
        self.cancel = threading.Event()

    def run(self) -> None:
        try:
            if self.mode == "disk":
                result = self.engine.scan_disk(self.source, self.image_path, length=self.length,
                                               case=self.case, progress=self.progress.emit, cancel=self.cancel)
            else:
                result = self.engine.scan_image(self.source, case=self.case, progress=self.progress.emit,
                                                cancel=self.cancel)
            self.finished.emit(result)
        except OperationCancelled:
            self.failed.emit("Cancelled. The partial acquisition image was removed.")
        except PermissionError:
            self.failed.emit("Permission denied. Reading a raw device needs administrator or root rights. "
                             "On Linux and macOS you can acquire with sudo revenant-cli acquire, then open "
                             "the image here.")
        except (SecurityError, OSError) as exc:
            self.failed.emit(str(exc))
        except Exception as exc:  # the window must survive anything a worker throws
            log.exception("worker failed")
            self.failed.emit(f"Unexpected error: {exc}")


class CaseDialog(QDialog):
    """Collects the case details that head the report."""

    def __init__(self, case: CaseInfo, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Case Details")
        self.setMinimumWidth(460)
        self._created = case.created_utc
        self.name = QLineEdit(case.case_name)
        self.examiner = QLineEdit(case.examiner)
        self.reference = QLineEdit(case.reference)
        self.notes = QPlainTextEdit(case.notes)
        self.notes.setFixedHeight(90)
        form = QFormLayout()
        form.addRow("Case name", self.name)
        form.addRow("Examiner", self.examiner)
        form.addRow("Reference", self.reference)
        form.addRow("Notes", self.notes)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        lay = QVBoxLayout(self)
        lay.addLayout(form)
        lay.addWidget(buttons)

    def case(self) -> CaseInfo:
        return CaseInfo(case_name=self.name.text().strip() or "Untitled Case",
                        examiner=self.examiner.text().strip(), reference=self.reference.text().strip(),
                        notes=self.notes.toPlainText().strip(), created_utc=self._created)


def _card(title: str) -> tuple[QFrame, QLabel]:
    frame = QFrame()
    frame.setObjectName("Card")
    lay = QVBoxLayout(frame)
    lay.setContentsMargins(14, 10, 14, 12)
    lay.setSpacing(2)
    head = QLabel(title.upper())
    head.setObjectName("CardTitle")
    value = QLabel("-")
    value.setObjectName("CardValue")
    lay.addWidget(head)
    lay.addWidget(value)
    return frame, value


def _section(text: str) -> QLabel:
    label = QLabel(text.upper())
    label.setObjectName("SectionLabel")
    return label


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} {__version__}")
        self.resize(1320, 840)
        self.setStyleSheet(stylesheet())
        self.audit = AuditLog()
        self.case = CaseInfo()
        self.result: Optional[ScanResult] = None
        self.image_path: Optional[str] = None
        self.disk: Optional[DiskInfo] = None
        self._thread: Optional[QThread] = None
        self._worker: Optional[ScanWorker] = None
        self._mono = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)

        root = QWidget()
        root.setObjectName("Root")
        outer = QVBoxLayout(root)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        outer.addWidget(self._build_header())
        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)
        body.addWidget(self._build_sidebar())
        body.addWidget(self._build_content(), 1)
        outer.addLayout(body, 1)
        self.setCentralWidget(root)
        self.statusBar().showMessage("Ready. Open an image or pick an attached disk.")
        self._shortcuts()
        self.refresh_disks()
        self._update_actions()

    # Layout
    def _build_header(self) -> QWidget:
        bar = QWidget()
        bar.setObjectName("HeaderBar")
        bar.setFixedHeight(68)
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(20, 10, 20, 10)
        logo = QLabel()
        pix = QPixmap(str(ASSETS / "revenant_logo_square.png"))
        if not pix.isNull():
            logo.setPixmap(pix.scaled(40, 40, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        lay.addWidget(logo)
        titles = QVBoxLayout()
        titles.setSpacing(0)
        title = QLabel(APP_NAME)
        title.setObjectName("HeaderTitle")
        tag = QLabel(APP_TAGLINE)
        tag.setObjectName("HeaderTagline")
        titles.addWidget(title)
        titles.addWidget(tag)
        lay.addLayout(titles)
        lay.addStretch(1)
        chip = QLabel("Administrator session" if have_admin_rights() else "Standard user session")
        chip.setObjectName("PrivChip")
        chip.setToolTip("Raw devices can only be read with administrator or root rights. "
                        "Image files work in any session.")
        lay.addWidget(chip)
        return bar

    def _build_sidebar(self) -> QWidget:
        side = QWidget()
        side.setObjectName("Sidebar")
        side.setFixedWidth(310)
        lay = QVBoxLayout(side)
        lay.setContentsMargins(16, 16, 16, 16)
        lay.setSpacing(8)

        lay.addWidget(_section("Evidence source"))
        self.open_btn = QPushButton("Open Image File")
        self.open_btn.setToolTip("Choose a raw flash dump, Ctrl+O")
        self.open_btn.clicked.connect(self.open_image)
        lay.addWidget(self.open_btn)
        self.source_label = QLabel("No source selected")
        self.source_label.setObjectName("Muted")
        self.source_label.setWordWrap(True)
        lay.addWidget(self.source_label)

        disks_row = QHBoxLayout()
        disks_row.addWidget(_section("Attached disks"))
        disks_row.addStretch(1)
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh_disks)
        disks_row.addWidget(self.refresh_btn)
        lay.addSpacing(6)
        lay.addLayout(disks_row)
        self.disk_list = QListWidget()
        self.disk_list.setMinimumHeight(120)
        self.disk_list.itemSelectionChanged.connect(self._disk_selected)
        lay.addWidget(self.disk_list, 1)
        hint = QLabel("A disk is copied into an image file you choose, the copy is verified by hash, "
                      "and only the copy is analysed.")
        hint.setObjectName("Muted")
        hint.setWordWrap(True)
        lay.addWidget(hint)

        lay.addSpacing(6)
        lay.addWidget(_section("Case"))
        self.case_label = QLabel(self.case.case_name)
        self.case_label.setWordWrap(True)
        lay.addWidget(self.case_label)
        case_btn = QPushButton("Edit Case Details")
        case_btn.clicked.connect(self.edit_case)
        lay.addWidget(case_btn)

        lay.addSpacing(10)
        self.scan_btn = QPushButton("Start Scan")
        self.scan_btn.setObjectName("Primary")
        self.scan_btn.setToolTip("Scan the selected source, Ctrl+Enter")
        self.scan_btn.clicked.connect(self.start_scan)
        lay.addWidget(self.scan_btn)
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setObjectName("Danger")
        self.cancel_btn.clicked.connect(self.cancel_scan)
        lay.addWidget(self.cancel_btn)
        self.progress = QProgressBar()
        self.progress.setRange(0, 1000)
        self.progress.setValue(0)
        lay.addWidget(self.progress)
        self.progress_label = QLabel("")
        self.progress_label.setObjectName("Muted")
        self.progress_label.setWordWrap(True)
        lay.addWidget(self.progress_label)
        return side

    def _build_content(self) -> QWidget:
        content = QWidget()
        content.setObjectName("Content")
        lay = QVBoxLayout(content)
        lay.setContentsMargins(18, 16, 18, 12)
        lay.setSpacing(12)

        cards = QHBoxLayout()
        cards.setSpacing(12)
        c1, self.card_fs = _card("Detected filesystems")
        c2, self.card_recovered = _card("Recovered items")
        c3, self.card_live = _card("Live files")
        c4, self.card_time = _card("Scan time")
        for c in (c1, c2, c3, c4):
            cards.addWidget(c, 1)
        lay.addLayout(cards)

        self.stack = QStackedWidget()
        empty = QFrame()
        empty.setObjectName("Card")
        el = QVBoxLayout(empty)
        el.addStretch(1)
        t = QLabel("Nothing scanned yet")
        t.setObjectName("EmptyTitle")
        t.setAlignment(Qt.AlignCenter)
        s = QLabel("Open a flash image or pick an attached disk, then start the scan. Deleted, superseded, "
                   "and orphaned data will be listed here next to the live files.")
        s.setObjectName("Muted")
        s.setAlignment(Qt.AlignCenter)
        s.setWordWrap(True)
        el.addWidget(t)
        el.addWidget(s)
        el.addStretch(1)
        self.stack.addWidget(empty)
        self.stack.addWidget(self._build_results())
        lay.addWidget(self.stack, 1)
        return content

    def _build_results(self) -> QWidget:
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(8)
        bar = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Filter by name, path, hash, or note")
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(lambda txt: self.proxy.set_text(txt))
        bar.addWidget(self.search, 1)
        self.state_box = QComboBox()
        for label, key in [("All items", "all"), ("Recovered only", "recovered"), ("Deleted", "deleted"),
                           ("Obsolete", "obsolete"), ("Orphaned", "orphaned"), ("Carved", "carved"),
                           ("Live", "live")]:
            self.state_box.addItem(label, key)
        self.state_box.currentIndexChanged.connect(lambda _: self.proxy.set_state(self.state_box.currentData()))
        bar.addWidget(self.state_box)
        self.export_btn = QPushButton("Export Selected")
        self.export_btn.setToolTip("Write the selected items with a hashed manifest, Ctrl+E")
        self.export_btn.clicked.connect(self.export_selected)
        bar.addWidget(self.export_btn)
        self.export_all_btn = QPushButton("Export Recovered")
        self.export_all_btn.clicked.connect(self.export_recovered)
        bar.addWidget(self.export_all_btn)
        self.report_btn = QPushButton("Generate Report")
        self.report_btn.setObjectName("Primary")
        self.report_btn.setToolTip("Write the PDF report, Ctrl+R")
        self.report_btn.clicked.connect(self.generate_report)
        bar.addWidget(self.report_btn)
        lay.addLayout(bar)

        self.model = ArtifactTableModel()
        self.proxy = ArtifactFilterProxy()
        self.proxy.setSourceModel(self.model)
        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setSortingEnabled(True)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for col in range(1, 7):
            header.setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)
        self.table.selectionModel().selectionChanged.connect(self._show_details)

        details = QFrame()
        details.setObjectName("Card")
        dl = QVBoxLayout(details)
        dl.setContentsMargins(14, 10, 14, 12)
        self.detail_title = QLabel("Select an item to inspect it")
        self.detail_title.setObjectName("DetailTitle")
        self.detail_title.setTextInteractionFlags(Qt.TextSelectableByMouse)
        dl.addWidget(self.detail_title)
        self.detail_grid = QGridLayout()
        self.detail_grid.setHorizontalSpacing(18)
        self.detail_grid.setVerticalSpacing(3)
        self._detail_values = {}
        fields = ["State", "Confidence", "Filesystem", "Offset", "Size", "Inode", "Modified", "SHA-256", "Note"]
        for i, key in enumerate(fields):
            k = QLabel(key)
            k.setObjectName("Muted")
            v = QLabel("-")
            v.setWordWrap(True)
            v.setTextInteractionFlags(Qt.TextSelectableByMouse)
            row, col = (i // 2, (i % 2) * 2) if key not in ("SHA-256", "Note") else (5 + fields.index(key) - 7, 0)
            self.detail_grid.addWidget(k, row, col)
            self.detail_grid.addWidget(v, row, col + 1, 1, 3 if key in ("SHA-256", "Note") else 1)
            self._detail_values[key] = v
        dl.addLayout(self.detail_grid)
        self.tabs = QTabWidget()
        self.text_view = QPlainTextEdit()
        self.hex_view = QPlainTextEdit()
        for view in (self.text_view, self.hex_view):
            view.setReadOnly(True)
            view.setFont(self._mono)
            view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.text_view.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        self.tabs.addTab(self.text_view, "Text")
        self.tabs.addTab(self.hex_view, "Hex")
        dl.addWidget(self.tabs, 1)

        split = QSplitter(Qt.Vertical)
        split.addWidget(self.table)
        split.addWidget(details)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)
        lay.addWidget(split, 1)
        return page

    def _shortcuts(self) -> None:
        for seq, fn in [(QKeySequence.StandardKey.Open, self.open_image), ("Ctrl+Return", self.start_scan),
                        ("Ctrl+E", self.export_selected), ("Ctrl+R", self.generate_report),
                        (QKeySequence.StandardKey.Find, lambda: self.search.setFocus())]:
            QShortcut(QKeySequence(seq), self, activated=fn)

    # Source selection
    def open_image(self) -> None:
        if self._busy():
            return
        path, _ = QFileDialog.getOpenFileName(self, "Open Flash Image", "",
                                              "Images (*.img *.bin *.dd *.raw *.dump *.nand);;All files (*)")
        if path:
            self.image_path, self.disk = path, None
            self.disk_list.clearSelection()
            self.source_label.setText(f"Image file\n{path}")
            self._update_actions()

    def refresh_disks(self) -> None:
        self.disk_list.clear()
        try:
            disks = list_disks()
        except Exception as exc:
            disks = []
            log.warning("disk listing failed: %s", exc)
        for d in disks:
            item = QListWidgetItem(f"{d.path}\n{d.human_size()}  {d.model}".rstrip())
            item.setData(Qt.UserRole, d)
            item.setToolTip(d.note or d.path)
            self.disk_list.addItem(item)
        if not disks:
            item = QListWidgetItem("No disks visible in this session")
            item.setFlags(Qt.NoItemFlags)
            self.disk_list.addItem(item)

    def _disk_selected(self) -> None:
        items = self.disk_list.selectedItems()
        disk = items[0].data(Qt.UserRole) if items else None
        if isinstance(disk, DiskInfo):
            self.disk, self.image_path = disk, None
            self.source_label.setText(f"Attached disk\n{disk.path}  {disk.human_size()}")
        self._update_actions()

    def edit_case(self) -> bool:
        dlg = CaseDialog(self.case, self)
        if dlg.exec() == QDialog.Accepted:
            self.case = dlg.case()
            if self.result is not None:
                self.result.case = self.case
            self.case_label.setText(self.case.case_name + (f"\n{self.case.examiner}" if self.case.examiner else ""))
            return True
        return False

    # Scanning
    def _busy(self) -> bool:
        return self._thread is not None

    def start_scan(self) -> None:
        if self._busy() or not (self.image_path or self.disk):
            return
        engine = ScanEngine(self.audit)
        if self.disk is not None:
            if not have_admin_rights():
                answer = QMessageBox.question(
                    self, "Elevation Needed",
                    "Reading a raw device normally needs administrator or root rights, and this session "
                    "does not have them. You can try anyway, or acquire the device with the command line "
                    "tool under sudo and open the image here.\n\nTry anyway?")
                if answer != QMessageBox.Yes:
                    return
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            default = f"{Path(self.disk.path).name or 'device'}_{stamp}.img"
            target, _ = QFileDialog.getSaveFileName(self, "Save The Acquired Image As", default,
                                                    "Images (*.img)")
            if not target:
                return
            if Path(target).exists():
                QMessageBox.warning(self, "File Exists", "Choose a new file name. Evidence images are never overwritten.")
                return
            worker = ScanWorker(engine, "disk", self.disk.path, self.case, target, self.disk.size_bytes)
        else:
            worker = ScanWorker(engine, "image", self.image_path, self.case)
        self._run(worker)

    def _run(self, worker: ScanWorker) -> None:
        thread = QThread(self)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.progress.connect(self._on_progress)
        worker.finished.connect(self._on_finished)
        worker.failed.connect(self._on_failed)
        worker.finished.connect(thread.quit)
        worker.failed.connect(thread.quit)
        thread.finished.connect(self._on_thread_done)
        self._thread, self._worker = thread, worker
        self.progress.setValue(0)
        self.progress_label.setText("Starting")
        self._update_actions()
        thread.start()

    def cancel_scan(self) -> None:
        if self._worker is not None:
            self._worker.cancel.set()
            self.progress_label.setText("Cancelling")

    def _on_progress(self, message: str, frac: float) -> None:
        self.progress.setValue(int(frac * 1000))
        self.progress_label.setText(message)

    def _on_finished(self, result: ScanResult) -> None:
        self.show_result(result)
        if result.stats.cancelled:
            self.statusBar().showMessage("Scan cancelled, the partial result is shown.")
        elif result.evidence.verified is False:
            QMessageBox.critical(self, "Verification Failed",
                                 "The acquired image does not match the hash taken during the copy. "
                                 "Treat this result with caution and acquire again.")

    def _on_failed(self, message: str) -> None:
        self.progress.setValue(0)
        self.progress_label.setText("")
        self.statusBar().showMessage(message)
        if not message.startswith("Cancelled"):
            QMessageBox.warning(self, "Scan Did Not Complete", message)

    def _on_thread_done(self) -> None:
        if self._thread is not None:
            self._thread.deleteLater()
        if self._worker is not None:
            self._worker.deleteLater()
        self._thread, self._worker = None, None
        self._update_actions()

    def show_result(self, result: ScanResult) -> None:
        self.result = result
        st = result.stats
        self.card_fs.setText(", ".join(result.detected_filesystems) or "none")
        self.card_recovered.setText(f"{st.recovered_count:,}")
        self.card_live.setText(f"{st.live_count:,}")
        self.card_time.setText(f"{st.duration_seconds:.2f} s")
        self.model.set_items(result.artifacts)
        self.table.sortByColumn(2, Qt.AscendingOrder)
        self.stack.setCurrentIndex(1)
        self.progress.setValue(1000)
        self.progress_label.setText("Scan complete")
        ev = result.evidence
        extra = f", merged {st.merged_duplicates} carved duplicates" if st.merged_duplicates else ""
        self.statusBar().showMessage(
            f"{len(result.artifacts)} items from {Path(ev.acquired_image or ev.source_path).name}{extra}. "
            f"SHA-256 {(ev.sha256 or 'not computed')[:16]}")
        if self.proxy.rowCount():
            self.table.selectRow(0)
        self._update_actions()

    # Details
    def _selected(self) -> list[Artifact]:
        rows = {self.proxy.mapToSource(i).row() for i in self.table.selectionModel().selectedRows()}
        return [a for a in (self.model.artifact_at(r) for r in sorted(rows)) if a is not None]

    def _show_details(self, *_):
        items = self._selected()
        self._update_actions()
        if not items:
            return
        a = items[0]
        colour = STATE_COLOURS.get(a.state.value, "#1D2A36")
        self.detail_title.setText(a.path or a.name)
        vals = self._detail_values
        vals["State"].setText(f'<span style="color:{colour}; font-weight:600">{a.state.value}</span>')
        vals["Confidence"].setText(a.confidence.value)
        vals["Filesystem"].setText(a.filesystem)
        vals["Offset"].setText(f"0x{a.offset:x}  ({a.offset:,})")
        vals["Size"].setText(f"{a.size:,} bytes")
        vals["Inode"].setText(str(a.inode) if a.inode is not None else "-")
        vals["Modified"].setText(a.mtime or "-")
        vals["SHA-256"].setText(a.sha256 or "-")
        vals["Note"].setText(a.note or "-")
        self.text_view.setPlainText(a.preview_text(8000))
        self.hex_view.setPlainText(a.hex_preview(8192))

    # Outputs
    def _pick_folder(self, title: str) -> Optional[str]:
        folder = QFileDialog.getExistingDirectory(self, title)
        return folder or None

    def _export(self, items: list[Artifact]) -> None:
        if not items:
            return
        folder = self._pick_folder("Choose An Export Folder")
        if not folder:
            return
        try:
            summary = export_artifacts(items, folder, audit=self.audit)
        except (OSError, SecurityError) as exc:
            QMessageBox.warning(self, "Export Failed", str(exc))
            return
        QMessageBox.information(self, "Export Complete",
                                f"Wrote {summary.written} items to {summary.folder}.\n"
                                f"Every file was hashed again after writing, see {summary.manifest.name if summary.manifest else 'the manifest'}.")

    def export_selected(self) -> None:
        self._export(self._selected())

    def export_recovered(self) -> None:
        if self.result is not None:
            self._export(self.result.recovered())

    def generate_report(self) -> None:
        if self.result is None or self._busy():
            return
        if self.case.case_name == "Untitled Case" and not self.edit_case():
            return
        self.result.case = self.case
        folder = self._pick_folder("Choose Where To Save The Report")
        if not folder:
            return
        try:
            logo = ASSETS / "revenant_logo_square.png"
            pdf = build_report(self.result, folder, audit_entries=self.audit.entries(),
                               logo_path=str(logo) if logo.exists() else None)
        except Exception as exc:
            QMessageBox.warning(self, "Report Failed", str(exc))
            return
        self.audit.record("report", pdf.name)
        box = QMessageBox(self)
        box.setWindowTitle("Report Written")
        box.setText(f"The report was saved to\n{pdf}")
        open_btn = box.addButton("Open Report", QMessageBox.AcceptRole)
        box.addButton(QMessageBox.Close)
        box.exec()
        if box.clickedButton() is open_btn:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(pdf)))

    def _update_actions(self) -> None:
        busy = self._busy()
        has_source = bool(self.image_path or self.disk)
        self.scan_btn.setEnabled(has_source and not busy)
        self.cancel_btn.setEnabled(busy)
        self.open_btn.setEnabled(not busy)
        self.refresh_btn.setEnabled(not busy)
        has_result = self.result is not None
        if hasattr(self, "report_btn"):
            self.report_btn.setEnabled(has_result and not busy)
            self.export_all_btn.setEnabled(has_result and not busy and bool(self.result and self.result.recovered()))
            self.export_btn.setEnabled(has_result and not busy and bool(self._selected()))

    def closeEvent(self, event) -> None:
        if self._worker is not None:
            self._worker.cancel.set()
        if self._thread is not None:
            self._thread.quit()
            self._thread.wait(3000)
        super().closeEvent(event)
