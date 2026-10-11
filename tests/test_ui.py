"""An offscreen smoke test of the desktop window."""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
QtWidgets = pytest.importorskip("PySide6.QtWidgets")


@pytest.fixture(scope="module")
def app():
    return QtWidgets.QApplication.instance() or QtWidgets.QApplication([])


def test_window_shows_a_result_and_details(app, samples):
    from revenant.core.engine import ScanEngine
    from revenant.ui.main_window import MainWindow

    w = MainWindow()
    assert not w.scan_btn.isEnabled() and not w.cancel_btn.isEnabled()
    w.image_path = str(samples / "jffs2_demo.img")
    w._update_actions()
    assert w.scan_btn.isEnabled()
    w.show_result(ScanEngine(w.audit).scan_image(w.image_path))
    app.processEvents()
    assert w.proxy.rowCount() == len(w.result.artifacts) > 0
    assert w.detail_title.text() != "Select an item to inspect it"
    assert w.hex_view.toPlainText().startswith("00000000")
    w.proxy.set_state("deleted")
    assert all(w.model.artifact_at(w.proxy.mapToSource(w.proxy.index(r, 0)).row()).state.value == "deleted"
               for r in range(w.proxy.rowCount()))
    w.close()
