"""Application bootstrap.

Creates the Qt application, applies the theme, and shows the main window. This
is what the launcher and the module entry point both call, so there is one
place that starts the interface.
"""

from __future__ import annotations

import logging
import sys

from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication

from .version import APP_NAME, __version__


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(__version__)

    # Import here so a headless import of this module does not require a display.
    from pathlib import Path
    from .ui.main_window import MainWindow

    icon_file = Path(__file__).resolve().parent / "assets" / "revenant_logo_square.png"
    if icon_file.exists():
        app.setWindowIcon(QIcon(str(icon_file)))

    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
