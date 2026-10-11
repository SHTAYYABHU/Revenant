"""The look of the desktop interface, kept in one place.

Colours match the report and the logo so the whole tool feels like one piece.
The page background is painted only on the root container, and labels are
transparent, so text sitting on the navy header or a white card never shows a
pale box behind it.
"""

NAVY = "#0E2A47"
NAVY_SOFT = "#173A5E"
ACCENT = "#2E6FB7"
ACCENT_HOVER = "#3C82D0"
BG = "#F3F6FA"
PANEL = "#FFFFFF"
BORDER = "#D8E2EC"
TEXT = "#1D2A36"
MUTED = "#667788"
LIGHT_ROW = "#F0F4F8"
DANGER = "#B23A48"

STATE_COLOURS = {
    "live": "#3C7D3C",
    "deleted": "#B23A48",
    "obsolete": "#B5852A",
    "orphaned": "#6E5AA6",
    "carved": "#2E6FB7",
}


def stylesheet() -> str:
    return f"""
    QMainWindow, QWidget#Root, QWidget#Content {{ background: {BG}; }}
    QWidget {{
        color: {TEXT};
        font-family: "Segoe UI", "Helvetica Neue", "Noto Sans", Arial, sans-serif;
        font-size: 13px;
    }}
    QLabel {{ background: transparent; }}
    QWidget#HeaderBar {{ background: {NAVY}; }}
    QLabel#HeaderTitle {{ color: white; font-size: 20px; font-weight: 600; }}
    QLabel#HeaderTagline {{ color: #9FB6CE; font-size: 12px; }}
    QLabel#PrivChip {{
        color: white; background: {NAVY_SOFT}; border: 1px solid #2A4E75;
        border-radius: 11px; padding: 3px 12px; font-size: 11px;
    }}
    QWidget#Sidebar {{ background: {PANEL}; border-right: 1px solid {BORDER}; }}
    QFrame#Card {{ background: {PANEL}; border: 1px solid {BORDER}; border-radius: 10px; }}
    QLabel#CardTitle {{ color: {MUTED}; font-size: 11px; font-weight: 600; }}
    QLabel#CardValue {{ color: {NAVY}; font-size: 20px; font-weight: 600; }}
    QLabel#SectionLabel {{ color: {MUTED}; font-size: 11px; font-weight: 600; }}
    QLabel#Muted {{ color: {MUTED}; }}
    QLabel#EmptyTitle {{ color: {NAVY}; font-size: 17px; font-weight: 600; }}
    QLabel#DetailTitle {{ color: {NAVY}; font-size: 15px; font-weight: 600; }}
    QPushButton {{
        background: {PANEL}; border: 1px solid {BORDER}; border-radius: 7px;
        padding: 7px 14px; color: {TEXT};
    }}
    QPushButton:hover {{ border-color: {ACCENT}; color: {ACCENT}; }}
    QPushButton:disabled {{ color: #A9B6C4; border-color: #E4EAF1; }}
    QPushButton#Primary {{ background: {ACCENT}; border: 1px solid {ACCENT}; color: white; font-weight: 600; }}
    QPushButton#Primary:hover {{ background: {ACCENT_HOVER}; border-color: {ACCENT_HOVER}; color: white; }}
    QPushButton#Primary:disabled {{ background: #A9C4E4; border-color: #A9C4E4; color: white; }}
    QPushButton#Danger:enabled {{ color: {DANGER}; border-color: #E7C3C8; }}
    QPushButton#Danger:hover {{ background: #FBEFF1; }}
    QListWidget, QTableView, QPlainTextEdit, QLineEdit, QComboBox {{
        background: {PANEL}; border: 1px solid {BORDER}; border-radius: 8px;
        selection-background-color: {ACCENT}; selection-color: white;
    }}
    QLineEdit, QComboBox {{ padding: 6px 10px; }}
    QComboBox::drop-down {{ border: none; width: 22px; }}
    QListWidget::item {{ padding: 8px 6px; border-bottom: 1px solid {LIGHT_ROW}; }}
    QListWidget::item:selected {{ background: {ACCENT}; color: white; border-radius: 6px; }}
    QTableView {{ gridline-color: {LIGHT_ROW}; alternate-background-color: #F7FAFC; }}
    QHeaderView::section {{
        background: {PANEL}; color: {MUTED}; border: none;
        border-bottom: 1px solid {BORDER}; padding: 7px 8px; font-weight: 600;
    }}
    QProgressBar {{
        border: 1px solid {BORDER}; border-radius: 5px; background: {LIGHT_ROW};
        max-height: 10px; text-align: center; font-size: 1px; color: transparent;
    }}
    QProgressBar::chunk {{ background: {ACCENT}; border-radius: 5px; }}
    QTabWidget::pane {{ border: 1px solid {BORDER}; border-radius: 8px; background: {PANEL}; top: -1px; }}
    QTabBar::tab {{ padding: 6px 14px; color: {MUTED}; background: transparent; border: none; }}
    QTabBar::tab:selected {{ color: {ACCENT}; border-bottom: 2px solid {ACCENT}; }}
    QStatusBar {{ background: {PANEL}; border-top: 1px solid {BORDER}; color: {MUTED}; }}
    QSplitter::handle {{ background: {BG}; }}
    QToolTip {{ background: {NAVY}; color: white; border: none; padding: 6px; }}
    QDialog {{ background: {BG}; }}
    """
