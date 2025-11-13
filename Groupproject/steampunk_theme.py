# steampunk_theme.py

NIC_MAROON = "#98002E"
NIC_GRAY   = "#999999"

STEAMPUNK_DARK_BG   = "#1f1b18"
STEAMPUNK_PANEL_BG  = "#2b2520"
STEAMPUNK_BRASS     = "#b08d57"
STEAMPUNK_COPPER    = "#b87333"
STEAMPUNK_TEXT      = "#f2e6d8"

APP_STYLESHEET = f"""
QMainWindow {{
    background-color: {STEAMPUNK_DARK_BG};
    color: {STEAMPUNK_TEXT};
}}

QWidget {{
    background-color: {STEAMPUNK_DARK_BG};
    color: {STEAMPUNK_TEXT};
    font-family: Segoe UI, Arial, sans-serif;
    font-size: 10pt;
}}

QSplitter::handle {{
    background-color: {STEAMPUNK_BRASS};
}}

QListWidget {{
    background-color: {STEAMPUNK_PANEL_BG};
    border: 1px solid {STEAMPUNK_BRASS};
    padding: 4px;
}}

QListWidget::item {{
    padding: 6px;
    border-bottom: 1px solid {NIC_GRAY};
}}

QListWidget::item:selected {{
    background-color: {NIC_MAROON};
    color: white;
}}

QFrame#HeaderBar {{
    background-color: {NIC_MAROON};
    border-bottom: 2px solid {STEAMPUNK_BRASS};
}}

QLabel#HeaderTitle {{
    font-size: 14pt;
    font-weight: bold;
    color: white;
}}

QLabel#HeaderSubtitle {{
    font-size: 9pt;
    color: {NIC_GRAY};
}}

QFrame#ContentPanel {{
    background-color: {STEAMPUNK_PANEL_BG};
    border: 1px solid {STEAMPUNK_BRASS};
    border-radius: 4px;
}}

QScrollArea {{
    background-color: {STEAMPUNK_PANEL_BG};
    border: none;
}}

QPushButton {{
    background-color: {STEAMPUNK_COPPER};
    color: black;
    border: 1px solid {STEAMPUNK_BRASS};
    border-radius: 4px;
    padding: 4px 10px;
}}

QPushButton:hover {{
    background-color: {NIC_MAROON};
    color: white;
}}

QToolTip {{
    background-color: {STEAMPUNK_PANEL_BG};
    color: {STEAMPUNK_TEXT};
    border: 1px solid {STEAMPUNK_BRASS};
}}
"""
