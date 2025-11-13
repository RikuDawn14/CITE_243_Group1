# modules/example_module.py

from PySide6 import QtWidgets, QtCore
import steampunk_theme as theme


def get_metadata():
    return {
        "name": "Example Gauge",
        "description": "Demo module with a faux steampunk gauge using NIC colors.",
    }


def create_module(parent=None):
    widget = QtWidgets.QWidget(parent)
    layout = QtWidgets.QVBoxLayout(widget)
    layout.setContentsMargins(10, 10, 10, 10)
    layout.setSpacing(8)

    title = QtWidgets.QLabel("Example Gauge Module")
    title.setAlignment(QtCore.Qt.AlignmentFlag.AlignLeft)
    title.setStyleSheet(
        "font-size: 12pt; font-weight: bold; "
        f"color: {theme.NIC_MAROON};"
    )

    info = QtWidgets.QLabel(
        "This is a placeholder module.\n"
        "You can build your own modules in the modules folder.\n\n"
        "Theme notes:\n"
        f"- NIC maroon: {theme.NIC_MAROON}\n"
        f"- NIC gray:   {theme.NIC_GRAY}\n"
        "- Steampunk accents: brass, copper, dark panel backgrounds."
    )
    info.setWordWrap(True)

    gauge = QtWidgets.QProgressBar()
    gauge.setRange(0, 100)
    gauge.setValue(65)
    gauge.setFormat("Pressure %p%")
    gauge.setStyleSheet(
        "QProgressBar {"
        f"  border: 1px solid {theme.STEAMPUNK_BRASS};"
        "  border-radius: 4px;"
        f"  text-align: center;"
        f"  background: {theme.STEAMPUNK_DARK_BG};"
        "}"
        "QProgressBar::chunk {"
        f"  background-color: {theme.NIC_MAROON};"
        "  margin: 1px;"
        "}"
    )

    button_row = QtWidgets.QHBoxLayout()
    button_row.addStretch()

    btn = QtWidgets.QPushButton("Do Something")
    button_row.addWidget(btn)

    layout.addWidget(title)
    layout.addWidget(info)
    layout.addWidget(gauge)
    layout.addLayout(button_row)
    layout.addStretch()

    return widget
