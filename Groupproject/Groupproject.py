# main.py

import os
import sys
import importlib.util
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from PySide6 import QtCore, QtGui, QtWidgets

import steampunk_theme as theme


@dataclass
class ModuleInfo:
    name: str
    description: str
    create_widget: Callable[[Optional[QtWidgets.QWidget]], QtWidgets.QWidget]


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self, modules: List[ModuleInfo]):
        super().__init__()
        self.modules = modules
        self.module_widgets: Dict[str, QtWidgets.QWidget] = {}

        self.setWindowTitle("NIC Steampunk Control Center")
        self.resize(1100, 700)

        self._build_ui()

    def _build_ui(self):
        central = QtWidgets.QWidget()
        root_layout = QtWidgets.QVBoxLayout(central)
        root_layout.setContentsMargins(6, 6, 6, 6)
        root_layout.setSpacing(6)

        # Header bar
        header = QtWidgets.QFrame()
        header.setObjectName("HeaderBar")
        header_layout = QtWidgets.QHBoxLayout(header)
        header_layout.setContentsMargins(10, 6, 10, 6)

        title_label = QtWidgets.QLabel("North Idaho Steampunk")
        title_label.setObjectName("HeaderTitle")

        subtitle_label = QtWidgets.QLabel("Module Console")
        subtitle_label.setObjectName("HeaderSubtitle")

        title_box = QtWidgets.QVBoxLayout()
        title_box.addWidget(title_label)
        title_box.addWidget(subtitle_label)
        title_box.setSpacing(0)

        header_layout.addLayout(title_box)
        header_layout.addStretch()

        refresh_button = QtWidgets.QPushButton("Reload Modules")
        refresh_button.clicked.connect(self._reload_modules_clicked)
        header_layout.addWidget(refresh_button)

        root_layout.addWidget(header)

        # Splitter: left module list, right content
        splitter = QtWidgets.QSplitter(QtCore.Qt.Orientation.Horizontal)

        # Left: module list
        self.module_list = QtWidgets.QListWidget()
        self.module_list.setSelectionMode(
            QtWidgets.QAbstractItemView.SelectionMode.SingleSelection
        )
        self.module_list.currentRowChanged.connect(self._on_module_selected)

        for m in self.modules:
            item = QtWidgets.QListWidgetItem(m.name)
            item.setToolTip(m.description)
            self.module_list.addItem(item)

        splitter.addWidget(self.module_list)
        splitter.setStretchFactor(0, 0)

        # Right: stacked content
        right_container = QtWidgets.QWidget()
        right_layout = QtWidgets.QVBoxLayout(right_container)
        right_layout.setContentsMargins(0, 0, 0, 0)

        content_frame = QtWidgets.QFrame()
        content_frame.setObjectName("ContentPanel")
        content_layout = QtWidgets.QVBoxLayout(content_frame)
        content_layout.setContentsMargins(10, 10, 10, 10)

        self.stack = QtWidgets.QStackedWidget()
        content_layout.addWidget(self.stack)

        right_layout.addWidget(content_frame)
        splitter.addWidget(right_container)
        splitter.setStretchFactor(1, 1)

        root_layout.addWidget(splitter)
        self.setCentralWidget(central)

        if self.modules:
            self.module_list.setCurrentRow(0)

    def _reload_modules_clicked(self):
        QtWidgets.QMessageBox.information(
            self,
            "Reload Modules",
            "Reload is not implemented yet. Restart the app to reload modules.",
        )

    def _on_module_selected(self, index: int):
        if index < 0 or index >= len(self.modules):
            return

        mod = self.modules[index]

        if mod.name not in self.module_widgets:
            widget = mod.create_widget(self)
            self.module_widgets[mod.name] = widget
            self.stack.addWidget(widget)

        widget = self.module_widgets[mod.name]
        self.stack.setCurrentWidget(widget)


def discover_modules(modules_path: str) -> List[ModuleInfo]:
    """
    Look for .py files in modules_path.
    Each module file should define:
      - function get_metadata() -> dict with "name" and "description"
      - function create_module(parent=None) -> QWidget
    """
    result: List[ModuleInfo] = []

    if not os.path.isdir(modules_path):
        print(f"Modules folder not found: {modules_path}")
        return result

    for filename in os.listdir(modules_path):
        base_name, ext = os.path.splitext(filename)
        if ext != ".py":
            continue

        # Skip package init and any private helpers
        if base_name in ("__init__", "init"):
            continue
        if filename.startswith("_"):
            continue

        file_path = os.path.join(modules_path, filename)
        mod_name = f"nic_mod_{base_name}"

        spec = importlib.util.spec_from_file_location(mod_name, file_path)
        if spec is None or spec.loader is None:
            continue

        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)  # type: ignore[attr-defined]
        except Exception as exc:
            print(f"Failed to load module {filename}: {exc}")
            continue

        get_metadata = getattr(module, "get_metadata", None)
        create_module_func = getattr(module, "create_module", None)

        if not callable(get_metadata) or not callable(create_module_func):
            print(
                f"Module {filename} does not provide get_metadata() and create_module()."
            )
            continue

        try:
            meta = get_metadata()
            name = str(meta.get("name", filename))
            description = str(meta.get("description", ""))
        except Exception as exc:
            print(f"Error reading metadata from {filename}: {exc}")
            continue

        result.append(
            ModuleInfo(
                name=name,
                description=description,
                create_widget=create_module_func,
            )
        )

    result.sort(key=lambda m: m.name.lower())
    return result


def main():
    app = QtWidgets.QApplication(sys.argv)
    app.setStyleSheet(theme.APP_STYLESHEET)

    modules_dir = os.path.join(os.path.dirname(__file__), "modules")
    modules = discover_modules(modules_dir)

    window = MainWindow(modules)
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
