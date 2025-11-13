# modules/website_scanner.py

from PySide6 import QtWidgets, QtCore
from bs4 import BeautifulSoup
import requests
from urllib.parse import urljoin
from thread_worker import Worker

def get_metadata():
    return {
        "name": "Website Scanner",
        "description": "Scan site for broken links, images, and header tags."
    }

def scan_broken_links(url):
    output = []
    seen = set()

    try:
        base = requests.get(url, timeout=10)
    except Exception:
        return "Could not reach URL."

    soup = BeautifulSoup(base.text, "html.parser")
    links = soup.find_all("a")

    for link in links:
        href = link.get("href")
        if not href:
            continue

        full = urljoin(url, href)
        if full in seen:
            continue
        seen.add(full)

        try:
            r = requests.get(full, timeout=10)
            if r.status_code >= 400:
                output.append(f"Broken: {full} (Status {r.status_code})")
        except Exception:
            output.append(f"Broken: {full} (No response)")

    if not output:
        return "No broken links found."

    return "\n".join(output)

def scan_images(url):
    output = []
    seen = set()

    try:
        base = requests.get(url, timeout=10)
    except Exception:
        return "Could not reach URL."

    soup = BeautifulSoup(base.text, "html.parser")
    images = soup.find_all("img")

    for img in images:
        src = img.get("src")
        if not src:
            continue

        full = urljoin(url, src)
        if full in seen:
            continue
        seen.add(full)

        try:
            r = requests.get(full, timeout=10)
            if r.status_code >= 400:
                output.append(f"Missing image: {full} (Status {r.status_code})")
        except Exception:
            output.append(f"Missing image: {full} (No response)")

    if not output:
        return "No missing images found."

    return "\n".join(output)

def scan_headers(url):
    try:
        r = requests.get(url, timeout=10)
    except Exception:
        return "Could not reach URL."

    soup = BeautifulSoup(r.text, "html.parser")

    h1 = len(soup.find_all("h1"))
    h2 = len(soup.find_all("h2"))
    h3 = len(soup.find_all("h3"))

    out = []
    out.append(f"H1 count: {h1}")
    out.append(f"H2 count: {h2}")
    out.append(f"H3 count: {h3}")

    if h1 == 0:
        out.append("WARNING: No H1 tag found.")

    return "\n".join(out)

def full_scan(url):
    parts = []
    parts.append("=== Broken Links ===")
    parts.append(scan_broken_links(url))
    parts.append("")
    parts.append("=== Images ===")
    parts.append(scan_images(url))
    parts.append("")
    parts.append("=== Headers ===")
    parts.append(scan_headers(url))
    return "\n".join(parts)

def create_module(parent=None):
    widget = QtWidgets.QWidget(parent)
    widget.thread_pool = []  # REQUIRED TO PREVENT QTHREAD DESTRUCTION
    layout = QtWidgets.QVBoxLayout(widget)

    # URL input
    row = QtWidgets.QHBoxLayout()
    url_label = QtWidgets.QLabel("URL:")
    url_input = QtWidgets.QLineEdit()
    row.addWidget(url_label)
    row.addWidget(url_input)
    layout.addLayout(row)

    # Buttons
    btn_row = QtWidgets.QHBoxLayout()
    btn_links = QtWidgets.QPushButton("Scan Broken Links")
    btn_imgs = QtWidgets.QPushButton("Scan Images")
    btn_headers = QtWidgets.QPushButton("Scan Headers")
    btn_full = QtWidgets.QPushButton("Full Scan")

    btn_row.addWidget(btn_links)
    btn_row.addWidget(btn_imgs)
    btn_row.addWidget(btn_headers)
    btn_row.addWidget(btn_full)
    layout.addLayout(btn_row)

    # Results
    results = QtWidgets.QTextEdit()
    results.setReadOnly(True)
    layout.addWidget(results)

    def run_thread(fn):
        url = url_input.text().strip()
        if not url:
            results.setPlainText("Enter a valid URL.")
            return

        if not url.startswith("http://") and not url.startswith("https://"):
            url_to_use = "http://" + url
        else:
            url_to_use = url

        results.setPlainText("Scanning...")

        worker = Worker(fn, url_to_use)
        thread = QtCore.QThread()

        worker.moveToThread(thread)

        worker.finished.connect(results.setPlainText)
        worker.error.connect(results.setPlainText)

        worker.finished.connect(thread.quit)
        worker.error.connect(thread.quit)

        thread.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)

        thread.started.connect(worker.run)

        widget.thread_pool.append(thread)  # KEEP THREAD ALIVE
        thread.start()

    btn_links.clicked.connect(lambda: run_thread(scan_broken_links))
    btn_imgs.clicked.connect(lambda: run_thread(scan_images))
    btn_headers.clicked.connect(lambda: run_thread(scan_headers))
    btn_full.clicked.connect(lambda: run_thread(full_scan))

    return widget
