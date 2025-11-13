# modules/vuln_scanner.py

from PySide6 import QtWidgets, QtCore
import socket
import ssl
import requests
from urllib.parse import urlparse
from thread_worker import Worker

def get_metadata():
    return {
        "name": "Vulnerability Scanner",
        "description": "Scan for server vulnerabilities, ports, SSL, and headers."
    }

def normalize_url(target):
    t = target.strip()
    if t.startswith("http://") or t.startswith("https://"):
        return t
    return "http://" + t

def get_hostname(target):
    t = normalize_url(target)
    parsed = urlparse(t)
    if parsed.hostname:
        return parsed.hostname
    return t

def fingerprint_server(target):
    url = normalize_url(target)
    try:
        r = requests.get(url, timeout=10)
    except Exception:
        return "Could not connect to server."

    out = []
    server = r.headers.get("Server", "Unknown")
    powered = r.headers.get("X-Powered-By", "Not disclosed")

    out.append(f"Server: {server}")
    out.append(f"X-Powered-By: {powered}")
    out.append("")

    checks = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-XSS-Protection",
        "Referrer-Policy"
    ]

    out.append("Security Headers:")
    for h in checks:
        if h in r.headers:
            out.append(f"  {h}: PRESENT")
        else:
            out.append(f"  {h}: MISSING")

    return "\n".join(out)

def ssl_check(target):
    host = get_hostname(target)

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(5)
            s.connect((host, 443))
            cert = s.getpeercert()
    except Exception as e:
        return f"SSL check failed: {str(e)}"

    out = [
        "SSL Certificate Info:",
        f"Subject: {cert.get('subject')}",
        f"Issuer: {cert.get('issuer')}",
        f"Valid From: {cert.get('notBefore')}",
        f"Valid Until: {cert.get('notAfter')}",
    ]

    return "\n".join(out)

def port_probe(target):
    host = get_hostname(target)
    ports = [80, 443, 21, 22, 3306, 3389, 8080]

    out = []
    for p in ports:
        s = socket.socket()
        s.settimeout(2)
        try:
            s.connect((host, p))
            out.append(f"Port {p}: OPEN")
        except Exception:
            out.append(f"Port {p}: closed")
        s.close()

    return "\n".join(out)

def full_scan(target):
    return "\n".join([
        "=== Fingerprint ===",
        fingerprint_server(target),
        "",
        "=== SSL ===",
        ssl_check(target),
        "",
        "=== Ports ===",
        port_probe(target)
    ])

def create_module(parent=None):
    widget = QtWidgets.QWidget(parent)
    widget.thread_pool = []  # REQUIRED FIX
    layout = QtWidgets.QVBoxLayout(widget)

    # Input
    row = QtWidgets.QHBoxLayout()
    label = QtWidgets.QLabel("Target:")
    input_box = QtWidgets.QLineEdit()
    row.addWidget(label)
    row.addWidget(input_box)
    layout.addLayout(row)

    # Buttons
    btn_row = QtWidgets.QHBoxLayout()
    quick = QtWidgets.QPushButton("Quick Scan")
    ssl_btn = QtWidgets.QPushButton("SSL Check")
    port_btn = QtWidgets.QPushButton("Port Probe")
    full = QtWidgets.QPushButton("Full Scan")

    btn_row.addWidget(quick)
    btn_row.addWidget(ssl_btn)
    btn_row.addWidget(port_btn)
    btn_row.addWidget(full)
    layout.addLayout(btn_row)

    # Output
    out_box = QtWidgets.QTextEdit()
    out_box.setReadOnly(True)
    layout.addWidget(out_box)

    def run_thread(fn):
        target = input_box.text().strip()
        if not target:
            out_box.setPlainText("Enter a domain or URL.")
            return

        out_box.setPlainText("Scanning...")

        worker = Worker(fn, target)
        thread = QtCore.QThread()
        worker.moveToThread(thread)

        worker.finished.connect(out_box.setPlainText)
        worker.error.connect(out_box.setPlainText)

        worker.finished.connect(thread.quit)
        worker.error.connect(thread.quit)

        thread.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)

        thread.started.connect(worker.run)

        widget.thread_pool.append(thread)
        thread.start()

    quick.clicked.connect(lambda: run_thread(fingerprint_server))
    ssl_btn.clicked.connect(lambda: run_thread(ssl_check))
    port_btn.clicked.connect(lambda: run_thread(port_probe))
    full.clicked.connect(lambda: run_thread(full_scan))

    return widget
