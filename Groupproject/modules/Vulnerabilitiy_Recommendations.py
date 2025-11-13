# modules/vuln_recommendations.py

from PySide6 import QtWidgets

def get_metadata():
    return {
        "name": "Vulnerability Recommendations",
        "description": "Generate security recommendations based on scan results."
    }

def generate_recs(text):
    out = []
    t = text.lower()

    if "missing" in t and "security header" in t:
        out.append("Missing security headers detected.")
        out.append("- Add HSTS, CSP, X-Frame-Options, Referrer-Policy.")
        out.append("")

    if "x-powered-by" in t and "not disclosed" not in t:
        out.append("Server exposes X-Powered-By.")
        out.append("- Disable or mask X-Powered-By header.")
        out.append("")

    if "port 21: open" in t:
        out.append("Port 21 (FTP) is open.")
        out.append("- Disable FTP or replace with SFTP.")
        out.append("")

    if "port 3389: open" in t:
        out.append("RDP port 3389 is open.")
        out.append("- Restrict RDP access with firewall or VPN.")
        out.append("")

    if "ssl check failed" in t:
        out.append("SSL certificate or handshake problem found.")
        out.append("- Verify certificate validity and TLS setup.")
        out.append("")

    if not out:
        return "No specific recommendations detected."

    return "\n".join(out)

def create_module(parent=None):
    widget = QtWidgets.QWidget(parent)
    layout = QtWidgets.QVBoxLayout(widget)

    input_box = QtWidgets.QTextEdit()
    input_box.setPlaceholderText("Paste scan results here...")
    layout.addWidget(input_box)

    btn = QtWidgets.QPushButton("Generate Recommendations")
    layout.addWidget(btn)

    output_box = QtWidgets.QTextEdit()
    output_box.setReadOnly(True)
    layout.addWidget(output_box)

    def do_generate():
        text = input_box.toPlainText()
        output_box.setPlainText(generate_recs(text))

    btn.clicked.connect(do_generate)

    return widget
