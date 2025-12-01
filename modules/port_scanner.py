import socket
import subprocess
import platform
from typing import Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from PySide6 import QtWidgets, QtCore


def get_metadata() -> dict:
    """Return module metadata for the main application."""
    return {
        "name": "Port Scanner",
        "description": "Network port scanner with service detection and auto-network discovery",
    }


def create_module(parent: Optional[QtWidgets.QWidget] = None) -> QtWidgets.QWidget:
    """Create and return the port scanner widget."""
    return PortScannerWidget(parent)


class PortScannerWidget(QtWidgets.QWidget):
    """Port scanner widget that integrates with the steampunk GUI."""

    def __init__(self, parent: Optional[QtWidgets.QWidget] = None):
        super().__init__(parent)
        self.scanning = False
        self.scan_thread = None
        self.router_ip = None
        self._build_ui()
        self._detect_network()

    def _build_ui(self):
        """Build the port scanner interface."""
        layout = QtWidgets.QVBoxLayout(self)
        layout.setSpacing(12)

        # Title
        title = QtWidgets.QLabel("Advanced Port Scanner")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #b08d57;")
        layout.addWidget(title)

        # Network Detection Section
        network_group = self._create_network_section()
        layout.addWidget(network_group)

        # Target Configuration
        target_group = self._create_target_section()
        layout.addWidget(target_group)

        # Scan Options
        options_group = self._create_options_section()
        layout.addWidget(options_group)

        # Control Buttons
        control_layout = self._create_controls()
        layout.addLayout(control_layout)

        # Progress
        progress_layout = QtWidgets.QHBoxLayout()
        self.progress_bar = QtWidgets.QProgressBar()
        self.status_label = QtWidgets.QLabel("Ready to scan")
        progress_layout.addWidget(self.progress_bar, 3)
        progress_layout.addWidget(self.status_label, 1)
        layout.addLayout(progress_layout)

        # Results
        results_label = QtWidgets.QLabel("Scan Results:")
        results_label.setStyleSheet("font-weight: bold;")
        layout.addWidget(results_label)

        self.results_text = QtWidgets.QTextEdit()
        self.results_text.setReadOnly(True)
        self.results_text.setStyleSheet(
            "background-color: #0a0a0a; color: #b87333; "
            "font-family: 'Courier New', monospace; font-size: 11px;"
        )
        layout.addWidget(self.results_text, 1)

        # Export buttons
        export_layout = QtWidgets.QHBoxLayout()
        export_layout.addStretch()
        export_txt = QtWidgets.QPushButton("Export TXT")
        export_txt.clicked.connect(self._export_txt)
        export_csv = QtWidgets.QPushButton("Export CSV")
        export_csv.clicked.connect(self._export_csv)
        export_json = QtWidgets.QPushButton("Export JSON")
        export_json.clicked.connect(self._export_json)
        export_layout.addWidget(export_txt)
        export_layout.addWidget(export_csv)
        export_layout.addWidget(export_json)
        layout.addLayout(export_layout)

    def _create_network_section(self):
        """Create network detection section."""
        group = QtWidgets.QGroupBox("Network Detection")
        layout = QtWidgets.QVBoxLayout()

        self.network_info_label = QtWidgets.QLabel("Detecting network...")
        layout.addWidget(self.network_info_label)

        btn_layout = QtWidgets.QHBoxLayout()
        self.scan_local_btn = QtWidgets.QPushButton("Scan This Computer")
        self.scan_local_btn.setToolTip("Scan ports on 127.0.0.1")
        self.scan_local_btn.clicked.connect(self._scan_localhost)
        
        self.scan_router_btn = QtWidgets.QPushButton("Scan Router")
        self.scan_router_btn.setToolTip("Scan your router/gateway")
        self.scan_router_btn.clicked.connect(self._scan_router)
        
        btn_layout.addWidget(self.scan_local_btn)
        btn_layout.addWidget(self.scan_router_btn)
        layout.addLayout(btn_layout)
        
        group.setLayout(layout)
        return group

    def _create_target_section(self):
        """Create target configuration section."""
        group = QtWidgets.QGroupBox("Target Configuration")
        layout = QtWidgets.QFormLayout()

        self.ip_input = QtWidgets.QLineEdit("127.0.0.1")
        self.ip_input.setPlaceholderText("e.g., 192.168.1.1 or scanme.nmap.org")
        layout.addRow("Target IP/Host:", self.ip_input)

        # Port range
        port_layout = QtWidgets.QHBoxLayout()
        self.port_start_input = QtWidgets.QSpinBox()
        self.port_start_input.setRange(1, 65535)
        self.port_start_input.setValue(1)
        
        self.port_end_input = QtWidgets.QSpinBox()
        self.port_end_input.setRange(1, 65535)
        self.port_end_input.setValue(1024)
        
        port_layout.addWidget(QtWidgets.QLabel("From:"))
        port_layout.addWidget(self.port_start_input)
        port_layout.addWidget(QtWidgets.QLabel("To:"))
        port_layout.addWidget(self.port_end_input)
        port_layout.addStretch()
        layout.addRow("Port Range:", port_layout)

        # Presets
        preset_layout = QtWidgets.QHBoxLayout()
        presets = [
            ("Common", 1, 1024),
            ("Well-Known", 1, 1024),
            ("Registered", 1024, 49151),
            ("All Ports", 1, 65535)
        ]
        for name, start, end in presets:
            btn = QtWidgets.QPushButton(name)
            btn.clicked.connect(lambda checked, s=start, e=end: self._set_ports(s, e))
            preset_layout.addWidget(btn)
        preset_layout.addStretch()
        layout.addRow("Presets:", preset_layout)

        group.setLayout(layout)
        return group

    def _create_options_section(self):
        """Create scan options section."""
        group = QtWidgets.QGroupBox("Scan Options")
        layout = QtWidgets.QHBoxLayout()

        self.service_check = QtWidgets.QCheckBox("Service Detection")
        self.service_check.setChecked(True)
        self.banner_check = QtWidgets.QCheckBox("Banner Grabbing")
        self.banner_check.setChecked(True)
        self.os_check = QtWidgets.QCheckBox("OS Fingerprinting")

        layout.addWidget(self.service_check)
        layout.addWidget(self.banner_check)
        layout.addWidget(self.os_check)
        layout.addStretch()

        layout.addWidget(QtWidgets.QLabel("Threads:"))
        self.thread_spin = QtWidgets.QSpinBox()
        self.thread_spin.setRange(1, 100)
        self.thread_spin.setValue(50)
        layout.addWidget(self.thread_spin)

        group.setLayout(layout)
        return group

    def _create_controls(self):
        """Create control buttons."""
        layout = QtWidgets.QHBoxLayout()

        self.scan_btn = QtWidgets.QPushButton("▶ Start Scan")
        self.scan_btn.setMinimumHeight(40)
        self.scan_btn.clicked.connect(self._start_scan)

        self.stop_btn = QtWidgets.QPushButton("⏹ Stop")
        self.stop_btn.setMinimumHeight(40)
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop_scan)

        self.clear_btn = QtWidgets.QPushButton("Clear")
        self.clear_btn.setMinimumHeight(40)
        self.clear_btn.clicked.connect(self._clear_results)

        layout.addWidget(self.scan_btn)
        layout.addWidget(self.stop_btn)
        layout.addWidget(self.clear_btn)
        return layout

    def _detect_network(self):
        """Detect local network information."""
        try:
            # Get local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()

            # Get router/gateway IP
            router_ip = "Unknown"
            if platform.system() == "Windows":
                result = subprocess.run(["ipconfig"], capture_output=True, text=True)
                for line in result.stdout.split("\n"):
                    if "Default Gateway" in line and ":" in line:
                        router_ip = line.split(":")[1].strip()
                        if router_ip:
                            break
            else:
                result = subprocess.run(["ip", "route"], capture_output=True, text=True)
                for line in result.stdout.split("\n"):
                    if "default" in line:
                        parts = line.split()
                        if len(parts) > 2:
                            router_ip = parts[2]
                            break

            self.router_ip = router_ip if router_ip != "Unknown" else None
            info = f"Local IP: {local_ip}"
            if self.router_ip:
                info += f" | Router: {self.router_ip}"
                self.scan_router_btn.setEnabled(True)
            else:
                info += " | Router: Not detected"
                self.scan_router_btn.setEnabled(False)
            
            self.network_info_label.setText(info)
        except Exception as e:
            self.network_info_label.setText(f"Network detection failed")
            self.scan_router_btn.setEnabled(False)

    def _set_ports(self, start, end):
        """Set port range."""
        self.port_start_input.setValue(start)
        self.port_end_input.setValue(end)

    def _scan_localhost(self):
        """Quick localhost scan."""
        self.ip_input.setText("127.0.0.1")
        self._set_ports(1, 1024)
        self._start_scan()

    def _scan_router(self):
        """Quick router scan."""
        if self.router_ip:
            self.ip_input.setText(self.router_ip)
            self._set_ports(1, 1024)
            self._start_scan()

    def _start_scan(self):
        """Start port scanning."""
        if self.scanning:
            return

        target = self.ip_input.text().strip()
        if not target:
            QtWidgets.QMessageBox.warning(self, "Error", "Enter a target IP/hostname")
            return

        start = self.port_start_input.value()
        end = self.port_end_input.value()
        if start > end:
            QtWidgets.QMessageBox.warning(self, "Error", "Start port must be ≤ end port")
            return

        self.scanning = True
        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setValue(0)
        self.results_text.clear()

        self.scan_thread = ScanThread(
            target, start, end,
            self.thread_spin.value(),
            self.service_check.isChecked(),
            self.banner_check.isChecked(),
            self.os_check.isChecked()
        )
        self.scan_thread.progress.connect(self.progress_bar.setValue)
        self.scan_thread.result.connect(self.results_text.append)
        self.scan_thread.status.connect(self.status_label.setText)
        self.scan_thread.finished_signal.connect(self._scan_finished)
        self.scan_thread.start()

    def _stop_scan(self):
        """Stop current scan."""
        if self.scan_thread:
            self.scan_thread.stop()
            self.status_label.setText("Stopping...")

    def _scan_finished(self):
        """Handle scan completion."""
        self.scanning = False
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setValue(100)
        self.status_label.setText("Complete!")

    def _clear_results(self):
        """Clear results."""
        self.results_text.clear()
        self.progress_bar.setValue(0)
        self.status_label.setText("Ready to scan")

    def _export_txt(self):
        """Export results as text."""
        filename, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "Export", "", "Text Files (*.txt)"
        )
        if filename:
            with open(filename, "w") as f:
                f.write(self.results_text.toPlainText())
            QtWidgets.QMessageBox.information(self, "Success", f"Exported to {filename}")

    def _export_csv(self):
        """Export results as CSV."""
        filename, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "Export", "", "CSV Files (*.csv)"
        )
        if filename:
            import csv
            with open(filename, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Port", "Status", "Service"])
                for line in self.results_text.toPlainText().split("\n"):
                    if "[OPEN]" in line:
                        writer.writerow([line])
            QtWidgets.QMessageBox.information(self, "Success", f"Exported to {filename}")

    def _export_json(self):
        """Export results as JSON."""
        filename, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "Export", "", "JSON Files (*.json)"
        )
        if filename:
            import json
            from datetime import datetime
            
            # Parse the results to extract structured data
            results_text = self.results_text.toPlainText()
            lines = results_text.split("\n")
            
            # Extract scan metadata
            target = "Unknown"
            target_ip = "Unknown"
            port_range = "Unknown"
            open_ports = []
            
            for line in lines:
                if line.startswith("Target:"):
                    target = line.split(":", 1)[1].strip()
                elif line.startswith("IP:"):
                    target_ip = line.split(":", 1)[1].strip()
                elif line.startswith("Ports:"):
                    port_range = line.split(":", 1)[1].strip()
                elif "[OPEN]" in line:
                    # Parse port info: "✓ Port  80 [OPEN] - HTTP"
                    parts = line.split()
                    if len(parts) >= 3:
                        try:
                            port_num = int(parts[2])
                            service = ""
                            if "-" in line:
                                service = line.split("-", 1)[1].strip()
                            open_ports.append({
                                "port": port_num,
                                "status": "open",
                                "service": service
                            })
                        except (ValueError, IndexError):
                            pass
            
            # Build JSON structure
            scan_data = {
                "scan_info": {
                    "target": target,
                    "target_ip": target_ip if target_ip != "Unknown" else target,
                    "port_range": port_range,
                    "scan_date": datetime.now().isoformat(),
                    "scanner": "NIC Port Scanner v2.0"
                },
                "scan_results": {
                    "total_open_ports": len(open_ports),
                    "open_ports": sorted(open_ports, key=lambda x: x["port"])
                },
                "raw_output": results_text
            }
            
            with open(filename, "w") as f:
                json.dump(scan_data, f, indent=2)
            
            QtWidgets.QMessageBox.information(self, "Success", f"Exported to {filename}")


class ScanThread(QtCore.QThread):
    """Background scanning thread."""
    
    progress = QtCore.Signal(int)
    result = QtCore.Signal(str)
    status = QtCore.Signal(str)
    finished_signal = QtCore.Signal()

    # Common port services
    SERVICES = {
        20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
        445: "SMB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
        5900: "VNC", 8080: "HTTP-Proxy", 27017: "MongoDB"
    }

    def __init__(self, target, port_start, port_end, threads, 
                 service_detect, banner_grab, os_detect):
        super().__init__()
        self.target = target
        self.port_start = port_start
        self.port_end = port_end
        self.max_threads = threads
        self.service_detect = service_detect
        self.banner_grab = banner_grab
        self.os_detect = os_detect
        self._stop = False
        self.open_ports = []

    def stop(self):
        self._stop = True

    def run(self):
        """Execute the scan."""
        try:
            # Resolve target
            self.status.emit(f"Resolving {self.target}...")
            try:
                target_ip = socket.gethostbyname(self.target)
                self.result.emit("═" * 45)
                self.result.emit(" PORT SCAN REPORT")
                self.result.emit("═" * 45)
                self.result.emit(f"Target: {self.target}")
                if target_ip != self.target:
                    self.result.emit(f"IP: {target_ip}")
                self.result.emit(f"Ports: {self.port_start}-{self.port_end}")
                self.result.emit("═" * 45 + "\n")
            except socket.gaierror:
                self.result.emit(f"Error: Cannot resolve {self.target}")
                self.finished_signal.emit()
                return

            total = self.port_end - self.port_start + 1
            scanned = 0

            self.status.emit(f"Scanning {total} ports...")

            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = {
                    executor.submit(self._scan_port, target_ip, port): port
                    for port in range(self.port_start, self.port_end + 1)
                }

                for future in as_completed(futures):
                    if self._stop:
                        executor.shutdown(wait=False)
                        self.result.emit("\n⚠ Scan stopped")
                        break

                    port = futures[future]
                    try:
                        is_open, service = future.result()
                        if is_open:
                            self.open_ports.append(port)
                            msg = f"✓ Port {port:5d} [OPEN]"
                            if service:
                                msg += f" - {service}"
                            self.result.emit(msg)
                    except:
                        pass

                    scanned += 1
                    self.progress.emit(int((scanned / total) * 100))
                    self.status.emit(f"{scanned}/{total} ({len(self.open_ports)} open)")

            # Summary
            self.result.emit(f"\n{'═' * 45}")
            self.result.emit(f"Found {len(self.open_ports)} open port(s)")
            self.result.emit("═" * 45)

            # OS detection
            if self.os_detect and self.open_ports:
                self._detect_os(target_ip)

        except Exception as e:
            self.result.emit(f"\n⚠ Error: {str(e)}")
        finally:
            self.finished_signal.emit()

    def _scan_port(self, ip, port) -> Tuple[bool, str]:
        """Scan a single port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))

            if result == 0:
                service = ""
                if self.service_detect:
                    service = self.SERVICES.get(port, "Unknown")
                
                if self.banner_grab:
                    try:
                        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                        if banner:
                            service += f" | {banner.split(chr(10))[0][:40]}"
                    except:
                        pass
                
                sock.close()
                return True, service
            
            sock.close()
            return False, ""
        except:
            return False, ""

    def _detect_os(self, ip):
        """Basic OS detection via TTL."""
        self.result.emit(f"\n🔍 OS Detection:")
        try:
            cmd = ["ping", "-n" if platform.system() == "Windows" else "-c", "1", ip]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            output = result.stdout.lower()
            
            if "ttl=" in output:
                ttl = int(output.split("ttl=")[1].split()[0])
                if ttl <= 64:
                    os_type = f"Linux/Unix (TTL={ttl})"
                elif ttl <= 128:
                    os_type = f"Windows (TTL={ttl})"
                else:
                    os_type = f"Network Device (TTL={ttl})"
                self.result.emit(f"   Likely: {os_type}")
            else:
                self.result.emit("   Could not determine")
        except:
            self.result.emit("   Detection failed")
