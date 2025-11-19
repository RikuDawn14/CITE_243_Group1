import sys
import socket
import threading
import subprocess
import platform
from typing import Optional, List, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

from PySide6 import QtWidgets, QtCore, QtGui


class PortScannerApp(QtWidgets.QMainWindow):
    """Main application window for standalone port scanner."""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle(" Port Scanner")
        self.resize(1000, 800)
        
        # Apply steampunk theme
        self.setStyleSheet(STEAMPUNK_STYLESHEET)
        
        # Create central widget
        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        
        # Create and set layout
        layout = QtWidgets.QVBoxLayout(central)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Add header
        header = self._create_header()
        layout.addWidget(header)
        
        # Add scanner widget
        self.scanner = PortScannerWidget()
        layout.addWidget(self.scanner)
    
    def _create_header(self):
        """Create application header."""
        header = QtWidgets.QFrame()
        header.setObjectName("HeaderBar")
        header_layout = QtWidgets.QHBoxLayout(header)
        header_layout.setContentsMargins(15, 10, 15, 10)
        
        title = QtWidgets.QLabel(" PORT SCANNER ")
        title.setStyleSheet("""
            font-size: 22px;
            font-weight: bold;
            color: #b08d57;
            padding: 5px;
        """)
        header_layout.addWidget(title)
        
        header_layout.addStretch()
        
        subtitle = QtWidgets.QLabel(" Network Analysis Tool")
        subtitle.setStyleSheet("color: #b87333; font-size: 12px;")
        header_layout.addWidget(subtitle)
        
        return header


class PortScannerWidget(QtWidgets.QWidget):
    """Port scanner widget with full functionality."""
    
    def __init__(self, parent: Optional[QtWidgets.QWidget] = None):
        super().__init__(parent)
        self.scanning = False
        self.scan_thread = None
        self._build_ui()
        self._detect_network()
        
    def _build_ui(self):
        """Build the port scanner interface."""
        layout = QtWidgets.QVBoxLayout(self)
        layout.setSpacing(12)
        
        # Network Detection Section
        network_group = QtWidgets.QGroupBox("Network Detection")
        network_layout = QtWidgets.QVBoxLayout()
        
        self.network_info_label = QtWidgets.QLabel("Detecting network...")
        self.network_info_label.setStyleSheet("color: #b87333; padding: 5px;")
        network_layout.addWidget(self.network_info_label)
        
        # Quick scan buttons
        quick_scan_layout = QtWidgets.QHBoxLayout()
        
        self.scan_local_btn = QtWidgets.QPushButton(" Scan This Computer")
        self.scan_local_btn.setToolTip("Scan ports on 127.0.0.1 (localhost)")
        self.scan_local_btn.clicked.connect(self._scan_localhost)
        quick_scan_layout.addWidget(self.scan_local_btn)
        
        self.scan_router_btn = QtWidgets.QPushButton(" Scan Router")
        self.scan_router_btn.setToolTip("Scan ports on your default gateway/router")
        self.scan_router_btn.clicked.connect(self._scan_router)
        quick_scan_layout.addWidget(self.scan_router_btn)
        
        network_layout.addLayout(quick_scan_layout)
        network_group.setLayout(network_layout)
        layout.addWidget(network_group)
        
        # Target Configuration Section
        target_group = QtWidgets.QGroupBox("Target Configuration")
        target_layout = QtWidgets.QFormLayout()
        target_layout.setSpacing(8)
        
        # IP Address input
        self.ip_input = QtWidgets.QLineEdit()
        self.ip_input.setPlaceholderText("e.g., 192.168.1.1 or scanme.nmap.org")
        self.ip_input.setText("127.0.0.1")
        target_layout.addRow("Target IP/Host:", self.ip_input)
        
        # Port range input
        port_range_layout = QtWidgets.QHBoxLayout()
        self.port_start_input = QtWidgets.QSpinBox()
        self.port_start_input.setRange(1, 65535)
        self.port_start_input.setValue(1)
        self.port_start_input.setMinimumWidth(100)
        
        port_range_layout.addWidget(QtWidgets.QLabel("From:"))
        port_range_layout.addWidget(self.port_start_input)
        port_range_layout.addWidget(QtWidgets.QLabel("To:"))
        
        self.port_end_input = QtWidgets.QSpinBox()
        self.port_end_input.setRange(1, 65535)
        self.port_end_input.setValue(1024)
        self.port_end_input.setMinimumWidth(100)
        port_range_layout.addWidget(self.port_end_input)
        port_range_layout.addStretch()
        
        target_layout.addRow("Port Range:", port_range_layout)
        
        # Scan presets
        preset_layout = QtWidgets.QHBoxLayout()
        
        common_btn = QtWidgets.QPushButton("Common Ports")
        common_btn.setToolTip("Scan most common 100 ports")
        common_btn.clicked.connect(lambda: self._set_port_range(1, 1024))
        preset_layout.addWidget(common_btn)
        
        well_known_btn = QtWidgets.QPushButton("Well-Known")
        well_known_btn.setToolTip("Scan well-known ports (1-1024)")
        well_known_btn.clicked.connect(lambda: self._set_port_range(1, 1024))
        preset_layout.addWidget(well_known_btn)
        
        registered_btn = QtWidgets.QPushButton("Registered")
        registered_btn.setToolTip("Scan registered ports (1024-49151)")
        registered_btn.clicked.connect(lambda: self._set_port_range(1024, 49151))
        preset_layout.addWidget(registered_btn)
        
        all_btn = QtWidgets.QPushButton("All Ports")
        all_btn.setToolTip("Scan all ports (1-65535) - WARNING: This takes a long time!")
        all_btn.clicked.connect(lambda: self._set_port_range(1, 65535))
        preset_layout.addWidget(all_btn)
        
        preset_layout.addStretch()
        target_layout.addRow("Presets:", preset_layout)
        
        target_group.setLayout(target_layout)
        layout.addWidget(target_group)
        
        # Scan Options Section
        options_group = QtWidgets.QGroupBox("Scan Options")
        options_layout = QtWidgets.QHBoxLayout()
        
        self.service_detection_check = QtWidgets.QCheckBox("Service Detection")
        self.service_detection_check.setChecked(True)
        self.service_detection_check.setToolTip("Attempt to identify services running on open ports")
        options_layout.addWidget(self.service_detection_check)
        
        self.banner_grab_check = QtWidgets.QCheckBox("Banner Grabbing")
        self.banner_grab_check.setChecked(True)
        self.banner_grab_check.setToolTip("Retrieve service banners for identification")
        options_layout.addWidget(self.banner_grab_check)
        
        self.os_detect_check = QtWidgets.QCheckBox("OS Fingerprinting")
        self.os_detect_check.setChecked(False)
        self.os_detect_check.setToolTip("Attempt basic OS detection")
        options_layout.addWidget(self.os_detect_check)
        
        options_layout.addStretch()
        
        # Thread count
        options_layout.addWidget(QtWidgets.QLabel("Threads:"))
        self.thread_count_spin = QtWidgets.QSpinBox()
        self.thread_count_spin.setRange(1, 100)
        self.thread_count_spin.setValue(50)
        self.thread_count_spin.setToolTip("Number of concurrent scanning threads")
        options_layout.addWidget(self.thread_count_spin)
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        # Control Buttons
        control_layout = QtWidgets.QHBoxLayout()
        
        self.scan_btn = QtWidgets.QPushButton("▶ Start Scan")
        self.scan_btn.setMinimumHeight(40)
        self.scan_btn.setStyleSheet("""
            QPushButton {
                background-color: #98002E;
                color: #b08d57;
                font-weight: bold;
                font-size: 14px;
                border: 2px solid #b08d57;
                border-radius: 5px;
                padding: 8px;
            }
            QPushButton:hover {
                background-color: #b8003e;
            }
            QPushButton:disabled {
                background-color: #4a4a4a;
                color: #7a7a7a;
            }
        """)
        self.scan_btn.clicked.connect(self._start_scan)
        control_layout.addWidget(self.scan_btn)
        
        self.stop_btn = QtWidgets.QPushButton(" Stop Scan")
        self.stop_btn.setMinimumHeight(40)
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet("""
            QPushButton {
                background-color: #4a0000;
                color: #b08d57;
                font-weight: bold;
                font-size: 14px;
                border: 2px solid #b08d57;
                border-radius: 5px;
                padding: 8px;
            }
            QPushButton:hover {
                background-color: #6a0000;
            }
            QPushButton:enabled {
                background-color: #8a0000;
            }
            QPushButton:enabled:hover {
                background-color: #aa0000;
            }
        """)
        self.stop_btn.clicked.connect(self._stop_scan)
        control_layout.addWidget(self.stop_btn)
        
        self.clear_btn = QtWidgets.QPushButton(" Clear Results")
        self.clear_btn.setMinimumHeight(40)
        self.clear_btn.clicked.connect(self._clear_results)
        control_layout.addWidget(self.clear_btn)
        
        layout.addLayout(control_layout)
        
        # Progress Section
        progress_layout = QtWidgets.QHBoxLayout()
        self.progress_bar = QtWidgets.QProgressBar()
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid #b08d57;
                border-radius: 5px;
                text-align: center;
                background-color: #1a0a0a;
                color: #b08d57;
            }
            QProgressBar::chunk {
                background-color: #98002E;
            }
        """)
        progress_layout.addWidget(self.progress_bar)
        
        self.status_label = QtWidgets.QLabel("Ready to scan")
        self.status_label.setStyleSheet("color: #b87333; font-weight: bold;")
        progress_layout.addWidget(self.status_label)
        
        layout.addLayout(progress_layout)
        
        # Results Section
        results_label = QtWidgets.QLabel("Scan Results:")
        results_label.setStyleSheet("color: #b08d57; font-weight: bold; font-size: 14px;")
        layout.addWidget(results_label)
        
        self.results_text = QtWidgets.QTextEdit()
        self.results_text.setReadOnly(True)
        self.results_text.setStyleSheet("""
            QTextEdit {
                background-color: #0a0a0a;
                color: #b87333;
                border: 2px solid #b08d57;
                border-radius: 5px;
                font-family: 'Courier New', monospace;
                font-size: 11px;
                padding: 8px;
            }
        """)
        layout.addWidget(self.results_text, 1)
        
        # Export buttons
        export_layout = QtWidgets.QHBoxLayout()
        export_layout.addStretch()
        
        export_txt_btn = QtWidgets.QPushButton(" Export as TXT")
        export_txt_btn.clicked.connect(self._export_txt)
        export_layout.addWidget(export_txt_btn)
        
        export_csv_btn = QtWidgets.QPushButton(" Export as CSV")
        export_csv_btn.clicked.connect(self._export_csv)
        export_layout.addWidget(export_csv_btn)
        
        layout.addLayout(export_layout)
    
    def _detect_network(self):
        """Detect local network information."""
        try:
            # Get local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            # Get router IP (gateway)
            router_ip = "Unknown"
            if platform.system() == "Windows":
                result = subprocess.run(["ipconfig"], capture_output=True, text=True)
                lines = result.stdout.split('\n')
                for line in lines:
                    if "Default Gateway" in line:
                        parts = line.split(':')
                        if len(parts) > 1:
                            router_ip = parts[1].strip()
                            if router_ip:
                                break
            else:  # Linux/Mac
                result = subprocess.run(["ip", "route"], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if "default" in line:
                        parts = line.split()
                        if len(parts) > 2:
                            router_ip = parts[2]
                            break
            
            self.router_ip = router_ip if router_ip != "Unknown" else None
            info_text = f"Local IP: {local_ip}"
            if self.router_ip:
                info_text += f" | Router: {self.router_ip}"
                self.scan_router_btn.setEnabled(True)
            else:
                info_text += " | Router: Not detected"
                self.scan_router_btn.setEnabled(False)
            
            self.network_info_label.setText(info_text)
            
        except Exception as e:
            self.network_info_label.setText(f"Network detection failed: {str(e)}")
            self.router_ip = None
            self.scan_router_btn.setEnabled(False)
    
    def _set_port_range(self, start: int, end: int):
        """Set the port range spinboxes."""
        self.port_start_input.setValue(start)
        self.port_end_input.setValue(end)
    
    def _scan_localhost(self):
        """Quick scan of localhost."""
        self.ip_input.setText("127.0.0.1")
        self._set_port_range(1, 1024)
        self._start_scan()
    
    def _scan_router(self):
        """Quick scan of router."""
        if self.router_ip:
            self.ip_input.setText(self.router_ip)
            self._set_port_range(1, 1024)
            self._start_scan()
    
    def _start_scan(self):
        """Start the port scan."""
        if self.scanning:
            return
        
        target = self.ip_input.text().strip()
        if not target:
            QtWidgets.QMessageBox.warning(self, "Error", "Please enter a target IP or hostname.")
            return
        
        port_start = self.port_start_input.value()
        port_end = self.port_end_input.value()
        
        if port_start > port_end:
            QtWidgets.QMessageBox.warning(self, "Error", "Start port must be less than or equal to end port.")
            return
        
        self.scanning = True
        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setValue(0)
        self.results_text.clear()
        
        # Start scan in separate thread
        self.scan_thread = ScanThread(
            target=target,
            port_start=port_start,
            port_end=port_end,
            threads=self.thread_count_spin.value(),
            service_detection=self.service_detection_check.isChecked(),
            banner_grab=self.banner_grab_check.isChecked(),
            os_detect=self.os_detect_check.isChecked()
        )
        self.scan_thread.progress.connect(self._update_progress)
        self.scan_thread.result.connect(self._add_result)
        self.scan_thread.status.connect(self._update_status)
        self.scan_thread.finished_signal.connect(self._scan_finished)
        self.scan_thread.start()
    
    def _stop_scan(self):
        """Stop the current scan."""
        if self.scan_thread:
            self.scan_thread.stop()
            self.status_label.setText("Stopping scan...")
    
    def _scan_finished(self):
        """Handle scan completion."""
        self.scanning = False
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setValue(100)
        self.status_label.setText("Scan complete!")
    
    def _update_progress(self, value: int):
        """Update progress bar."""
        self.progress_bar.setValue(value)
    
    def _update_status(self, message: str):
        """Update status label."""
        self.status_label.setText(message)
    
    def _add_result(self, message: str):
        """Add result to text area."""
        self.results_text.append(message)
    
    def _clear_results(self):
        """Clear all results."""
        self.results_text.clear()
        self.progress_bar.setValue(0)
        self.status_label.setText("Ready to scan")
    
    def _export_txt(self):
        """Export results as text file."""
        filename, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "Export Results", "", "Text Files (*.txt);;All Files (*)"
        )
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(self.results_text.toPlainText())
                QtWidgets.QMessageBox.information(self, "Success", f"Results exported to {filename}")
            except Exception as e:
                QtWidgets.QMessageBox.critical(self, "Error", f"Failed to export: {str(e)}")
    
    def _export_csv(self):
        """Export results as CSV file."""
        filename, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "Export Results", "", "CSV Files (*.csv);;All Files (*)"
        )
        if filename:
            try:
                import csv
                with open(filename, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Port', 'Status', 'Service', 'Details'])
                    
                    # Parse results text
                    for line in self.results_text.toPlainText().split('\n'):
                        if 'OPEN' in line or 'CLOSED' in line or 'FILTERED' in line:
                            writer.writerow([line])
                
                QtWidgets.QMessageBox.information(self, "Success", f"Results exported to {filename}")
            except Exception as e:
                QtWidgets.QMessageBox.critical(self, "Error", f"Failed to export: {str(e)}")


class ScanThread(QtCore.QThread):
    """Background thread for port scanning."""
    
    progress = QtCore.Signal(int)
    result = QtCore.Signal(str)
    status = QtCore.Signal(str)
    finished_signal = QtCore.Signal()
    
    def __init__(self, target: str, port_start: int, port_end: int, threads: int,
                 service_detection: bool, banner_grab: bool, os_detect: bool):
        super().__init__()
        self.target = target
        self.port_start = port_start
        self.port_end = port_end
        self.max_threads = threads
        self.service_detection = service_detection
        self.banner_grab = banner_grab
        self.os_detect = os_detect
        self._stop_flag = False
        self.open_ports = []
        
        # Common services dictionary
        self.common_services = {
            20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet",
            25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
            69: "TFTP", 80: "HTTP", 110: "POP3", 119: "NNTP",
            123: "NTP", 135: "MS-RPC", 139: "NetBIOS", 143: "IMAP",
            161: "SNMP", 162: "SNMP-Trap", 389: "LDAP", 443: "HTTPS",
            445: "SMB", 465: "SMTPS", 514: "Syslog", 587: "SMTP",
            631: "IPP", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
            1433: "MS-SQL", 1521: "Oracle", 1723: "PPTP", 3306: "MySQL",
            3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
            8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 27017: "MongoDB"
        }
    
    def stop(self):
        """Set stop flag to halt scanning."""
        self._stop_flag = True
    
    def run(self):
        """Execute the port scan."""
        try:
            # Resolve hostname to IP
            self.status.emit(f"Resolving {self.target}...")
            try:
                target_ip = socket.gethostbyname(self.target)
                self.result.emit(f"═══════════════════════════════════════════")
                self.result.emit(f" PORT SCAN REPORT ")
                self.result.emit(f"═══════════════════════════════════════════")
                self.result.emit(f"Target: {self.target}")
                if target_ip != self.target:
                    self.result.emit(f"IP Address: {target_ip}")
                self.result.emit(f"Port Range: {self.port_start}-{self.port_end}")
                self.result.emit(f"═══════════════════════════════════════════\n")
            except socket.gaierror:
                self.result.emit(f" Error: Could not resolve hostname: {self.target}")
                self.finished_signal.emit()
                return
            
            total_ports = self.port_end - self.port_start + 1
            scanned = 0
            
            # Scan ports with threading
            self.status.emit(f"Scanning {total_ports} ports...")
            
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = {
                    executor.submit(self._scan_port, target_ip, port): port
                    for port in range(self.port_start, self.port_end + 1)
                }
                
                for future in as_completed(futures):
                    if self._stop_flag:
                        executor.shutdown(wait=False)
                        self.result.emit("\n⚠ Scan stopped by user")
                        break
                    
                    port = futures[future]
                    try:
                        is_open, service_info = future.result()
                        if is_open:
                            self.open_ports.append(port)
                            msg = f"✓ Port {port:5d} [OPEN]"
                            if service_info:
                                msg += f" - {service_info}"
                            self.result.emit(msg)
                    except Exception:
                        pass  # Silently ignore errors
                    
                    scanned += 1
                    progress_pct = int((scanned / total_ports) * 100)
                    self.progress.emit(progress_pct)
                    self.status.emit(f"Scanned {scanned}/{total_ports} ports ({len(self.open_ports)} open)")
            
            # Summary
            self.result.emit(f"\n═══════════════════════════════════════════")
            self.result.emit(f"Scan complete: {len(self.open_ports)} open port(s) found")
            self.result.emit(f"═══════════════════════════════════════════")
            
            # OS Detection if enabled
            if self.os_detect and self.open_ports:
                self._detect_os(target_ip)
            
        except Exception as e:
            self.result.emit(f"\n Scan error: {str(e)}")
        
        finally:
            self.finished_signal.emit()
    
    def _scan_port(self, ip: str, port: int) -> Tuple[bool, str]:
        """Scan a single port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            
            service_info = ""
            if result == 0:
                # Port is open
                if self.service_detection:
                    service_info = self.common_services.get(port, "Unknown")
                
                if self.banner_grab:
                    try:
                        sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                        if banner:
                            banner_short = banner.split('\n')[0][:50]
                            service_info += f" | {banner_short}"
                    except:
                        pass
                
                sock.close()
                return True, service_info
            
            sock.close()
            return False, ""
            
        except:
            return False, ""
    
    def _detect_os(self, ip: str):
        """Attempt basic OS detection."""
        self.result.emit(f"\n🔍 OS Detection:")
        try:
            if platform.system() == "Windows":
                result = subprocess.run(["ping", "-n", "1", ip], 
                                       capture_output=True, text=True, timeout=5)
            else:
                result = subprocess.run(["ping", "-c", "1", ip],
                                       capture_output=True, text=True, timeout=5)
            
            output = result.stdout
            if "TTL=" in output or "ttl=" in output:
                ttl_str = output.lower().split("ttl=")[1].split()[0]
                try:
                    ttl = int(ttl_str)
                    if ttl <= 64:
                        self.result.emit(f"   Likely OS: Linux/Unix (TTL={ttl})")
                    elif ttl <= 128:
                        self.result.emit(f"   Likely OS: Windows (TTL={ttl})")
                    else:
                        self.result.emit(f"   Likely OS: Cisco/Network Device (TTL={ttl})")
                except:
                    self.result.emit(f"   Could not determine OS")
            else:
                self.result.emit(f"   Could not determine OS")
                
        except Exception as e:
            self.result.emit(f"   OS detection failed: {str(e)}")


# Steampunk Theme Stylesheet
STEAMPUNK_STYLESHEET = """
/* Global Styles */
* {
    font-family: 'Segoe UI', Arial, sans-serif;
}

QMainWindow, QWidget {
    background-color: #1a1a1a;
    color: #d4d4d4;
}

/* Header Bar */
QFrame#HeaderBar {
    background: qlineargradient(
        x1:0, y1:0, x2:0, y2:1,
        stop:0 #2a1a1a,
        stop:1 #1a0a0a
    );
    border-bottom: 3px solid #b08d57;
    border-radius: 5px;
}

/* Group Boxes */
QGroupBox {
    border: 2px solid #b08d57;
    border-radius: 5px;
    margin-top: 12px;
    padding-top: 12px;
    font-weight: bold;
    color: #b08d57;
    background-color: #1a1a1a;
}

QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 10px;
    padding: 0 5px;
    background-color: #1a1a1a;
}

/* Buttons */
QPushButton {
    background-color: #2a1a1a;
    color: #b08d57;
    border: 2px solid #b08d57;
    border-radius: 5px;
    padding: 6px 12px;
    font-weight: bold;
    min-width: 80px;
}

QPushButton:hover {
    background-color: #3a2a2a;
    border-color: #c09d67;
}

QPushButton:pressed {
    background-color: #98002E;
    border-color: #b08d57;
}

QPushButton:disabled {
    background-color: #1a1a1a;
    color: #6a6a6a;
    border-color: #4a4a4a;
}

/* Input Fields */
QLineEdit, QSpinBox {
    background-color: #0a0a0a;
    color: #b87333;
    border: 2px solid #b08d57;
    border-radius: 4px;
    padding: 5px;
    selection-background-color: #98002E;
}

QLineEdit:focus, QSpinBox:focus {
    border-color: #c09d67;
}

QSpinBox::up-button, QSpinBox::down-button {
    background-color: #2a1a1a;
    border-left: 1px solid #b08d57;
}

QSpinBox::up-button:hover, QSpinBox::down-button:hover {
    background-color: #3a2a2a;
}

/* Checkboxes */
QCheckBox {
    color: #b87333;
    spacing: 8px;
}

QCheckBox::indicator {
    width: 18px;
    height: 18px;
    border: 2px solid #b08d57;
    border-radius: 3px;
    background-color: #0a0a0a;
}

QCheckBox::indicator:checked {
    background-color: #98002E;
}

/* Progress Bar */
QProgressBar {
    border: 2px solid #b08d57;
    border-radius: 5px;
    text-align: center;
    background-color: #0a0a0a;
    color: #b08d57;
    font-weight: bold;
}

QProgressBar::chunk {
    background-color: #98002E;
    border-radius: 3px;
}

/* Text Edit */
QTextEdit {
    background-color: #0a0a0a;
    color: #b87333;
    border: 2px solid #b08d57;
    border-radius: 5px;
    selection-background-color: #98002E;
    padding: 5px;
}

/* Scroll Bars */
QScrollBar:vertical {
    background-color: #1a1a1a;
    width: 14px;
    border: 1px solid #b08d57;
    border-radius: 7px;
}

QScrollBar::handle:vertical {
    background-color: #98002E;
    border-radius: 6px;
    min-height: 20px;
}

QScrollBar::handle:vertical:hover {
    background-color: #b8003e;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}

QScrollBar:horizontal {
    background-color: #1a1a1a;
    height: 14px;
    border: 1px solid #b08d57;
    border-radius: 7px;
}

QScrollBar::handle:horizontal {
    background-color: #98002E;
    border-radius: 6px;
    min-width: 20px;
}
"""


def main():
    """Main entry point for standalone application."""
    app = QtWidgets.QApplication(sys.argv)
    
    # Set application info
    app.setApplicationName("Steampunk Port Scanner")
    app.setOrganizationName("North Idaho College")
    app.setOrganizationDomain("nic.edu")
    
    # Create and show main window
    window = PortScannerApp()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()