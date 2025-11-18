#!/usr/bin/env python3
"""
Stylish Packet Sniffer GUI for Kali Linux (educational use only).
Modern UI with grouped controls, color-coded rows, and clean layout.
Requires root privileges to capture live traffic.
"""
import sys
import threading
import time
from scapy.all import sniff, IP, IPv6, Raw, wrpcap
from scapy.packet import Packet
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QColor, QFont, QBrush
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLineEdit, QLabel, QTableWidget, QTableWidgetItem, QTextEdit,
    QFileDialog, QMessageBox, QHeaderView, QAbstractItemView, QSizePolicy,
    QGroupBox
)

class SniffThread(QThread):
    packet_signal = pyqtSignal(object)

    def __init__(self, bpf_filter="", iface=None):
        super().__init__()
        self._stop_event = threading.Event()
        self.bpf_filter = bpf_filter
        self.iface = iface

    def run(self):
        try:
            sniff(
                filter=self.bpf_filter or None,
                prn=lambda p: self._on_packet(p),
                store=False,
                iface=self.iface,
                stop_filter=lambda pkt: self._stop_event.is_set()
            )
        except Exception as e:
            print("Sniffer thread exception:", e)
            self.packet_signal.emit(("__error__", str(e)))

    def _on_packet(self, packet):
        if self._stop_event.is_set():
            return True
        self.packet_signal.emit(packet)

    def stop(self):
        self._stop_event.set()

class PacketSnifferGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Stylish Packet Sniffer (Educational)")
        self.resize(950, 620)
        self.packets = []
        self._counter = 0

        # Filters group box
        filter_group = QGroupBox("Capture Settings")
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("BPF Filter (e.g. tcp, udp port 80)")
        self.iface_input = QLineEdit()
        self.iface_input.setPlaceholderText("Interface (e.g. eth0, wlan0)")
        filters_layout = QHBoxLayout()
        filters_layout.addWidget(QLabel("Filter:"))
        filters_layout.addWidget(self.filter_input)
        filters_layout.addWidget(QLabel("Interface:"))
        filters_layout.addWidget(self.iface_input)
        filter_group.setLayout(filters_layout)

        # Controls group box
        controls_group = QGroupBox("Controls")
        self.start_btn = QPushButton("Start Capture")
        self.stop_btn = QPushButton("Stop Capture")
        self.stop_btn.setEnabled(False)
        self.clear_btn = QPushButton("Clear Packets")
        self.save_btn = QPushButton("Save Capture")
        self.refresh_btn = QPushButton("Refresh View")
        self.apply_filter_btn = QPushButton("Apply Filter")
        controls_layout = QHBoxLayout()
        controls_layout.addWidget(self.start_btn)
        controls_layout.addWidget(self.stop_btn)
        controls_layout.addWidget(self.clear_btn)
        controls_layout.addWidget(self.save_btn)
        controls_layout.addWidget(self.refresh_btn)
        controls_layout.addWidget(self.apply_filter_btn)
        controls_group.setLayout(controls_layout)

        # Packet table
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["#", "Time", "Source", "Destination", "Proto", "Length"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        # Payload viewer with title
        payload_group = QGroupBox("Packet Payload (Hex + ASCII)")
        self.payload_view = QTextEdit()
        self.payload_view.setReadOnly(True)
        payload_layout = QVBoxLayout()
        payload_layout.addWidget(self.payload_view)
        payload_group.setLayout(payload_layout)

        # Layout for table and payload side by side
        mid_layout = QHBoxLayout()
        mid_layout.addWidget(self.table, 3)
        mid_layout.addWidget(payload_group, 2)

        # Status bar
        self.status = QLabel("Ready. Run as root for capture functionality.")
        self.status.setStyleSheet("color: #666666; font-style: italic; padding: 4px;")

        # Main layout
        main_layout = QVBoxLayout()
        main_layout.addWidget(filter_group)
        main_layout.addWidget(controls_group)
        main_layout.addLayout(mid_layout)
        main_layout.addWidget(self.status)

        self.setLayout(main_layout)

        # Connect signals
        self.start_btn.clicked.connect(self.start_capture)
        self.stop_btn.clicked.connect(self.stop_capture)
        self.clear_btn.clicked.connect(self.clear_all)
        self.save_btn.clicked.connect(self.save_pcap)
        self.refresh_btn.clicked.connect(self.refresh_table)
        self.apply_filter_btn.clicked.connect(self.apply_filter)
        self.table.itemSelectionChanged.connect(self.on_row_selected)

        self.sniff_thread = None

    def summarize_packet(self, pkt):
        proto = "?"
        src = "-"
        dst = "-"
        length = len(pkt)
        info = ""
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            proto = pkt[IP].proto
            info = pkt.summary()
            try:
                from scapy.layers.inet import TCP, UDP, ICMP
                if TCP in pkt:
                    proto = "TCP"
                elif UDP in pkt:
                    proto = "UDP"
                elif ICMP in pkt:
                    proto = "ICMP"
                else:
                    proto = str(pkt[IP].proto)
            except Exception:
                pass
        elif IPv6 in pkt:
            src = pkt[IPv6].src
            dst = pkt[IPv6].dst
            info = pkt.summary()
            proto = "IPv6"
        else:
            try:
                info = pkt.summary()
                if pkt.haslayer("ARP"):
                    proto = "ARP"
                    src = pkt.sprintf("%ARP.psrc%")
                    dst = pkt.sprintf("%ARP.pdst%")
                else:
                    proto = pkt.name
            except Exception:
                info = str(pkt)
        return src, dst, proto, length, info

    def ascii_preview(self, raw_bytes, max_len=256):
        preview = []
        for b in raw_bytes[:max_len]:
            if 32 <= b <= 126:
                preview.append(chr(b))
            else:
                preview.append(".")
        return "".join(preview)

    def start_capture(self):
        if self.sniff_thread and self.sniff_thread.isRunning():
            QMessageBox.warning(self, "Already running", "Sniffer is already running.")
            return
        bpf = self.filter_input.text().strip()
        iface = self.iface_input.text().strip() or None
        try:
            self.sniff_thread = SniffThread(bpf_filter=bpf, iface=iface)
            self.sniff_thread.packet_signal.connect(self.handle_packet_or_error)
            self.sniff_thread.start()
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            self.status.setText(f"Capturing... Filter='{bpf}' Interface='{iface or 'default'}'")
        except Exception as e:
            QMessageBox.critical(self, "Capture Start Error", f"Failed to start capture:\n{e}")
            self.status.setText("Error starting capture")

    def stop_capture(self):
        if not self.sniff_thread:
            return
        self.sniff_thread.stop()
        self.sniff_thread.wait(2000)  # Fixed - use positional argument
        self.sniff_thread = None
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status.setText("Capture stopped.")

    def clear_all(self):
        self.packets.clear()
        self._counter = 0
        self.table.clearContents()
        self.table.setRowCount(0)
        self.payload_view.clear()
        self.status.setText("Captured packets cleared.")

    def save_pcap(self):
        if not self.packets:
            QMessageBox.information(self, "No packets", "No packets to save.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save Capture", "capture.pcap", "PCAP Files (*.pcap)")
        if path:
            try:
                valid_packets = [p for p in self.packets if isinstance(p, Packet)]
                if not valid_packets:
                    QMessageBox.warning(self, "No valid packets", "No valid packets available to save.")
                    return
                wrpcap(path, valid_packets)
                QMessageBox.information(self, "Saved", f"Saved {len(valid_packets)} packets to {path}")
            except Exception as e:
                QMessageBox.critical(self, "Save Error", f"Failed to save PCAP:\n{e}")

    def handle_packet_or_error(self, pkt):
        if isinstance(pkt, tuple) and pkt and pkt[0] == "__error__":
            self.status.setText("Error: " + str(pkt[1]))
            QMessageBox.critical(self, "Capture Error", str(pkt[1]))
            self.stop_capture()
            return
        if not isinstance(pkt, Packet):
            return
        self.packets.append(pkt)
        self._counter += 1
        row = self.table.rowCount()
        self.table.insertRow(row)

        ts = time.strftime("%H:%M:%S", time.localtime(time.time()))
        src, dst, proto, length, info = self.summarize_packet(pkt)

        color = None
        if proto == "TCP":
            color = QBrush(QColor(200, 230, 255))
        elif proto == "UDP":
            color = QBrush(QColor(220, 255, 220))
        elif proto == "ARP":
            color = QBrush(QColor(255, 230, 230))

        for col, desc in enumerate([str(self._counter), ts, src, dst, str(proto), str(length)]):
            item = QTableWidgetItem(desc)
            if color:
                item.setBackground(color)
            if col == 4:
                font = QFont()
                font.setBold(True)
                item.setFont(font)
            self.table.setItem(row, col, item)
            item.setToolTip(info)

        self.table.scrollToBottom()
        self.status.setText(f"Captured: {self._counter} packets")

    def on_row_selected(self):
        sel = self.table.currentRow()
        if sel < 0 or sel >= len(self.packets):
            return
        pkt = self.packets[sel]
        payload_bytes = b""
        if Raw in pkt:
            try:
                payload_bytes = bytes(pkt[Raw].load)
            except Exception:
                payload_bytes = b""
        else:
            try:
                payload_bytes = bytes(pkt.payload)
            except Exception:
                payload_bytes = b""

        max_show = 1024
        hb = payload_bytes[:max_show]
        hexstr = " ".join(f"{b:02x}" for b in hb)
        asc = self.ascii_preview(hb, max_len=256)
        more = "" if len(payload_bytes) <= max_show else f"\n\n... (payload truncated, total {len(payload_bytes)} bytes)"
        text = f"Hex (first {min(len(payload_bytes), max_show)} bytes):\n{hexstr}\n\nASCII preview:\n{asc}{more}"
        if not payload_bytes:
            text = "(No payload captured or payload not in Raw layer)\n\nPacket summary:\n" + pkt.summary()
        self.payload_view.setPlainText(text)

    def refresh_table(self):
        self.table.setRowCount(0)
        for idx, pkt in enumerate(self.packets):
            ts = time.strftime("%H:%M:%S", time.localtime(time.time()))
            src, dst, proto, length, info = self.summarize_packet(pkt)

            color = None
            if proto == "TCP":
                color = QBrush(QColor(200, 230, 255))
            elif proto == "UDP":
                color = QBrush(QColor(220, 255, 220))
            elif proto == "ARP":
                color = QBrush(QColor(255, 230, 230))

            self.table.insertRow(idx)
            for col, desc in enumerate([str(idx + 1), ts, src, dst, str(proto), str(length)]):
                item = QTableWidgetItem(desc)
                if color:
                    item.setBackground(color)
                if col == 4:
                    font = QFont()
                    font.setBold(True)
                    item.setFont(font)
                self.table.setItem(idx, col, item)
                item.setToolTip(info)
        self.status.setText(f"Refreshed: {len(self.packets)} packets")

    def apply_filter(self):
        self.stop_capture()
        self.clear_all()
        self.start_capture()

    def closeEvent(self, event):
        if self.sniff_thread and self.sniff_thread.isRunning():
            self.sniff_thread.stop()
            self.sniff_thread.wait(2000)
        event.accept()

def main():
    app = QApplication(sys.argv)
    gui = PacketSnifferGUI()
    gui.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
