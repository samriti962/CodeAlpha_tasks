import os
os.environ["SCAPY_CACHE"] = "0"   # IMPORTANT: Fixes PermissionError on Windows
from scapy.all import sniff, IP, TCP
from datetime import datetime
from collections import defaultdict
# ------------------------------
# CONFIGURATION
# ------------------------------
PORT_SCAN_THRESHOLD = 10   # number of ports
TIME_WINDOW = 10           # seconds
LOG_FILE = "alerts.log"
ip_activity = defaultdict(list)
# ------------------------------
# ALERT & LOGGING
# ------------------------------
def log_alert(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as file:
        file.write(f"{timestamp} - {message}\n")
    print(f"[ALERT] {message}")
# ------------------------------
# DETECTION RULES
# ------------------------------
def detect_port_scan(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        current_time = datetime.now().timestamp()
        ip_activity[src_ip].append((dst_port, current_time))
        # Keep only recent packets
        ip_activity[src_ip] = [
            (p, t) for p, t in ip_activity[src_ip]
            if current_time - t <= TIME_WINDOW
        ]
        ports = set(p for p, t in ip_activity[src_ip])
        if len(ports) >= PORT_SCAN_THRESHOLD:
            log_alert(f"Port Scan detected from {src_ip}")
            ip_activity[src_ip].clear()
def detect_syn_flood(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        if packet[TCP].flags == "S":
            log_alert(f"SYN Flood attempt from {packet[IP].src}")
# ------------------------------
# PACKET HANDLER
# ------------------------------
def packet_handler(packet):
    detect_port_scan(packet)
    detect_syn_flood(packet)
# ------------------------------
# START IDS
# ------------------------------
print("🚨 Network Intrusion Detection System Started...")
print("📡 Monitoring network traffic...\n")
sniff(prn=packet_handler, store=False)
