"""
config.py
Configuration constants for the Unified Automotive Attacker.
"""
import os
import sys

# Try to import doip_utils for MAC address resolution, similar to original script
try:
    from doip_utils import get_if_hwaddr
except ImportError:
    # Fallback if doip_utils isn't present during static analysis
    def get_if_hwaddr(iface): return "00:00:00:00:00:00"

# --- Interface ---
INTERFACE = "vatk"
try:
    ATTACKER_MAC = get_if_hwaddr(INTERFACE)
except Exception:
    ATTACKER_MAC = "00:00:00:00:00:00"

# --- SOME/IP Config (IPv4) ---
ATTACKER_IP4 = "192.168.42.30"
SD_MULTICAST_GROUP = "224.224.224.245"
SD_PORT = 30490
PROBE_DURATION = 3.0

# --- DoIP Config (IPv6) ---
MY_IP6 = 'fd00::30'
DOIP_PORT = 13400
BROADCAST_IP6 = 'ff02::1'  # IPv6 All Nodes Multicast
AUTO_KEEPALIVE_SERVICE = b'\x3E\x80'
KEEPALIVE_INTERVAL = 4.0

# --- Files ---
PCAP_FILE = "doip_capture.pcap"
