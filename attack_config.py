"""
attack_config.py
Unified configuration and utilities for the Automotive Attacker.
"""
import os
import sys
import asyncio
from scapy.all import get_if_hwaddr

# --- Utilities ---

class Colors:
    G = '\033[92m'
    Y = '\033[93m'
    R = '\033[91m'
    C = '\033[96m'
    M = '\033[95m'
    W = '\033[0m'
    BOLD = '\033[1m'

async def ainput(prompt: str = "") -> str:
    """Async wrapper for stdin input."""
    print(prompt, end="", flush=True)
    return await asyncio.to_thread(sys.stdin.readline)


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
