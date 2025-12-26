```python
"""
attack_config.py
Unified configuration and utilities for the Automotive Attacker.

This file is intended to be the single place to adjust:
- Network interface selection (used by Scapy)
- Attacker IPv4/IPv6 addresses
- SOME/IP Service Discovery parameters
- DoIP parameters (ports, multicast, keep-alive behavior)
- Output artifacts such as PCAP capture file name

Only constants should be edited in this file. Core attacker logic should import from here.
"""
import os
import sys
import asyncio
from scapy.all import get_if_hwaddr

# --- Utilities ---
# Purpose: shared helper utilities used by the attacker CLI and modules.

class Colors:
    # ANSI escape codes for colored terminal output.
    # If your terminal does not support ANSI colors, output may show raw sequences.
    G = '\033[92m'   # Green   (success/info)
    Y = '\033[93m'   # Yellow  (warnings)
    R = '\033[91m'   # Red     (errors)
    C = '\033[96m'   # Cyan    (headings)
    M = '\033[95m'   # Magenta (emphasis)
    W = '\033[0m'    # Reset to default color
    BOLD = '\033[1m' # Bold text


async def ainput(prompt: str = "") -> str:
    """
    Async wrapper for stdin input.

    Why needed:
    - Attacker components may run inside an asyncio event loop.
    - Standard input() blocks the loop and breaks concurrent tasks (sniffing, timers, etc.).
    - This wrapper prints the prompt and reads from stdin in a background thread.

    Returns:
    - The raw line from stdin (including trailing newline). Caller may want .strip().
    """
    print(prompt, end="", flush=True)
    return await asyncio.to_thread(sys.stdin.readline)


# --- Interface ---
# Purpose: tell Scapy which Linux interface to use for sending/sniffing.
# This must match the interface name created by your network setup script (net.sh / setup_network.sh).
# If the interface name is wrong, MAC lookup and packet I/O may fail.

INTERFACE = "vatk"

# ATTACKER_MAC is used by SOME/IP/ARP-based attacks and for building Ethernet frames.
# If get_if_hwaddr() fails (interface missing or not up), we fall back to a dummy MAC.
# Warning: dummy MAC will break attacks that require a correct source MAC.
try:
    ATTACKER_MAC = get_if_hwaddr(INTERFACE)
except Exception:
    ATTACKER_MAC = "00:00:00:00:00:00"


# --- SOME/IP Config (IPv4) ---
# Purpose: configuration for SOME/IP and SOME/IP Service Discovery (SD) attacks.

ATTACKER_IP4 = "192.168.42.30"
# IPv4 address assigned to the attacker namespace/interface.

SD_MULTICAST_GROUP = "224.224.224.245"
# Standard SOME/IP-SD multicast group used for service offers/finds.

SD_PORT = 30490
# Standard SOME/IP-SD UDP port.

PROBE_DURATION = 3.0
# Time window (seconds) used by enumeration/probing logic to listen for responses/offers.


# --- DoIP Config (IPv6) ---
# Purpose: configuration for DoIP discovery, connections, and UDS keep-alive behavior over IPv6.

MY_IP6 = 'fd00::30'
# Attacker IPv6 address used as source for DoIP traffic.

DOIP_PORT = 13400
# DoIP port (ISO 13400-2): used by the ECU for UDP discovery and TCP diagnostics.

BROADCAST_IP6 = 'ff02::1'  # IPv6 All Nodes Multicast
# IPv6 multicast address used for local-link "discover everyone" style requests.
# Note: ff02::/16 is link-local scope; packets will not route beyond the L2 segment.

AUTO_KEEPALIVE_SERVICE = b'\x3E\x80'
# UDS TesterPresent (0x3E) request payload used as keep-alive.
# 0x80 sub-function indicates "suppress positive response" in many implementations.

KEEPALIVE_INTERVAL = 4.0
# Interval (seconds) between periodic TesterPresent messages when auto keep-alive is enabled.
# Must be smaller than the ECU S3 session timeout to prevent session reset.


# --- Files ---
# Purpose: output artifact names for captures/logging.

PCAP_FILE = "doip_capture.pcap"
# PCAP file used to store captured DoIP traffic during sniffing/replay workflows.
# If you run the attacker from a different working directory, the file will be created there.
```
