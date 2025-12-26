```python
"""
config.py
Configuration constants for the Unified Automotive Attacker.

Purpose:
- Centralizes all attacker-side configuration values.
- Keeps network parameters, protocol settings, and file paths in one place.
- Intended to be edited by users to adapt the attacker to different lab topologies.

No attack logic should live here. Other modules import from this file.
"""

import os
import sys

# -----------------------------------------------------------------------------
# MAC Address Resolution
# -----------------------------------------------------------------------------
# Try to import get_if_hwaddr from doip_utils.
# This mirrors the behavior used elsewhere in the project to resolve
# the MAC address of a given network interface.
#
# If doip_utils is not available (e.g., static analysis, partial imports),
# a fallback function is defined to avoid import-time crashes.
try:
    from doip_utils import get_if_hwaddr
except ImportError:
    # Fallback: return a dummy MAC address
    # Note: attacks that rely on correct MAC addressing will not work with this.
    def get_if_hwaddr(iface):
        return "00:00:00:00:00:00"


# -----------------------------------------------------------------------------
# Interface Configuration
# -----------------------------------------------------------------------------
# Network interface name used by the attacker.
# This must match the interface created by the network setup script
# (e.g., veth pair inside the attacker namespace).
INTERFACE = "vatk"

# Resolve attacker MAC address from the interface.
# Used for:
# - SOME/IP packet crafting
# - ARP poisoning
# - Ethernet-level spoofing
try:
    ATTACKER_MAC = get_if_hwaddr(INTERFACE)
except Exception:
    # Fallback MAC if interface lookup fails
    ATTACKER_MAC = "00:00:00:00:00:00"


# -----------------------------------------------------------------------------
# SOME/IP Configuration (IPv4)
# -----------------------------------------------------------------------------
# IPv4 address assigned to the attacker node.
# Must match the address configured in the attacker network namespace.
ATTACKER_IP4 = "192.168.42.30"

# SOME/IP Service Discovery multicast group and port.
# All SOME/IP nodes must agree on these values.
SD_MULTICAST_GROUP = "224.224.224.245"
SD_PORT = 30490

# Duration (in seconds) to listen for SOME/IP responses during enumeration.
# Used by service probing and discovery attacks.
PROBE_DURATION = 3.0


# -----------------------------------------------------------------------------
# DoIP Configuration (IPv6)
# -----------------------------------------------------------------------------
# IPv6 address used by the attacker as source address for DoIP traffic.
MY_IP6 = 'fd00::30'

# Standard DoIP port as defined by ISO 13400-2.
DOIP_PORT = 13400

# IPv6 multicast address for "all nodes" on the local link.
# Used for DoIP discovery-style broadcasts.
BROADCAST_IP6 = 'ff02::1'  # IPv6 All Nodes Multicast (link-local scope)

# UDS TesterPresent service (0x3E) with "suppress positive response" sub-function (0x80).
# Used by the attacker to keep diagnostic sessions alive automatically.
AUTO_KEEPALIVE_SERVICE = b'\x3E\x80'

# Interval (seconds) between automatic TesterPresent messages.
# Must be lower than the ECU S3 timeout to prevent session reset.
KEEPALIVE_INTERVAL = 4.0


# -----------------------------------------------------------------------------
# Files / Artifacts
# -----------------------------------------------------------------------------
# PCAP file name used to store captured DoIP traffic during sniffing.
# The file is created in the current working directory.
PCAP_FILE = "doip_capture.pcap"
```
