"""
tester_tls.py
Secure DoIP Diagnostic Tester (IPv6 + TLS)

This script acts as a legitimate diagnostic tool that communicates over IPv6
using DoIP wrapped in TLS (Transport Layer Security).

Features:
- UDP Vehicle Discovery (Unencrypted)
- TCP/TLS Connection (Encrypted)
- Routing Activation
- UDS Service Execution
- Automated Security Access (Seed/Key)
"""
import socket
import struct
import sys
import select
import time
import ssl

from doip_utils import *

# =========================
# IPv6 CONFIGURATION
# =========================
# [CONFIGURABLE] The IPv6 address of this tester interface
MY_IP = 'fd00::40'

# [CONFIGURABLE] Fallback IP if discovery fails (e.g., direct connection)
TARGET_IP_HINT = 'fd00::10'

# Standard DoIP ports
discovery_port=13400  # UDP Discovery is usually on 13400
PORT = 3496           # TCP Data port for Secure DoIP (IANA assigned)

# [CONFIGURABLE] IPv6 Multicast group for Vehicle Identification Request
BROADCAST_IP = 'ff02::1'

# [CONFIGURABLE] The Logical Address of this Tester (e.g., 0x0E50 for external test equipment)
LOGICAL_ADDR = 0x0E50

# Keep-alive settings (TesterPresent 0x3E80)
KEEPALIVE_INTERVAL = 4.0
AUTO_KEEPALIVE_SERVICE = b'\x3E\x80'

# Global State Variables
target_ip = None
logical_addr = None
tcp_socket = None
auto_keepalive = False
last_keepalive_sent = time.time()

# =========================
# TLS CONFIGURATION
# =========================
# [CONFIGURABLE] The Common Name (CN) expected in the ECU's certificate
TLS_SERVER_NAME = "DoIP-ECU"

# Create a default SSL context
tls_context = ssl.create_default_context()

# [SECURITY CONFIG] Disable hostname checking for lab simulation
tls_context.check_hostname = False

# [SECURITY CONFIG] Disable certificate chain verification (accept self-signed)
tls_context.verify_mode = ssl.CERT_NONE

# Set allowed TLS versions (Attempt 1.0 up to 1.2)
tls_context.minimum_version = ssl.TLSVersion.TLSv1
tls_context.maximum_version = ssl.TLSVersion.TLSv1_2

# Explicitly enable older TLS versions (often disabled by default in modern Python)
tls_context.options &= ~ssl.OP_NO_TLSv1
tls_context.options &= ~ssl.OP_NO_TLSv1_1

# [CRITICAL] Lower security level to 0.
# This allows the use of legacy/weak ciphers necessary for TLS 1.0/1.1 compatibility.
tls_context.set_ciphers('DEFAULT:@SECLEVEL=0')

# =========================
# SECURITY ACCESS CONFIG
# =========================
# [CONFIGURABLE] Secret keys for the Seed & Key algorithm (UDS 0x27)
PROTECTED_MODE = False
SECRET_KEY = b"\x93\x11\xfa\x22\x8b"
CONSTANT = b"\x11\x22\x33\x44"


# =========================================================
# DISCOVERY (UDP IPv6 - NO TLS BY DESIGN)
# =========================================================
def do_discovery():
    """
    Sends a Vehicle Identification Request (VIR) via UDP multicast.
    Note: Discovery messages in DoIP are typically unencrypted even in secure modes.
    """
    global target_ip, logical_addr

    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    try:
        sock.bind((MY_IP, 0))
    except Exception as e:
        print(f"[-] Error binding to {MY_IP}: {e}")
        return

    sock.settimeout(3.0)
    print(f"\n[d] Performing UDP Vehicle Discovery (IPv6) to {BROADCAST_IP}...")

    try:
        # Send payload type 0x0001 (Vehicle ID Request)
        sock.sendto(create_header(TYPE_VEHICLE_ID_REQ, 0), (BROADCAST_IP, discovery_port))
    except Exception as e:
        print(f"[-] Discovery send failed: {e}")

    try:
        data, addr = sock.recvfrom(1024)
        p_type, _, payload = parse_header(data)

        if p_type != TYPE_VEHICLE_ID_RES:
            print(f"[-] Unexpected response type: 0x{p_type:04X}")
            return

        entity = parse_vehicle_announcement(payload)
        if not entity:
            print("[-] Failed to parse announcement.")
            return

        target_ip = addr[0].split('%')[0]
        logical_addr = entity['logical_addr']

        print("[+] Discovery SUCCESS!")
        print(f"    IP              : {target_ip}")
        print(f"    Logical Address : 0x{logical_addr:04X}")
        print(f"    VIN             : {entity.get('vin', 'N/A')}")

    except socket.timeout:
        print("[-] Timeout – no vehicle responded.")
        print(f"[*] Fallback: Assuming target is {TARGET_IP_HINT}")
        target_ip = TARGET_IP_HINT
        logical_addr = 0x1000
    finally:
        sock.close()


# =========================================================
# TCP + TLS CONNECT
# =========================================================
def do_connect():
    """
    Establishes a secure TCP connection to the ECU.
    1. Connects raw TCP socket.
    2. Performs TLS Handshake (wrapping the socket).
    3. Performs DoIP Routing Activation.
    """
    global tcp_socket

    if not target_ip:
        print("[-] No vehicle discovered yet (run 'd' first).")
        return
    if tcp_socket:
        print("[!] Already connected.")
        return

    print(f"\n[s] Connecting TCP (IPv6 + TLS) to {target_ip}:{PORT}...")

    secure_sock = None  # Initialize to avoid UnboundLocalError

    # Loop to try TLS 1.2 first, then fallback to TLS 1.0 (Simulation of negotiation)
    for version in (
            ssl.TLSVersion.TLSv1_2,
            ssl.TLSVersion.TLSv1,
    ):
        raw_sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        raw_sock.settimeout(3.0)

        try:
            print(f"[*] Trying TLS {version.name}")

            # --- CRITICAL EDITS START ---

            # 1. Lower security level to 0 to allow legacy TLS 1.0 ciphers
            # Without this, the Tester will reject its own TLS 1.0 attempt
            tls_context.set_ciphers('DEFAULT:@SECLEVEL=0')

            # 2. Set strict versions for the handshake
            tls_context.minimum_version = version
            tls_context.maximum_version = version

            # 3. Disable hostname and certificate verification for the lab
            tls_context.check_hostname = False
            tls_context.verify_mode = ssl.CERT_NONE
            try:
                raw_sock.connect((target_ip, PORT))
            except Exception as e:
                print(f"[-] TCP connection failed for {version.name}: {e}")
                raw_sock.close()
                continue  # Try next version if TCP fails (important if attacker drops SYN)

            # --- CRITICAL EDITS END ---

            # Wrap the raw TCP socket with SSL context
            secure_sock = tls_context.wrap_socket(
                raw_sock,
                server_hostname=TLS_SERVER_NAME
            )

            print(f"[+] TLS established using {secure_sock.version()}")
            break  # ✅ SUCCESS

        except (ssl.SSLError, socket.timeout, TimeoutError, ConnectionResetError) as e:
            print(f"[-] TLS {version.name} failed: {e}")
            raw_sock.close()
            secure_sock = None
            continue

    if not secure_sock:
        print("[-] All TLS versions failed")
        return

    # ---------- ROUTING ACTIVATION ----------
    # (The rest of your code remains the same)
    # Required by DoIP (ISO 13400) before any diagnostic data can be sent
    print("[s] Sending Routing Activation Request...")
    act_payload = struct.pack('!HBL', LOGICAL_ADDR, 0, 0)
    secure_sock.send(
        create_header(TYPE_ROUTING_ACTIVATION_REQ, len(act_payload)) + act_payload
    )

    try:
        data = secure_sock.recv(1024)
        _, _, body = parse_header(data)
        code = body[4]

        if code == 0x10:
            print("[+] Routing Activation SUCCESS")
            secure_sock.setblocking(0)
            tcp_socket = secure_sock
        else:
            print(f"[-] Activation failed (0x{code:02X})")
            secure_sock.close()

    except Exception as e:
        print(f"[-] Activation error: {e}")
        secure_sock.close()

# =========================================================
# DISCONNECT
# =========================================================
def do_disconnect():
    """Closes the secure connection and resets state."""
    global tcp_socket, auto_keepalive

    if not tcp_socket:
        print("[!] No active connection.")
        return

    print("\n[t] Closing TLS connection...")
    try:
        tcp_socket.close()
    except:
        pass

    tcp_socket = None
    auto_keepalive = False
    print("[+] Connection closed.")


# =========================================================
# SEND UDS (UNCHANGED)
# =========================================================
def send_uds(uds_bytes: bytes):
    """
    Wraps raw UDS bytes in a DoIP Diagnostic Message header and sends via TLS.
    """
    if not tcp_socket or not logical_addr:
        print("[-] Not connected.")
        return None

    # DoIP Payload: Source Address (2B) + Target Address (2B) + UDS Data
    payload = struct.pack('!HH', LOGICAL_ADDR, logical_addr) + uds_bytes

    try:
        tcp_socket.sendall(
            create_header(TYPE_DIAGNOSTIC_MESSAGE, len(payload)) + payload
        )
    except Exception as e:
        print(f"[-] Send error: {e}")
        return None

    # Temporarily switch to blocking to wait for response
    tcp_socket.setblocking(1)
    tcp_socket.settimeout(2.0)

    try:
        # Read DoIP Header (8 bytes)
        header = tcp_socket.recv(8)
        if len(header) < 8:
            return None

        p_type, p_len, _ = parse_header(header)

        # Handle fragmented or queued messages
        while p_type != TYPE_DIAGNOSTIC_MESSAGE:
            if p_len:
                tcp_socket.recv(p_len)
            header = tcp_socket.recv(8)
            p_type, p_len, _ = parse_header(header)

        # Read Payload
        payload_data = b''
        while len(payload_data) < p_len:
            payload_data += tcp_socket.recv(p_len - len(payload_data))

        sa, ta = struct.unpack('!HH', payload_data[:4])
        uds_resp = payload_data[4:]
        print(f"Response: {uds_resp.hex().upper()}")
        return uds_resp

    except socket.timeout:
        print("Response: TIMEOUT")
        return None
    finally:
        tcp_socket.setblocking(0)


# =========================================================
# SECURITY ACCESS
# =========================================================
def seed_to_key(seed):
    """Calculates the Key from a given Seed (Simple XOR for demo)."""
    return (int.from_bytes(seed, "big") ^ int.from_bytes(CONSTANT, "big")).to_bytes(4, "big")


def automated_unlock():
    """
    Performs the full UDS Security Access sequence (Service 0x27).
    1. Request Seed (27 01)
    2. Calculate Key
    3. Send Key (27 02)
    """
    print("\n[AUTO] Starting Security Access...")
    resp = send_uds(b'\x27\x01')

    if not resp or resp[:2] != b'\x67\x01':
        print("[-] Failed to get seed")
        return False

    seed = resp[2:6]
    key = seed_to_key(seed)
    print(f"[+] Seed: {seed.hex()}  Key: {key.hex()}")

    resp2 = send_uds(b'\x27\x02' + key)
    if resp2 and resp2[:2] == b'\x67\x02':
        print("[+] SECURITY ACCESS GRANTED")
        return True

    print("[-] SECURITY ACCESS DENIED")
    return False


# =========================================================
# UI LOOP
# =========================================================
def print_status():
    print("\n=== DoIP UDS Tester (IPv6 + TLS) ===")
    print(f"Vehicle    : {target_ip if target_ip else 'Not discovered'}")
    print(f"TLS/TCP    : {'CONNECTED' if tcp_socket else 'DISCONNECTED'}")
    print(f"Keep-alive : {'ON' if auto_keepalive else 'OFF'}")
    print("\nCommands: d=discover  s=connect  t=disconnect  e/x=keep-alive  q=quit  <hex>=UDS")
    print(">", end=" ", flush=True)


def main():
    global auto_keepalive, last_keepalive_sent

    print("=== DoIP UDS Tester (IPv6) ===\n")
    print_status()

    while True:
        # ---- Auto keep-alive ----
        # Sends TesterPresent (0x3E) periodically to keep session active
        if auto_keepalive and tcp_socket:
            now = time.time()
            if now - last_keepalive_sent >= KEEPALIVE_INTERVAL:
                try:
                    payload = struct.pack('!HH', LOGICAL_ADDR, logical_addr) + AUTO_KEEPALIVE_SERVICE
                    tcp_socket.sendall(create_header(TYPE_DIAGNOSTIC_MESSAGE, len(payload)) + payload)
                    print(f"\n→ 3E 80 auto keep-alive ({now:.1f}s)")
                    last_keepalive_sent = now
                except:
                    print("\n[-] Failed to send keep-alive")

        # ---- Check for user input (non-blocking) ----
        if select.select([sys.stdin], [], [], 0.05)[0]:
            line = sys.stdin.readline().strip()
            if not line:
                continue

            # Single-letter commands
            cmd = line.lower()
            if cmd in ("d", "s", "t", "e", "x", "q"):
                if cmd == "q":
                    print("\nGoodbye!")
                    if tcp_socket:
                        tcp_socket.close()
                    return

                elif cmd == "d":
                    do_discovery()

                elif cmd == "s":
                    do_connect()

                elif cmd == "t":
                    do_disconnect()

                elif cmd == "e":
                    if not tcp_socket:
                        print("\n[-] Connect first with 's'")
                    elif auto_keepalive:
                        print("\n[!] Keep-alive already ON")
                    else:
                        auto_keepalive = True
                        last_keepalive_sent = time.time() - KEEPALIVE_INTERVAL + 0.5
                        print("\n[+] Auto 3E80 keep-alive ENABLED")

                elif cmd == "x":
                    auto_keepalive = False
                    print("\n[+] Auto 3E80 keep-alive DISABLED")

            else:
                # Hex UDS command
                cleaned = line.replace(" ", "").replace("0x", "").upper()
                if len(cleaned) % 2 != 0:
                    print("\n[-] Odd number of hex digits")
                elif not all(c in "0123456789ABCDEF" for c in cleaned):
                    print("\n[-] Invalid hex characters")
                else:
                    uds_bytes = bytes.fromhex(cleaned)
                    pairs = [cleaned[i:i + 2] for i in range(0, len(cleaned), 2)]
                    print(f"\n{' '.join(pairs)} was sent!")
                    # Check for quick-macro to unlock security
                    if uds_bytes == b'\x27\x01':
                        automated_unlock();
                        continue
                    send_uds(uds_bytes)

            print_status()  # refresh menu after every command

        else:
            time.sleep(0.01)  # tiny sleep when idle


if __name__ == "__main__":
    main()
S
