"""
tester_dual.py
Dual-Mode DoIP Diagnostic Tester (IPv6)

Commands:
  s   → Plain TCP (port 13400, no TLS)
  tls → Secure TCP with TLS (port 3496)
"""

import socket
import struct
import sys
import select
import time
import ssl
from common_definitions import *

# =========================
# CONFIGURATION
# =========================
MY_IP = 'fd00::40'
TARGET_IP_HINT = 'fd00::10'
BROADCAST_IP = 'ff02::1'
discovery_port = 13400
PORT_PLAIN = 13400
PORT_TLS = 3496

LOGICAL_ADDR = 0x0E50

KEEPALIVE_INTERVAL = 4.0
AUTO_KEEPALIVE_SERVICE = b'\x3E\x80'

# Global state
target_ip = None
logical_addr = None
tcp_socket = None
connection_mode = None  # "PLAIN" or "TLS"
auto_keepalive = False
last_keepalive_sent = time.time()

# =========================
# TLS CONTEXT
# =========================
TLS_SERVER_NAME = "DoIP-ECU"

tls_context = ssl.create_default_context()
tls_context.check_hostname = False
tls_context.verify_mode = ssl.CERT_NONE
tls_context.minimum_version = ssl.TLSVersion.TLSv1
tls_context.maximum_version = ssl.TLSVersion.TLSv1_2
tls_context.options &= ~ssl.OP_NO_TLSv1
tls_context.options &= ~ssl.OP_NO_TLSv1_1
tls_context.set_ciphers('DEFAULT:@SECLEVEL=0')

# =========================
# SECURITY ACCESS
# =========================
PROTECTED_MODE = False
SECRET_KEY = b"\x93\x11\xfa\x22\x8b"
CONSTANT = b"\x11\x22\x33\x44"

# =========================================================
# DISCOVERY
# =========================================================
def do_discovery():
    global target_ip, logical_addr
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        sock.bind((MY_IP, 0))
    except Exception as e:
        print(f"[-] Bind error: {e}")
        return

    sock.settimeout(3.0)
    print(f"\n[d] Sending Vehicle Identification Request → {BROADCAST_IP}:{discovery_port}")
    try:
        sock.sendto(create_header(TYPE_VEHICLE_ID_REQ, 0), (BROADCAST_IP, discovery_port))
    except Exception as e:
        print(f"[-] Send failed: {e}")
        sock.close()
        return

    try:
        data, addr = sock.recvfrom(1024)
        p_type, _, payload = parse_header(data)
        if p_type != TYPE_VEHICLE_ID_RES:
            print(f"[-] Wrong response type: 0x{p_type:04X}")
            return
        entity = parse_vehicle_announcement(payload)
        if not entity:
            print("[-] Failed to parse vehicle announcement")
            return
        target_ip = addr[0].split('%')[0]
        logical_addr = entity['logical_addr']
        print("[+] Discovery SUCCESS")
        print(f"    IP              : {target_ip}")
        print(f"    Logical Address : 0x{logical_addr:04X}")
        print(f"    VIN             : {entity.get('vin', 'N/A')}")
    except socket.timeout:
        print("[-] Discovery timeout")
        print(f"[*] Using fallback IP: {TARGET_IP_HINT}")
        target_ip = TARGET_IP_HINT
        logical_addr = 0x1000
    finally:
        sock.close()

# =========================================================
# CONNECT
# =========================================================
def do_connect(use_tls: bool):
    global tcp_socket, connection_mode
    if not target_ip:
        print("[-] Run 'd' to discover vehicle first")
        return
    if tcp_socket:
        print("[!] Already connected – use 't' to disconnect first")
        return

    port = PORT_TLS if use_tls else PORT_PLAIN
    mode_str = "TLS" if use_tls else "PLAIN"
    cmd_name = "tls" if use_tls else "s"
    print(f"\n[{cmd_name}] Connecting via {mode_str} TCP to {target_ip}:{port}...")

    if not use_tls:
        # Plain TCP – no TLS, simple connect
        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect((target_ip, port))
            print("[+] Plain TCP connected")
            conn = sock
        except Exception as e:
            print(f"[-] Plain TCP connection failed: {e}")
            return
    else:
        # === TLS WITH DOWNGRADE LOOP (for downgrade attack simulation) ===
        conn = None
        raw_sock = None
        for tls_version_name, tls_version in [
            ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
            ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
            ("TLSv1.0", ssl.TLSVersion.TLSv1),
        ]:
            print(f"[*] Attempting {tls_version_name}...")
            raw_sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            raw_sock.settimeout(5.0)

            # Create fresh context for this attempt
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            # Force exact version (no negotiation range)
            context.minimum_version = tls_version
            context.maximum_version = tls_version

            # Allow legacy ciphers (critical for old automotive ECUs)
            context.set_ciphers('DEFAULT:@SECLEVEL=0')

            try:
                raw_sock.connect((target_ip, port))
                conn = context.wrap_socket(raw_sock, server_hostname=TLS_SERVER_NAME)
                actual_version = conn.version()
                print(f"[+] TLS handshake SUCCESS → {actual_version}")
                print(f"    Cipher: {conn.cipher()[0]}")
                break  # Success – exit loop
            except ssl.SSLError as e:
                print(f"[-] {tls_version_name} failed: {e}")
                try:
                    raw_sock.close()
                except:
                    pass
                conn = None
                continue
            except Exception as e:
                print(f"[-] Connection error during {tls_version_name}: {e}")
                try:
                    raw_sock.close()
                except:
                    pass
                conn = None
                continue

        if conn is None:
            print("[-] All TLS versions failed – no secure connection possible")
            return

    # === Routing Activation (same for plain and TLS) ===
    print("[*] Sending Routing Activation Request...")
    payload = struct.pack('!HBL', LOGICAL_ADDR, 0, 0)
    try:
        conn.sendall(create_header(TYPE_ROUTING_ACTIVATION_REQ, len(payload)) + payload)
    except Exception as e:
        print(f"[-] Failed to send activation: {e}")
        conn.close()
        return

    try:
        data = conn.recv(1024)
        if not data:
            raise Exception("Empty response")
        _, _, body = parse_header(data)
        code = body[4]

        if code == 0x10:
            print("[+] Routing Activation SUCCESS")
            conn.setblocking(0)
            tcp_socket = conn
            connection_mode = "TLS" if use_tls else "PLAIN"
        else:
            print(f"[-] Routing Activation failed (code 0x{code:02X})")
            conn.close()
    except Exception as e:
        print(f"[-] Activation error: {e}")
        try:
            conn.close()
        except:
            pass

# =========================================================
# DISCONNECT
# =========================================================
def do_disconnect():
    global tcp_socket, connection_mode, auto_keepalive
    if not tcp_socket:
        print("[!] Not connected")
        return
    print("\n[t] Closing connection...")
    try:
        tcp_socket.close()
    except:
        pass
    tcp_socket = None
    connection_mode = None
    auto_keepalive = False
    print("[+] Disconnected")

# =========================================================
# SEND UDS
# =========================================================
def send_uds(uds_bytes: bytes):
    if not tcp_socket or logical_addr is None:
        print("[-] Not connected")
        return None

    payload = struct.pack('!HH', LOGICAL_ADDR, logical_addr) + uds_bytes
    try:
        tcp_socket.sendall(create_header(TYPE_DIAGNOSTIC_MESSAGE, len(payload)) + payload)
    except Exception as e:
        print(f"[-] Send error: {e}")
        return None

    tcp_socket.setblocking(1)
    tcp_socket.settimeout(2.0)
    try:
        header = tcp_socket.recv(8)
        if len(header) < 8:
            return None
        p_type, p_len, _ = parse_header(header)

        while p_type != TYPE_DIAGNOSTIC_MESSAGE:
            if p_len > 0:
                tcp_socket.recv(p_len)
            header = tcp_socket.recv(8)
            if len(header) < 8:
                return None
            p_type, p_len, _ = parse_header(header)

        data = b''
        while len(data) < p_len:
            chunk = tcp_socket.recv(p_len - len(data))
            if not chunk:
                break
            data += chunk

        if len(data) >= 4:
            uds_resp = data[4:]
            print(f"Response: {uds_resp.hex().upper()}")
            return uds_resp
    except socket.timeout:
        print("Response: TIMEOUT")
    except Exception as e:
        print(f"[-] Receive error: {e}")
    finally:
        tcp_socket.setblocking(0)
    return None

# =========================================================
# SECURITY ACCESS
# =========================================================
def seed_to_key(seed):
    if PROTECTED_MODE:
        import hashlib
        import hmac
        return hmac.new(SECRET_KEY, seed, hashlib.sha256).digest()[:4]
    else:
        return (int.from_bytes(seed, "big") ^ int.from_bytes(CONSTANT, "big")).to_bytes(4, "big")

def automated_unlock():
    print("\n[AUTO] Security Access (0x27)...")
    resp = send_uds(b'\x27\x01')
    if not resp or len(resp) < 6 or resp[:2] != b'\x67\x01':
        print("[-] No valid seed received")
        return False
    seed = resp[2:6]
    key = seed_to_key(seed)
    print(f"[+] Seed {seed.hex().upper()} → Key {key.hex().upper()}")
    resp2 = send_uds(b'\x27\x02' + key)
    if resp2 and resp2[:2] == b'\x67\x02':
        print("[+] SECURITY ACCESS GRANTED")
        return True
    print("[-] Access denied")
    return False

# =========================================================
# UI
# =========================================================
def print_status():
    print("\n=== DoIP Dual-Mode Tester ===")
    print(f"Vehicle IP   : {target_ip or 'Not discovered'}")
    print(f"Connection   : {connection_mode + ' (CONNECTED)' if connection_mode else 'DISCONNECTED'}")
    print(f"Keep-alive   : {'ON' if auto_keepalive else 'OFF'}")
    print("\nCommands:")
    print("  d   → discover vehicle")
    print("  s   → connect plain TCP	tls → connect with TLS")
    print("  t   → disconnect bind")
    print("  e/x   → enable/disable auto TesterPresent (3E 80)")
    print("  q   → quit")
    print("  <hex> → send raw UDS (e.g. 10 01)")
    print(">", end=" ", flush=True)

def main():
    global auto_keepalive, last_keepalive_sent

    print("=== DoIP Tester – Plain & TLS Support ===\n")
    print_status()

    while True:
        # Auto keep-alive
        if auto_keepalive and tcp_socket:
            now = time.time()
            if now - last_keepalive_sent >= KEEPALIVE_INTERVAL:
                try:
                    payload = struct.pack('!HH', LOGICAL_ADDR, logical_addr) + AUTO_KEEPALIVE_SERVICE
                    tcp_socket.sendall(create_header(TYPE_DIAGNOSTIC_MESSAGE, len(payload)) + payload)
                    print(f"\n→ Auto TesterPresent sent")
                    last_keepalive_sent = now
                except:
                    print("\n[-] Keep-alive failed")

        # Non-blocking input
        if select.select([sys.stdin], [], [], 0.05)[0]:
            line = sys.stdin.readline().strip()
            if not line:
                continue

            # Keep original case for 'tls' detection
            if line == "q":
                print("\nGoodbye!")
                if tcp_socket:
                    tcp_socket.close()
                return

            elif line == "d":
                do_discovery()

            elif line == "s":
                do_connect(use_tls=False)

            elif line == "tls":  # ← New clear command
                do_connect(use_tls=True)

            elif line == "t":
                do_disconnect()

            elif line == "e":
                if not tcp_socket:
                    print("\n[-] Connect first")
                elif auto_keepalive:
                    print("\n[!] Already enabled")
                else:
                    auto_keepalive = True
                    last_keepalive_sent = time.time() - KEEPALIVE_INTERVAL + 0.5
                    print("\n[+] Auto keep-alive ON")

            elif line == "x":
                auto_keepalive = False
                print("\n[+] Auto keep-alive OFF")

            else:
                # Raw UDS hex
                cleaned = line.replace(" ", "").replace("0x", "").upper()
                if len(cleaned) % 2 != 0:
                    print("\n[-] Odd number of hex digits")
                elif not all(c in "0123456789ABCDEF" for c in cleaned):
                    print("\n[-] Invalid hex")
                else:
                    uds_bytes = bytes.fromhex(cleaned)
                    pairs = ' '.join(cleaned[i:i+2] for i in range(0, len(cleaned), 2))
                    print(f"\n→ {pairs}")
                    if uds_bytes == b'\x27\x01':
                        automated_unlock()
                    else:
                        send_uds(uds_bytes)

            print_status()
        else:
            time.sleep(0.01)

if __name__ == "__main__":
    main()
