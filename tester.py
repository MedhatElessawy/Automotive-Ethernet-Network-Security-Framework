import socket
import struct
from doip_utils import *
import sys
import select
import time

# --- IPv6 CONFIGURATION ---
MY_IP = 'fd00::40'
TARGET_IP_HINT = 'fd00::10'  # Main ECU
PORT = 13400
# IPv6 link-local multicast for DoIP discovery (or site-local ff05::1)
# For simplicity in local setup, we can try direct unicast if multicast fails,
# or use interface-specific multicast. Standard DoIP multicast is usually restricted.
# Let's try ff02::1 (All Nodes) for discovery on the link.
BROADCAST_IP = 'ff02::1'

LOGICAL_ADDR = 0x0E50
KEEPALIVE_INTERVAL = 4.0
AUTO_KEEPALIVE_SERVICE = b'\x3E\x80'

target_ip = None
logical_addr = None
tcp_socket = None
auto_keepalive = False
last_keepalive_sent = time.time()

# Security Config
PROTECTED_MODE = False
SECRET_KEY = b"\x93\x11\xfa\x22\x8b"
CONSTANT = b"\x11\x22\x33\x44"


def do_discovery():
    global target_ip, logical_addr
    # IPv6 UDP Socket
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    # Bind to our specific IPv6
    try:
        sock.bind((MY_IP, 0))
    except Exception as e:
        print(f"[-] Error binding to {MY_IP}: {e}")
        return

    sock.settimeout(3.0)

    print(f"\n[d] Performing UDP Vehicle Discovery (IPv6) to {BROADCAST_IP}...")
    try:
        # Send Vehicle ID Request
        # Note: Sending to multicast requires specifying interface index if not default route
        # For simplicity in this lab, we send to the broadcast group.
        sock.sendto(create_header(TYPE_VEHICLE_ID_REQ, 0), (BROADCAST_IP, PORT))
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

        target_ip = addr[0]
        # Remove %scope_id if present for clean display/connect
        if '%' in target_ip:
            target_ip = target_ip.split('%')[0]

        logical_addr = entity['logical_addr']
        print("[+] Discovery SUCCESS!")
        print(f"    IP              : {target_ip}")
        print(f"    Logical Address : 0x{logical_addr:04X}")
        print(f"    VIN             : {entity.get('vin', 'N/A')}")

    except socket.timeout:
        print("[-] Timeout – no vehicle responded.")
        # Fallback for lab: Assume target is there if we know it
        print(f"[*] Fallback: Assuming target is {TARGET_IP_HINT}")
        target_ip = TARGET_IP_HINT
        logical_addr = 0x1000  # Default Main ECU LA
    finally:
        sock.close()


def do_connect():
    global tcp_socket
    if not target_ip:
        print("[-] No vehicle discovered yet (run 'd' first).")
        return
    if tcp_socket:
        print("[!] Already connected (run 't' to disconnect first).")
        return

    print(f"\n[s] Connecting TCP (IPv6) to {target_ip}:{PORT}...")
    # IPv6 TCP Socket
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    # sock.bind((MY_IP, 0)) # Optional bind
    try:
        sock.connect((target_ip, PORT))
    except Exception as e:
        print(f"[-] Connection failed: {e}")
        return

    # Routing activation
    print("[s] Sending Routing Activation Request...")
    act_payload = struct.pack('!HBL', LOGICAL_ADDR, 0, 0)
    sock.send(create_header(TYPE_ROUTING_ACTIVATION_REQ, len(act_payload)) + act_payload)

    try:
        data = sock.recv(1024)
        _, _, body = parse_header(data)
        code = body[4]
        if code == 0x10:
            print("[+] Routing Activation SUCCESS")
            sock.setblocking(0)  # non-blocking for the main loop
            tcp_socket = sock
        else:
            print(f"[-] Activation failed (0x{code:02X})")
            sock.close()
    except Exception as e:
        print(f"[-] Activation error: {e}")
        sock.close()


def do_disconnect():
    global tcp_socket, auto_keepalive
    if not tcp_socket:
        print("[!] No active connection.")
        return
    print("\n[t] Closing TCP connection...")
    try:
        tcp_socket.close()
    except:
        pass
    tcp_socket = None
    auto_keepalive = False
    print("[+] Connection closed, keep-alive disabled.")


def send_uds(uds_bytes: bytes):
    if not tcp_socket or not logical_addr:
        print("[-] Not connected or no logical address.")
        return None

    payload = struct.pack('!HH', LOGICAL_ADDR, logical_addr) + uds_bytes
    try:
        tcp_socket.sendall(create_header(TYPE_DIAGNOSTIC_MESSAGE, len(payload)) + payload)
    except Exception as e:
        print(f"[-] Send error: {e}")
        return None

    # Temporarily switch to blocking with timeout
    tcp_socket.setblocking(1)
    tcp_socket.settimeout(2.0)

    try:
        # Read exactly one full DoIP message
        header = tcp_socket.recv(8)
        if len(header) < 8:
            print("[-] Incomplete DoIP header")
            return None

        p_type, p_len, _ = parse_header(header)
        # Drain loop for async messages
        while p_type != 0x8002:
            print(f"[!] Draining unexpected DoIP message type 0x{p_type:04X}")
            if p_len > 0:
                tcp_socket.recv(p_len)

                # Read next header
            header = tcp_socket.recv(8)
            if len(header) < 8: return None
            p_type, p_len, _ = parse_header(header)

        # Now read the actual payload
        payload_data = b''
        while len(payload_data) < p_len:
            chunk = tcp_socket.recv(p_len - len(payload_data))
            if not chunk:
                break
            payload_data += chunk

        if p_type == 0x8002:
            sa, ta = struct.unpack('!HH', payload_data[:4])
            uds_resp = payload_data[4:]
            print(f"Response: {uds_resp.hex().upper()}")
            return uds_resp
        else:
            return None

    except socket.timeout:
        print("Response: TIMEOUT")
        return None
    except Exception as e:
        print(f"[-] Receive error: {e}")
        return None
    finally:
        tcp_socket.setblocking(0)  # restore non-blocking


def seed_to_key(seed):
    c = int.from_bytes(CONSTANT, "big")
    s = int.from_bytes(seed, "big")
    return (s ^ c).to_bytes(4, "big")


def automated_unlock():
    print("\n[AUTO] Starting Security Access (27 01 → 27 02)...")
    resp = send_uds(b'\x27\x01')
    if not resp or len(resp) < 6 or resp[:2] != b'\x67\x01':
        print(" [-] Failed to get seed (no 67 01 response)")
        return False

    seed = resp[2:6]
    print(f" [+] Received Seed: {seed.hex().upper()}")

    key = seed_to_key(seed)
    print(f" [+] Sending Key: {key.hex().upper()}")

    resp2 = send_uds(b'\x27\x02' + key)
    if resp2 and resp2[:2] == b'\x67\x02':
        print(" [+] SECURITY ACCESS SUCCESSFUL!")
        return True
    else:
        print(" [-] Key rejected (wrong key or security conditions)")
        if resp2:
            print(f"     Negative response: {resp2.hex().upper()}")
        return False


def print_status():
    print("\n=== DoIP UDS Tester (IPv6) ===")
    print(f"Vehicle    : {'Found (' + str(target_ip) + ')' if target_ip else 'Not discovered'}")
    print(f"TCP        : {'CONNECTED' if tcp_socket else 'DISCONNECTED'}")
    print(f"Keep-alive : {'ON' if auto_keepalive else 'OFF'}")
    print("\nCommands: d=discover  s=connect  t=disconnect  e/x=keep-alive  q=quit  <hex>=UDS")
    print(">", end=" ", flush=True)


def main():
    global auto_keepalive, last_keepalive_sent

    print("=== DoIP UDS Tester (IPv6) ===\n")
    print_status()

    while True:
        # ---- Auto keep-alive ----
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
                    if uds_bytes == b'\x27\x01':
                        automated_unlock();
                        continue
                    send_uds(uds_bytes)

            print_status()  # refresh menu after every command

        else:
            time.sleep(0.01)  # tiny sleep when idle


if __name__ == "__main__":
    main()