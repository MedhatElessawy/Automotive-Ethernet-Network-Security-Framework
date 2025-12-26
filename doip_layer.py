import socket
import struct
import threading
import random
import hmac
import hashlib
import select
import time

# --- Local Imports ---
from doip_utils import *
from s3_timer import S3Timer

# ==========================================
#               DoIP CONFIGURATION (IPv6)
# ==========================================
SERVER_IP_V6 = '::'  # Listen on all IPv6 interfaces
PORT_DOIP = 13400
TRUSTED_IP_V6 = 'fd00::40'  # The IPv6 address of Node A (Tester)

# --- REALISTIC ECU LIMITS (DoS Protection) ---
MAX_CLIENTS = 5
client_semaphore = threading.Semaphore(MAX_CLIENTS)

# --- CONFIG ---
VIN = b'TESTVIN1234567890'
LOGICAL_ADDR = 0x1000
TESTER_ADDR = 0x0E50
EID = b'\x00\x00\x00\x00\x00\x01'
GID = b'\x00\x00\x00\x00\x00\x00'

# Security Config
PROTECTED_MODE = False
MITM_PROTECTION = False
SECRET_KEY = b"\x93\x11\xfa\x22\x8b"
CONSTANT = b"\x11\x22\x33\x44"
SESSION_TOKEN_STATIC = b"\xAA\xBB\xCC\xDD"

SEED_MIN = 0x00001000
SEED_MAX = 0x00001FFF

# ==========================================
#               DoIP LOGIC (Class)
# ==========================================
class DoIPECU:
    def __init__(self):
        self.running = True
        self.access_flag = 0
        self.session = 0x01
        self.current_seed = None
        self.session_token = None
        self.program_data = b"\x10\x20\x30\x40"
        self.routine_results = {}
        self.tester_la = None
        self.s3 = S3Timer(lambda: None, self.s3_expired, s3_timeout=5.0)

    def s3_expired(self):
        print("\n[DoIP][S3Timer] EXPIRED -> Resetting Session to Default Only")
        self.session = 0x01
        self.routine_results.clear()
        self.s3.stop()

    def seed_to_key(self, seed):
        if not PROTECTED_MODE:
            c = int.from_bytes(CONSTANT, "big")
            s = int.from_bytes(seed, "big")
            return (s ^ c).to_bytes(4, "big")
        else:
            return hmac.new(SECRET_KEY, seed, hashlib.sha256).digest()[:4]

    def process_request(self, req):
        if len(req) == 0: return b'\x7F\x00\x13'
        sid = req[0]

        # --- 0x10 SESSION CONTROL ---
        if sid == 0x10:
            if len(req) < 2: return b'\x7F\x10\x13'
            sub = req[1]
            if sub == 0x01:
                self.session = 0x01
                self.s3.stop()
                return b'\x50\x01'
            elif sub in (0x02, 0x03):
                if self.access_flag != 1: return b'\x7F\x10\x33'
                if MITM_PROTECTION:
                    if len(req) < 6 or req[2:6] != self.session_token: return b'\x7F\x10\x33'
                self.session = sub
                self.s3.start()
                print(f"[DoIP][S3Timer] Started (Session 0x{sub:02X})")
                return bytes([0x50, sub])
            return b'\x7F\x10\x12'

        # --- 0x11 ECU RESET (FULL LOGIC) ---
        elif sid == 0x11:
            if self.access_flag != 1: return b'\x7F\x11\x33'
            if len(req) < 2: return b'\x7F\x11\x13'
            sub = req[1]
            if sub in (0x01, 0x03):
                self.access_flag = 0
                self.session = 0x01
                self.session_token = None
                self.routine_results.clear()
                self.s3.stop()
                print("[DoIP][S3Timer] Stopped (ECU Reset)")
                return bytes([0x51, sub])
            return b'\x7F\x11\x12'

        # --- 0x22 READ DATA ---
        elif sid == 0x22:
            if len(req) < 3: return b'\x7F\x22\x13'
            did = (req[1] << 8) | req[2]
            if did == 0xF190:
                if self.session not in (0x02, 0x03): return b'\x7F\x22\x33'
                return b'\x62\xF1\x90' + VIN
            if did == 0xF1A0: return b'\x62\xF1\xA0' + self.program_data
            return b'\x7F\x22\x31'

        # --- 0x27 SECURITY ACCESS ---
        elif sid == 0x27:
            if len(req) < 2: return b'\x7F\x27\x13'
            sub = req[1]
            if sub == 0x01:
                val = random.randint(SEED_MIN, SEED_MAX)
                self.current_seed = val.to_bytes(4, 'big')
                self.session_token = None
                return b'\x67\x01' + self.current_seed
            elif sub == 0x02:
                if not self.current_seed: return b'\x7F\x27\x22'
                if len(req) < 6: return b'\x7F\x27\x13'
                if req[2:6] == self.seed_to_key(self.current_seed):
                    self.access_flag = 1
                    self.current_seed = None
                    if MITM_PROTECTION:
                        self.session_token = SESSION_TOKEN_STATIC
                        return b'\x67\x02' + self.session_token
                    return b'\x67\x02'
                self.access_flag = 0
                return b'\x7F\x27\x35'

        # --- 0x2E WRITE DATA ---
        elif sid == 0x2E:
            if self.access_flag != 1: return b'\x7F\x2E\x33'
            if len(req) < 4: return b'\x7F\x2E\x13'
            did = (req[1] << 8) | req[2]
            if did == 0xF1A0:
                if self.session not in (0x02, 0x03): return b'\x7F\x2E\x31'
                self.program_data = req[3:]
                return b'\x6E\xF1\xA0'
            return b'\x7F\x2E\x31'

        # --- 0x31 ROUTINE CONTROL (RESTORED) ---
        elif sid == 0x31:
            if len(req) < 4: return b'\x7F\x31\x13'
            sub = req[1]
            rid = (req[2] << 8) | req[3]

            if rid == 0x1234:  # Self Test
                if sub == 0x01:
                    self.routine_results[rid] = b'\x0B\xB8\x50\x00'
                    return b'\x71\x01\x12\x34\x00'
                elif sub == 0x03:
                    if rid not in self.routine_results: return b'\x7F\x31\x22'
                    return b'\x71\x03\x12\x34' + self.routine_results[rid]
            elif rid == 0x1390:  # Checksum
                if self.session not in (0x02, 0x03): return b'\x7F\x31\x7E'
                if sub == 0x01:
                    self.routine_results[rid] = b'\xDE\xAD\xBE\xEF\x00'
                    return b'\x71\x01\x14\x56\x00'
                elif sub == 0x03:
                    if rid not in self.routine_results: return b'\x7F\x31\x22'
                    return b'\x71\x03\x14\x56' + self.routine_results[rid]
            return b'\x7F\x31\x31'

        # --- 0x3E TESTER PRESENT (FULL LOGIC) ---
        elif sid == 0x3E:
            if len(req) < 2: return b'\x7F\x3E\x13'
            sub = req[1]
            suppress = (sub & 0x80) == 0x80

            if self.session in (0x02, 0x03):
                self.s3.reset()
                print("[DoIP][S3Timer] Timer Reset (TesterPresent)")

            if not suppress:
                return bytes([0x7E, sub & 0x7F])
            else:
                return None  # Suppress response

        return b'\x7F' + bytes([sid]) + b'\x11'

    def udp_server(self):
        # socket.AF_INET6 for IPv6
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((SERVER_IP_V6, PORT_DOIP))
        print(f"[*] [DoIP] UDP Listening on IPv6 {SERVER_IP_V6}:{PORT_DOIP}")
        while self.running:
            try:
                data, addr = sock.recvfrom(1024)
                p_type, _, _ = parse_header(data)
                if p_type == TYPE_VEHICLE_ID_REQ:
                    payload = VIN + struct.pack('!H', LOGICAL_ADDR) + EID + GID + b'\x00\x00'
                    header = create_header(TYPE_VEHICLE_ID_RES, len(payload))
                    sock.sendto(header + payload, addr)
                    print(f"[DoIP] Sent Vehicle ID to {addr}")
            except:
                pass

    def handle_client(self, conn, addr):
        # DoS Protection: Track active clients
        print(
            f"[*] [TCP] Client {addr[0]} Connected. Active: {MAX_CLIENTS - client_semaphore._value + 1}/{MAX_CLIENTS}")

        authenticated = False
        try:
            while True:
                header = conn.recv(8)
                if not header: break
                p_type, p_len, _ = parse_header(header)
                payload = conn.recv(p_len)
                if p_type == TYPE_ROUTING_ACTIVATION_REQ:
                    if len(payload) < 7:
                        res_code = 0x01  # Invalid format
                    else:
                        la = struct.unpack('!H', payload[:2])[0]  # Extract client's requested tester LA
                        if la == TESTER_ADDR:
                            res_code = 0x10  # Success
                            authenticated = True
                            self.tester_la = la
                            print(f"[+] Trusted client activated: {addr[0]} (LA=0x{la:04X})")
                        else:
                            res_code = 0x06  # Unknown source address
                            print(f"[-] Rejected unknown LA 0x{la:04X} from {addr[0]}")

                    # Correct successful response payload (exactly 9 bytes)
                    response_payload = (
                            struct.pack('!H', la) +  # Echo client's tester LA (bytes 0-1)
                            struct.pack('!H', LOGICAL_ADDR) +  # OEM-specific (usually 0x0000, bytes 2-3)
                            bytes([res_code]) +  # Success/reject code (byte 4)
                            b'\x00\x00\x00\x00'  # ISO reserved (bytes 5-8)
                    )

                    # Send with correct length 9 (for success) or 5 (for reject, but we use 9 for consistency)
                    conn.send(create_header(TYPE_ROUTING_ACTIVATION_RES, len(response_payload)) + response_payload)
                elif p_type == TYPE_DIAGNOSTIC_MESSAGE:
                    if not authenticated: conn.close(); break
                    uds_req = payload[4:]
                    print(f"[RX] UDS Req: {uds_req.hex().upper()}")
                    uds_res = self.process_request(uds_req)
                    if uds_res is not None:  # Only send if there's a response
                        full = struct.pack('!HH', LOGICAL_ADDR, self.tester_la) + uds_res
                        conn.send(create_header(TYPE_DIAGNOSTIC_POS_ACK, len(full)) + full)
                        print(f"[TX] UDS Res: {uds_res.hex().upper()}")

                elif p_type == TYPE_DIAGNOSTIC_MESSAGE:
                    if not authenticated: conn.close(); break
                    uds_res = self.process_request(payload[4:])
                    # Only send if response is not None (handles Suppress Bit)
                    if uds_res:
                        full = struct.pack('!HH', LOGICAL_ADDR, self.tester_la) + uds_res
                        conn.send(create_header(TYPE_DIAGNOSTIC_POS_ACK, len(full)) + full)
                        print(f"[TX] UDS Res: {uds_res.hex().upper()}")
        except:
            pass
        finally:
            conn.close()
            client_semaphore.release()  # DoS Protection: Release slot
            print(f"[-] [TCP] Client {addr[0]} Disconnected")

    def start(self):
        # Start UDP Discovery Server in background thread
        threading.Thread(target=self.udp_server, daemon=True).start()

        # Start TCP Listening (IPv6)
        # socket.AF_INET6 for IPv6 Support
        tcp = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp.bind((SERVER_IP_V6, PORT_DOIP))
        tcp.listen(5)
        print(f"[*] [DoIP] TCP Listening on IPv6 {SERVER_IP_V6}:{PORT_DOIP} (Max Clients: {MAX_CLIENTS})")

        while True:
            c, a = tcp.accept()
            # CRITICAL: Check semaphore BEFORE starting thread
            if client_semaphore.acquire(blocking=False):
                threading.Thread(target=self.handle_client, args=(c, a), daemon=True).start()
            else:
                print(f"[!] [DoIP] REJECTED {a[0]} - Too many connections!")
                c.close()
