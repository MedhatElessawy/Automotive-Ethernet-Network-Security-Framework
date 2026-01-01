import socket
import struct
import threading
import random
import hmac
import hashlib
import select, os
import time
import ssl

# --- Local Imports ---
from common_definitions import *


# ==========================================
# DoIP CONFIGURATION (IPv6)
# ==========================================
SERVER_IP_V6 = '::'                  # Listen on all IPv6 interfaces
PORT_DOIP_PLAIN = 13400              # Standard DoIP TCP port (non-TLS)
PORT_DOIP_TLS = 3496                 # Your desired TLS port
DIS_PORT = 13400                     # UDP discovery port stays the same

TRUSTED_IP_V6 = 'fd00::40'           # The IPv6 address of Node A (Tester)

# SSL Configs (only used for TLS port)
CERT_FILE = os.path.join(os.path.dirname(__file__), "../certs/server.crt")
KEY_FILE = os.path.join(os.path.dirname(__file__), "../certs/server.key")

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

#Protection KEYS
IP_PROTECTION = False
LOCKOUT_PROTECTION = False
MAX_ERROR_COUNT =3
LOCKOUT_SECONDS = 30


# ==========================================
# DoIP LOGIC (Class)
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
        self.lockout_until = 0.0
        self.error_num = 0

    def s3_expired(self):
        print("\n[DoIP][S3Timer] EXPIRED -> Resetting Session to Default Only")
        self.session = 0x01
        self.routine_results.clear()
        # self.s3.stop()

    def seed_to_key(self, seed):
        if not PROTECTED_MODE:
            c = int.from_bytes(CONSTANT, "big")
            s = int.from_bytes(seed, "big")
            return (s ^ c).to_bytes(4, "big")
        else:
            return hmac.new(SECRET_KEY, seed, hashlib.sha256).digest()[:4]

    def process_request(self, req):
        """Parses and processes raw UDS bytes (SID + Data). Returns response bytes or None."""
        if len(req) == 0:
            return b'\x7F\x00\x13'  # NRC: Incorrect Message Length

        sid = req[0]

        # ---------------------------------------------------------
        # 0x10 Diagnostic Session Control
        # ---------------------------------------------------------
        if sid == 0x10:
            if len(req) < 2:
                return b'\x7F\x10\x13'
            sub = req[1]

            if sub == 0x01:  # Default Session
                self.session = 0x01
                self.s3.stop()
                return b'\x50\x01'

            elif sub in (0x02, 0x03):  # Programming or Extended
                if self.access_flag != 1:
                    return b'\x7F\x10\x33'  # Security Access Denied

                if MITM_PROTECTION:
                    if len(req) < 6 or req[2:6] != self.session_token:
                        return b'\x7F\x10\x33'

                self.session = sub
                self.s3.start()
                print(f"[DoIP][S3Timer] Started (Session 0x{sub:02X})")
                return bytes([0x50, sub])

            return b'\x7F\x10\x12'  # Sub-function Not Supported

        # ---------------------------------------------------------
        # 0x11 ECU Reset
        # ---------------------------------------------------------
        elif sid == 0x11:
            if self.access_flag != 1:
                return b'\x7F\x11\x33'
            if len(req) < 2:
                return b'\x7F\x11\x13'
            sub = req[1]

            if sub in (0x01, 0x03):  # Hard or Soft Reset
                self.access_flag = 0
                self.session = 0x01
                self.session_token = None
                self.routine_results.clear()
                self.s3.stop()
                # Reset lockout if enabled
                if hasattr(self, 'error_num'):
                    self.error_num = 0
                if hasattr(self, 'lockout_until'):
                    self.lockout_until = 0.0
                print("[DoIP][S3Timer] Stopped (ECU Reset)")
                return bytes([0x51, sub])

            return b'\x7F\x11\x12'

        # ---------------------------------------------------------
        # 0x22 Read Data By Identifier
        # ---------------------------------------------------------
        elif sid == 0x22:
            if len(req) < 3:
                return b'\x7F\x22\x13'
            did = (req[1] << 8) | req[2]

            if did == 0xF190:  # VIN
                if self.session not in (0x02, 0x03):
                    return b'\x7F\x22\x33'
                return b'\x62\xF1\x90' + VIN

            elif did == 0xF1A0:  # Custom Program Data
                return b'\x62\xF1\xA0' + self.program_data

            return b'\x7F\x22\x31'  # Request Out of Range

        # ---------------------------------------------------------
        # 0x27 Security Access (with optional lockout protection)
        # ---------------------------------------------------------
        elif sid == 0x27:
            if len(req) < 2:
                return b'\x7F\x27\x13'

            current_time = time.time()

            # Lockout check (if protection is enabled globally)
            if LOCKOUT_PROTECTION:
                if current_time < self.lockout_until:
                    return b'\x7F\x27\x37'  # Required Time Delay Not Expired

                elif self.lockout_until > 0:  # Just came out of lockout
                    print(f"[DoIP] Lockout FINISHED at {time.ctime(current_time)}. Access restored.")
                    self.lockout_until = 0.0
                    self.error_num = 0

            sub = req[1]

            if sub == 0x01:  # Request Seed
                val = random.randint(SEED_MIN, SEED_MAX)
                self.current_seed = val.to_bytes(4, 'big')
                self.session_token = None
                return b'\x67\x01' + self.current_seed

            elif sub == 0x02:  # Send Key
                if not self.current_seed:
                    return b'\x7F\x27\x22'  # Conditions Not Correct
                if len(req) < 6:
                    return b'\x7F\x27\x13'

                if req[2:6] == self.seed_to_key(self.current_seed):
                    self.access_flag = 1
                    self.current_seed = None
                    self.error_num = 0
                    if MITM_PROTECTION:
                        self.session_token = SESSION_TOKEN_STATIC
                        return b'\x67\x02' + self.session_token
                    return b'\x67\x02'
                else:
                    # Invalid Key
                    self.access_flag = 0
                    if LOCKOUT_PROTECTION:
                        if self.error_num < MAX_ERROR_COUNT - 1:
                            self.error_num += 1
                            print(f"[DoIP] Invalid Key. Attempts: {self.error_num}/{MAX_ERROR_COUNT}")
                            return b'\x7F\x27\x35'  # Invalid Key
                        else:
                            # Trigger lockout
                            self.error_num = 0
                            self.lockout_until = time.time() + LOCKOUT_SECONDS
                            finish_time = time.ctime(self.lockout_until)
                            print(f"[DoIP] MAX ATTEMPTS REACHED. Locking out for {LOCKOUT_SECONDS}s until {finish_time}")
                            return b'\x7F\x27\x36'  # Exceeded Number of Attempts
                    return b'\x7F\x27\x35'

        # ---------------------------------------------------------
        # 0x2E Write Data By Identifier
        # ---------------------------------------------------------
        elif sid == 0x2E:
            if self.access_flag != 1:
                return b'\x7F\x2E\x33'
            if len(req) < 4:
                return b'\x7F\x2E\x13'
            did = (req[1] << 8) | req[2]

            if did == 0xF1A0:
                if self.session not in (0x02, 0x03):
                    return b'\x7F\x2E\x31'
                self.program_data = req[3:]
                return b'\x6E\xF1\xA0'

            return b'\x7F\x2E\x31'

        # ---------------------------------------------------------
        # 0x31 Routine Control
        # ---------------------------------------------------------
        elif sid == 0x31:
            if len(req) < 4:
                return b'\x7F\x31\x13'
            sub = req[1]
            rid = (req[2] << 8) | req[3]

            if rid == 0x1234:  # Self Test
                if sub == 0x01:
                    self.routine_results[rid] = b'\x0B\xB8\x50\x00'
                    return b'\x71\x01\x12\x34\x00'
                elif sub == 0x03:
                    if rid not in self.routine_results:
                        return b'\x7F\x31\x22'
                    return b'\x71\x03\x12\x34' + self.routine_results[rid]

            elif rid == 0x1390:  # Checksum
                if self.session not in (0x02, 0x03):
                    return b'\x7F\x31\x7E'
                if sub == 0x01:
                    self.routine_results[rid] = b'\xDE\xAD\xBE\xEF\x00'
                    return b'\x71\x01\x14\x56\x00'
                elif sub == 0x03:
                    if rid not in self.routine_results:
                        return b'\x7F\x31\x22'
                    return b'\x71\x03\x14\x56' + self.routine_results[rid]

            return b'\x7F\x31\x31'

        # ---------------------------------------------------------
        # 0x3E Tester Present
        # ---------------------------------------------------------
        elif sid == 0x3E:
            if len(req) < 2:
                return b'\x7F\x3E\x13'
            sub = req[1]
            suppress = (sub & 0x80) == 0x80

            if self.session in (0x02, 0x03):
                self.s3.reset()
                print("[DoIP][S3Timer] Timer Reset (TesterPresent)")

            if not suppress:
                return bytes([0x7E, sub & 0x7F])
            else:
                return None  # Suppress positive response

        # ---------------------------------------------------------
        # Default: Service Not Supported
        # ---------------------------------------------------------
        return b'\x7F' + bytes([sid]) + b'\x11'

    def udp_server(self):
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((SERVER_IP_V6, DIS_PORT))
        print(f"[*] [DoIP] UDP Discovery listening on [{SERVER_IP_V6}]:{DIS_PORT}")
        while self.running:
            try:
                data, addr = sock.recvfrom(1024)
                p_type, _, _ = parse_header(data)
                if p_type == TYPE_VEHICLE_ID_REQ:
                    payload = VIN + struct.pack('!H', LOGICAL_ADDR) + EID + GID + b'\x00\x00'
                    header = create_header(TYPE_VEHICLE_ID_RES, len(payload))
                    sock.sendto(header + payload, addr)
                    print(f"[DoIP] Sent Vehicle ID to {addr}")
            except Exception:
                pass

    def handle_client(self, conn, addr, secure=False):
        proto = "TLS" if secure else "PLAIN"
        print(f"[*] [TCP/{proto}] Client {addr[0]} connected. Active: {MAX_CLIENTS - client_semaphore._value}/{MAX_CLIENTS}")

        ip = addr[0]
        authenticated = False
        try:
            while True:
                header = conn.recv(8)
                if not header:
                    break
                p_type, p_len, _ = parse_header(header)
                payload = conn.recv(p_len)

                if p_type == TYPE_ROUTING_ACTIVATION_REQ:
                    if len(payload) < 7:
                        res_code = 0x01
                    else:
                        la = struct.unpack('!H', payload[:2])[0]
                        # --- ADD IP PROTECTION CHECK ---
                        if la == TESTER_ADDR and (not IP_PROTECTION or ip == TRUSTED_IP_V6):
                            res_code = 0x10
                            authenticated = True
                            self.tester_la = la
                            print(f"[+] [{proto}] Trusted client activated: {addr[0]} (LA=0x{la:04X})")
                        else:
                            res_code = 0x06
                            print(f"[-] [{proto}] Rejected unknown LA 0x{la:04X} from {addr[0]}")
                    response_payload = (
                        struct.pack('!H', la) +
                        struct.pack('!H', LOGICAL_ADDR) +
                        bytes([res_code]) +
                        b'\x00\x00\x00\x00'
                    )
                    conn.send(create_header(TYPE_ROUTING_ACTIVATION_RES, len(response_payload)) + response_payload)

                elif p_type == TYPE_DIAGNOSTIC_MESSAGE:
                    if not authenticated:
                        conn.close()
                        break

                    uds_req = payload[4:]

                    # --- LOG SPAM PREVENTION DURING LOCKOUT ---
                    current_time = time.time()
                    is_locked = LOCKOUT_PROTECTION and (current_time < self.lockout_until)
                    if not is_locked:
                        print(f"[RX/{proto}] UDS Req: {uds_req.hex().upper()}")

                    uds_res = self.process_request(uds_req)

                    if uds_res is not None:
                        full = struct.pack('!HH', LOGICAL_ADDR, self.tester_la) + uds_res
                        conn.send(create_header(TYPE_DIAGNOSTIC_MESSAGE, len(full)) + full)

                        if not is_locked:
                            print(f"[TX/{proto}] UDS Res: {uds_res.hex().upper()}")

                        # --- CLOSE CONNECTION ON LOCKOUT TRIGGER (NRC 0x36) ---
                        if uds_res == b'\x7F\x27\x36':
                            print("[!] Lockout Triggered. Closing connection to prevent further attacks.")
                            break

        except Exception as e:
            print(f"[!] [{proto}] Exception in handler: {e}")
        finally:
            conn.close()
            client_semaphore.release()
            print(f"[-] [TCP/{proto}] Client {addr[0]} disconnected")

    def start(self):
        # Start UDP Discovery
        threading.Thread(target=self.udp_server, daemon=True).start()

        # -----------------------------
        # 1. Plain TCP listener (port 13400)
        # -----------------------------
        def plain_tcp_server():
            plain_sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            plain_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            plain_sock.bind((SERVER_IP_V6, PORT_DOIP_PLAIN))
            plain_sock.listen(5)
            print(f"[*] [DoIP] Plain TCP listening on [{SERVER_IP_V6}]:{PORT_DOIP_PLAIN}")

            while self.running:
                try:
                    conn, addr = plain_sock.accept()
                    if not client_semaphore.acquire(blocking=False):
                        print(f"[!] [PLAIN] Rejected {addr[0]} - Too many connections")
                        conn.close()
                        continue
                    threading.Thread(
                        target=self.handle_client,
                        args=(conn, addr, False),
                        daemon=True
                    ).start()
                except Exception as e:
                    if self.running:
                        print(f"[PLAIN] Accept error: {e}")

        # -----------------------------
        # 2. TLS TCP listener (port 3496)
        # -----------------------------
        def secure_tcp_server():
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
            context.set_ciphers("DEFAULT:@SECLEVEL=0")
            context.minimum_version = ssl.TLSVersion.TLSv1
            context.maximum_version = ssl.TLSVersion.TLSv1_2

            secure_sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            secure_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            secure_sock.bind((SERVER_IP_V6, PORT_DOIP_TLS))
            secure_sock.listen(5)
            print(f"[*] [DoIP] Secure TCP (TLS) listening on [{SERVER_IP_V6}]:{PORT_DOIP_TLS}")

            while self.running:
                try:
                    raw_conn, addr = secure_sock.accept()
                    if not client_semaphore.acquire(blocking=False):
                        print(f"[!] [TLS] Rejected {addr[0]} - Too many connections")
                        raw_conn.close()
                        continue

                    try:
                        secure_conn = context.wrap_socket(raw_conn, server_side=True)
                        print(f"[+] [TLS] Handshake SUCCESS with {addr} | {secure_conn.version()} | Cipher: {secure_conn.cipher()}")
                    except ssl.SSLError as ssl_err:
                        print(f"[-] [TLS] Handshake FAILED with {addr}: {ssl_err}")
                        client_semaphore.release()
                        raw_conn.close()
                        continue
                    except Exception as e:
                        print(f"[-] [TLS] Wrap error: {e}")
                        client_semaphore.release()
                        raw_conn.close()
                        continue

                    threading.Thread(
                        target=self.handle_client,
                        args=(secure_conn, addr, True),
                        daemon=True
                    ).start()
                except Exception as e:
                    if self.running:
                        print(f"[TLS] Accept error: {e}")

        # Start both listeners
        threading.Thread(target=plain_tcp_server, daemon=True).start()
        threading.Thread(target=secure_tcp_server, daemon=True).start()

        # Keep main thread alive
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[*] Shutting down...")
            self.running = False


# ==========================================
# Entry Point
# ==========================================
if __name__ == "__main__":
    ecu = DoIPECU()
    ecu.start()
