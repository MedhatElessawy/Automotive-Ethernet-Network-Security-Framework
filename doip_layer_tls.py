```python
import socket
import struct
import threading
import random
import hmac
import hashlib
import select
import time
import ssl

# --- Local Imports ---
# doip_utils is expected to provide:
# - TYPE_* constants for DoIP payload types
# - parse_header() to decode 8-byte DoIP headers
# - create_header() to build DoIP headers
from doip_utils import *
# S3Timer implements the UDS S3 server inactivity timer behavior
from s3_timer import S3Timer

# ==========================================
#               DoIP CONFIGURATION (IPv6)
# ==========================================
# IPv6 bind address:
# - '::' means bind/listen on all IPv6 interfaces of the host
SERVER_IP_V6 = '::'  # Listen on all IPv6 interfaces

# TCP DoIP port used by THIS server (secure channel here)
# NOTE: 3496 is not the typical DoIP port (13400). In this script it is intentional as your TCP/TLS port.
PORT_DOIP = 3496

# UDP discovery port for Vehicle Identification (commonly 13400)
# This script listens for DoIP discovery requests on this separate port.
dis_port = 13400

# (Optional) Trusted tester IPv6 address for your lab topology
# NOTE: This variable is defined but NOT used for enforcement in this code.
TRUSTED_IP_V6 = 'fd00::40'  # The IPv6 address of Node A (Tester)

# ==========================================
#               SSL/TLS CONFIG
# ==========================================
# Server certificate and private key used by TLS server socket
CERT_FILE = "server.crt"
KEY_FILE = "server.key"

# --- REALISTIC ECU LIMITS (DoS Protection) ---
# Maximum number of concurrent TCP clients allowed.
# Enforced using a semaphore acquired before starting a client thread.
MAX_CLIENTS = 5
client_semaphore = threading.Semaphore(MAX_CLIENTS)

# ==========================================
#               ECU / UDS CONFIG
# ==========================================
# VIN used in:
# - UDP DoIP Vehicle Identification Response
# - UDS ReadDataByIdentifier 0x22 DID 0xF190 response
VIN = b'TESTVIN1234567890'

# ECU logical address used in DoIP diagnostic framing (source LA)
LOGICAL_ADDR = 0x1000

# Expected tester logical address. Client must request this LA in Routing Activation.
TESTER_ADDR = 0x0E50

# Entity ID and Group ID used in DoIP discovery response payload
EID = b'\x00\x00\x00\x00\x00\x01'
GID = b'\x00\x00\x00\x00\x00\x00'

# ==========================================
#               SECURITY CONFIG
# ==========================================
# PROTECTED_MODE:
# - False -> weak XOR seed-key: key = seed XOR CONSTANT
# - True  -> HMAC-SHA256(SECRET_KEY, seed) truncated to 4 bytes
PROTECTED_MODE = False

# MITM_PROTECTION:
# - False -> after valid key, ECU returns only 0x67 0x02 (unlocked)
# - True  -> after valid key, ECU returns a session token and requires it for some ops
MITM_PROTECTION = False

# HMAC key used only when PROTECTED_MODE=True
SECRET_KEY = b"\x93\x11\xfa\x22\x8b"

# XOR constant used only when PROTECTED_MODE=False
CONSTANT = b"\x11\x22\x33\x44"

# Static token returned when MITM_PROTECTION=True after successful key
SESSION_TOKEN_STATIC = b"\xAA\xBB\xCC\xDD"

# Seed generation bounds (simulated ECU range)
SEED_MIN = 0x00001000
SEED_MAX = 0x00001FFF


# ==========================================
#               DoIP LOGIC (Class)
# ==========================================
class DoIPECU:
    def __init__(self):
        # Server run flag for UDP + TCP accept loops
        self.running = True

        # Security access state:
        # 0 = locked, 1 = unlocked
        self.access_flag = 0

        # UDS session:
        # 0x01 default, 0x02/0x03 non-default sessions (used here)
        self.session = 0x01

        # Stores last issued seed for 0x27 flow
        self.current_seed = None

        # Session token used when MITM_PROTECTION=True
        self.session_token = None

        # Example data for DID 0xF1A0
        self.program_data = b"\x10\x20\x30\x40"

        # Cache routine results by RID
        self.routine_results = {}

        # Tester logical address captured from routing activation
        self.tester_la = None

        # S3 timer:
        # - started when entering session 0x02/0x03
        # - reset by TesterPresent (0x3E) in those sessions
        # - expiry returns session to 0x01 and clears routine state
        self.s3 = S3Timer(lambda: None, self.s3_expired, s3_timeout=5.0)

    def s3_expired(self):
        # Called when S3 server timer expires
        print("\n[DoIP][S3Timer] EXPIRED -> Resetting Session to Default Only")
        self.session = 0x01
        self.routine_results.clear()
        self.s3.stop()

    def seed_to_key(self, seed):
        # Converts ECU seed to key based on selected mode
        if not PROTECTED_MODE:
            # Weak XOR-based seed/key
            c = int.from_bytes(CONSTANT, "big")
            s = int.from_bytes(seed, "big")
            return (s ^ c).to_bytes(4, "big")
        else:
            # HMAC-based seed/key
            return hmac.new(SECRET_KEY, seed, hashlib.sha256).digest()[:4]

    def process_request(self, req):
        # Process a raw UDS request payload (SID + params)
        # Return bytes response, or None if response is suppressed.
        if len(req) == 0:
            # 0x13 = IncorrectMessageLengthOrInvalidFormat
            return b'\x7F\x00\x13'

        sid = req[0]

        # --- 0x10 SESSION CONTROL ---
        if sid == 0x10:
            if len(req) < 2:
                return b'\x7F\x10\x13'

            sub = req[1]

            # Default session
            if sub == 0x01:
                self.session = 0x01
                self.s3.stop()
                return b'\x50\x01'

            # Non-default sessions
            elif sub in (0x02, 0x03):
                # Require security access
                if self.access_flag != 1:
                    # 0x33 = SecurityAccessDenied
                    return b'\x7F\x10\x33'

                # Optional token check when MITM_PROTECTION enabled
                if MITM_PROTECTION:
                    if len(req) < 6 or req[2:6] != self.session_token:
                        return b'\x7F\x10\x33'

                self.session = sub
                self.s3.start()
                print(f"[DoIP][S3Timer] Started (Session 0x{sub:02X})")
                return bytes([0x50, sub])

            # 0x12 = SubFunctionNotSupported
            return b'\x7F\x10\x12'

        # --- 0x11 ECU RESET ---
        elif sid == 0x11:
            if self.access_flag != 1:
                return b'\x7F\x11\x33'
            if len(req) < 2:
                return b'\x7F\x11\x13'

            sub = req[1]

            # Reset types handled here
            if sub in (0x01, 0x03):
                # Reset ECU runtime state
                self.access_flag = 0
                self.session = 0x01
                self.session_token = None
                self.routine_results.clear()
                self.s3.stop()
                print("[DoIP][S3Timer] Stopped (ECU Reset)")
                return bytes([0x51, sub])

            return b'\x7F\x11\x12'

        # --- 0x22 READ DATA BY IDENTIFIER ---
        elif sid == 0x22:
            if len(req) < 3:
                return b'\x7F\x22\x13'

            did = (req[1] << 8) | req[2]

            # VIN DID
            if did == 0xF190:
                # Restricted to non-default sessions in this lab behavior
                if self.session not in (0x02, 0x03):
                    return b'\x7F\x22\x33'
                return b'\x62\xF1\x90' + VIN

            # Program data DID
            if did == 0xF1A0:
                return b'\x62\xF1\xA0' + self.program_data

            return b'\x7F\x22\x31'

        # --- 0x27 SECURITY ACCESS ---
        elif sid == 0x27:
            if len(req) < 2:
                return b'\x7F\x27\x13'

            sub = req[1]

            # Request seed
            if sub == 0x01:
                val = random.randint(SEED_MIN, SEED_MAX)
                self.current_seed = val.to_bytes(4, 'big')
                self.session_token = None
                return b'\x67\x01' + self.current_seed

            # Send key
            elif sub == 0x02:
                if not self.current_seed:
                    # Used here when no seed exists
                    return b'\x7F\x27\x22'
                if len(req) < 6:
                    return b'\x7F\x27\x13'

                # Validate provided key bytes
                if req[2:6] == self.seed_to_key(self.current_seed):
                    self.access_flag = 1
                    self.current_seed = None

                    # Optional token return
                    if MITM_PROTECTION:
                        self.session_token = SESSION_TOKEN_STATIC
                        return b'\x67\x02' + self.session_token

                    return b'\x67\x02'

                # Invalid key
                self.access_flag = 0
                return b'\x7F\x27\x35'

        # --- 0x2E WRITE DATA BY IDENTIFIER ---
        elif sid == 0x2E:
            if self.access_flag != 1:
                return b'\x7F\x2E\x33'
            if len(req) < 4:
                return b'\x7F\x2E\x13'

            did = (req[1] << 8) | req[2]

            # Write program data
            if did == 0xF1A0:
                if self.session not in (0x02, 0x03):
                    return b'\x7F\x2E\x31'
                self.program_data = req[3:]
                return b'\x6E\xF1\xA0'

            return b'\x7F\x2E\x31'

        # --- 0x31 ROUTINE CONTROL ---
        elif sid == 0x31:
            if len(req) < 4:
                return b'\x7F\x31\x13'

            sub = req[1]
            rid = (req[2] << 8) | req[3]

            # RID 0x1234: Self Test
            if rid == 0x1234:
                if sub == 0x01:
                    self.routine_results[rid] = b'\x0B\xB8\x50\x00'
                    return b'\x71\x01\x12\x34\x00'
                elif sub == 0x03:
                    if rid not in self.routine_results:
                        return b'\x7F\x31\x22'
                    return b'\x71\x03\x12\x34' + self.routine_results[rid]

            # RID 0x1390: Checksum (restricted to non-default sessions)
            elif rid == 0x1390:
                if self.session not in (0x02, 0x03):
                    return b'\x7F\x31\x7E'
                if sub == 0x01:
                    self.routine_results[rid] = b'\xDE\xAD\xBE\xEF\x00'
                    # Note: payload uses 0x14 0x56 per your current logic
                    return b'\x71\x01\x14\x56\x00'
                elif sub == 0x03:
                    if rid not in self.routine_results:
                        return b'\x7F\x31\x22'
                    return b'\x71\x03\x14\x56' + self.routine_results[rid]

            return b'\x7F\x31\x31'

        # --- 0x3E TESTER PRESENT ---
        elif sid == 0x3E:
            if len(req) < 2:
                return b'\x7F\x3E\x13'

            sub = req[1]

            # Response suppression bit = 0x80
            suppress = (sub & 0x80) == 0x80

            # Reset S3 timer in non-default session
            if self.session in (0x02, 0x03):
                self.s3.reset()
                print("[DoIP][S3Timer] Timer Reset (TesterPresent)")

            # If not suppressed, send response; else return None
            if not suppress:
                return bytes([0x7E, sub & 0x7F])
            else:
                return None  # Suppress response

        # Default negative response for unsupported SID
        return b'\x7F' + bytes([sid]) + b'\x11'

    def udp_server(self):
        # UDP DoIP discovery server (Vehicle Identification)
        # Listens on dis_port (usually 13400)
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((SERVER_IP_V6, dis_port))

        # NOTE: print uses PORT_DOIP in message even though bound port is dis_port (kept as-is)
        print(f"[*] [DoIP] UDP Listening on IPv6 {SERVER_IP_V6}:{PORT_DOIP}")

        while self.running:
            try:
                data, addr = sock.recvfrom(1024)
                p_type, _, _ = parse_header(data)

                # Respond only to vehicle identification requests
                if p_type == TYPE_VEHICLE_ID_REQ:
                    payload = VIN + struct.pack('!H', LOGICAL_ADDR) + EID + GID + b'\x00\x00'
                    header = create_header(TYPE_VEHICLE_ID_RES, len(payload))
                    sock.sendto(header + payload, addr)
                    print(f"[DoIP] Sent Vehicle ID to {addr}")
            except:
                pass

    def handle_client(self, conn, addr):
        # Per-client TLS-wrapped TCP connection handler
        print(
            f"[*] [TCP] Client {addr[0]} Connected. Active: {MAX_CLIENTS - client_semaphore._value + 1}/{MAX_CLIENTS}"
        )

        authenticated = False

        try:
            while True:
                # Read DoIP header (8 bytes)
                header = conn.recv(8)
                if not header:
                    break

                # Parse header fields (type, length, ...)
                p_type, p_len, _ = parse_header(header)

                # Read full payload
                payload = conn.recv(p_len)

                # -------------------------------
                # Routing activation
                # -------------------------------
                if p_type == TYPE_ROUTING_ACTIVATION_REQ:
                    if len(payload) < 7:
                        res_code = 0x01  # Invalid format
                    else:
                        # Extract tester requested LA from first 2 bytes
                        la = struct.unpack('!H', payload[:2])[0]

                        # Authenticate only if LA matches configured tester
                        if la == TESTER_ADDR:
                            res_code = 0x10  # Success
                            authenticated = True
                            self.tester_la = la
                            print(f"[+] Trusted client activated: {addr[0]} (LA=0x{la:04X})")
                        else:
                            res_code = 0x06  # Unknown source address
                            print(f"[-] Rejected unknown LA 0x{la:04X} from {addr[0]}")

                    # Routing activation response payload:
                    # - tester LA (2)
                    # - ECU logical address (2)
                    # - response code (1)
                    # - reserved (4)
                    response_payload = (
                        struct.pack('!H', la) +
                        struct.pack('!H', LOGICAL_ADDR) +
                        bytes([res_code]) +
                        b'\x00\x00\x00\x00'
                    )

                    conn.send(create_header(TYPE_ROUTING_ACTIVATION_RES, len(response_payload)) + response_payload)

                # -------------------------------
                # Diagnostic message (UDS over DoIP)
                # -------------------------------
                elif p_type == TYPE_DIAGNOSTIC_MESSAGE:
                    # Reject diagnostics unless routing activation succeeded
                    if not authenticated:
                        conn.close()
                        break

                    # Strip DoIP diag addressing (first 4 bytes)
                    uds_req = payload[4:]
                    print(f"[RX] UDS Req: {uds_req.hex().upper()}")

                    # Process UDS
                    uds_res = self.process_request(uds_req)

                    # Only respond if not suppressed (None)
                    if uds_res is not None:
                        # Build response: ECU LA + tester LA + UDS response
                        full = struct.pack('!HH', LOGICAL_ADDR, self.tester_la) + uds_res

                        # IMPORTANT (as per your comment in code):
                        # This sends TYPE_DIAGNOSTIC_MESSAGE (0x8001) for responses, not POS_ACK.
                        # Kept exactly as your current code.
                        conn.send(create_header(TYPE_DIAGNOSTIC_MESSAGE, len(full)) + full)

                        print(f"[TX] UDS Res: {uds_res.hex().upper()}")

        except:
            pass
        finally:
            conn.close()
            client_semaphore.release()  # Release DoS slot
            print(f"[-] [TCP] Client {addr[0]} Disconnected")

    def start(self):
        # Start UDP discovery in background thread
        threading.Thread(target=self.udp_server, daemon=True).start()

        # ==========================================
        #               TLS CONTEXT SETUP
        # ==========================================
        # Create a TLS server context
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        # Load server certificate and private key (must exist on disk)
        context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

        # Allow older/weak cipher suites by lowering OpenSSL security level (lab/testing)
        context.set_ciphers("DEFAULT:@SECLEVEL=0")

        # Restrict TLS versions (lab settings):
        # - minimum TLSv1
        # - maximum TLSv1.2
        # NOTE: this allows TLS 1.0/1.1 which are insecure in production.
        context.minimum_version = ssl.TLSVersion.TLSv1
        context.maximum_version = ssl.TLSVersion.TLSv1_2

        # ==========================================
        #               TCP LISTENER (IPv6)
        # ==========================================
        tcp = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp.bind((SERVER_IP_V6, PORT_DOIP))
        tcp.listen(5)

        # NOTE: Print says "TLS 1.2 Only" but max_version allows up to TLS 1.2 (not only). Kept as-is.
        print(f"[*] [DoIP] Secure TCP (TLS) Listening on [{SERVER_IP_V6}]:{PORT_DOIP} (TLS 1.2 Only)")

        # Accept loop
        while self.running:
            try:
                raw_conn, addr = tcp.accept()
                print(f"[DoIP] Raw connection from {addr}")

                # DoS protection: acquire a slot before TLS handshake/thread
                if not client_semaphore.acquire(blocking=False):
                    print(f"[!] [DoIP] REJECTED {addr[0]} - Too many connections!")
                    raw_conn.close()
                    continue

                try:
                    # Wrap raw TCP socket in TLS and perform handshake immediately
                    secure_conn = context.wrap_socket(
                        raw_conn,
                        server_side=True
                    )
                    print(
                        f"[+] [DoIP] TLS Handshake SUCCESS with {addr} | {secure_conn.version()} | Cipher: {secure_conn.cipher()}"
                    )

                except ssl.SSLError as ssl_err:
                    # TLS handshake failed: release slot and close
                    print(f"[-] [DoIP] TLS Handshake FAILED with {addr}: {ssl_err}")
                    client_semaphore.release()
                    raw_conn.close()
                    continue

                except Exception as e:
                    # Other wrap/handshake error
                    print(f"[-] [DoIP] Error during TLS wrap: {e}")
                    client_semaphore.release()
                    raw_conn.close()
                    continue

                # Start per-client handler thread using the TLS socket
                threading.Thread(
                    target=self.handle_client,
                    args=(secure_conn, addr),
                    daemon=True
                ).start()

            except Exception as e:
                if self.running:
                    print(f"[DoIP] Accept error: {e}")
                break

        # Cleanup listener socket on exit
        tcp.close()
```
