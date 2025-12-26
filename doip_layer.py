import socket
import struct
import threading
import random
import hmac
import hashlib
import select
import time

# --- Local Imports ---
# doip_utils is expected to provide:
# - DoIP payload type constants (TYPE_*)
# - parse_header() to decode DoIP header fields
# - create_header() to build DoIP headers
from doip_utils import *
# S3Timer is a session timeout helper (UDS S3 server timer behavior)
from s3_timer import S3Timer

# ==========================================
#               DoIP CONFIGURATION (IPv6)
# ==========================================
# IPv6 bind address:
# - '::' means listen on all IPv6 interfaces on the host
SERVER_IP_V6 = '::'  # Listen on all IPv6 interfaces

# DoIP standard port is commonly 13400 (your lab uses 13400)
PORT_DOIP = 13400

# (Optional) Trusted tester IPv6 address for your lab topology
# NOTE: In THIS script, TRUSTED_IP_V6 is defined but not used for enforcement.
TRUSTED_IP_V6 = 'fd00::40'  # The IPv6 address of Node A (Tester)

# --- REALISTIC ECU LIMITS (DoS Protection) ---
# Limit concurrent TCP clients. Extra connections get rejected immediately.
MAX_CLIENTS = 5
client_semaphore = threading.Semaphore(MAX_CLIENTS)

# --- CONFIG ---
# VIN returned in ReadDataByIdentifier (0x22 F190) and discovery response
VIN = b'TESTVIN1234567890'

# ECU logical address used in DoIP diagnostic framing (source/target LA fields)
LOGICAL_ADDR = 0x1000

# Expected tester logical address (the tester must request this LA in routing activation)
TESTER_ADDR = 0x0E50

# Entity ID and Group ID used in DoIP discovery response payload
EID = b'\x00\x00\x00\x00\x00\x01'
GID = b'\x00\x00\x00\x00\x00\x00'

# ==========================================
#               SECURITY CONFIG
# ==========================================
# PROTECTED_MODE:
# - False: seed->key is XOR-based (seed XOR CONSTANT)
# - True : seed->key uses HMAC-SHA256(SECRET_KEY, seed) truncated to 4 bytes
PROTECTED_MODE = False

# MITM_PROTECTION:
# - False: normal flow, security access grants "access_flag"
# - True : ECU issues a session token after successful key, and requires it for some operations
MITM_PROTECTION = False

# HMAC secret key used only if PROTECTED_MODE=True
SECRET_KEY = b"\x93\x11\xfa\x22\x8b"

# XOR constant used only if PROTECTED_MODE=False
CONSTANT = b"\x11\x22\x33\x44"

# Static session token returned when MITM_PROTECTION=True after SecurityAccess success
SESSION_TOKEN_STATIC = b"\xAA\xBB\xCC\xDD"

# Seed range (simulates ECU seed generation bounds)
SEED_MIN = 0x00001000
SEED_MAX = 0x00001FFF

# ==========================================
#               DoIP LOGIC (Class)
# ==========================================
class DoIPECU:
    def __init__(self):
        # Global run flag for the UDP discovery server loop
        self.running = True

        # Access state:
        # - 0 = locked
        # - 1 = unlocked (after successful SecurityAccess 0x27)
        self.access_flag = 0

        # UDS session:
        # - 0x01 = Default session
        # - 0x02 = Programming session (example)
        # - 0x03 = Extended session (example)
        self.session = 0x01

        # Stores the last generated seed (for SecurityAccess 0x27)
        self.current_seed = None

        # Session token used when MITM_PROTECTION=True
        self.session_token = None

        # Example "programmable data" returned by DID 0xF1A0 and updated via 0x2E F1A0
        self.program_data = b"\x10\x20\x30\x40"

        # Routine results cache keyed by RID
        self.routine_results = {}

        # Tester logical address used for DoIP diagnostic response framing
        self.tester_la = None

        # S3 session timeout timer:
        # - starts when entering a non-default session (0x02/0x03)
        # - resets on TesterPresent (0x3E) in those sessions
        # - expiration returns ECU to Default session and clears routine state
        self.s3 = S3Timer(lambda: None, self.s3_expired, s3_timeout=5.0)

    def s3_expired(self):
        # Called by S3Timer when inactivity timer expires in non-default session
        print("\n[DoIP][S3Timer] EXPIRED -> Resetting Session to Default Only")
        self.session = 0x01
        self.routine_results.clear()
        self.s3.stop()

    def seed_to_key(self, seed):
        # Convert seed bytes to key bytes (4 bytes) based on selected security mode
        if not PROTECTED_MODE:
            # Simple XOR-based key derivation (lab / weak security)
            c = int.from_bytes(CONSTANT, "big")
            s = int.from_bytes(seed, "big")
            return (s ^ c).to_bytes(4, "big")
        else:
            # HMAC-based key derivation (stronger lab mode)
            return hmac.new(SECRET_KEY, seed, hashlib.sha256).digest()[:4]

    def process_request(self, req):
        # This processes UDS payload (NOT DoIP framing)
        # Input: req = raw UDS bytes (SID + params)
        # Output: UDS response bytes OR None (if response suppressed)
        if len(req) == 0:
            # 0x13 = IncorrectMessageLengthOrInvalidFormat
            return b'\x7F\x00\x13'

        sid = req[0]

        # ----------------------------------------------------------
        # 0x10 DIAGNOSTIC SESSION CONTROL
        # ----------------------------------------------------------
        if sid == 0x10:
            if len(req) < 2:
                return b'\x7F\x10\x13'
            sub = req[1]

            # Default session
            if sub == 0x01:
                self.session = 0x01
                self.s3.stop()
                return b'\x50\x01'

            # Example: Programming or Extended session
            elif sub in (0x02, 0x03):
                # Require unlocked access
                if self.access_flag != 1:
                    # 0x33 = SecurityAccessDenied
                    return b'\x7F\x10\x33'

                # Optional token check when MITM_PROTECTION enabled
                if MITM_PROTECTION:
                    # Expect token in req[2:6]
                    if len(req) < 6 or req[2:6] != self.session_token:
                        return b'\x7F\x10\x33'

                self.session = sub
                self.s3.start()
                print(f"[DoIP][S3Timer] Started (Session 0x{sub:02X})")
                return bytes([0x50, sub])

            # 0x12 = SubFunctionNotSupported
            return b'\x7F\x10\x12'

        # ----------------------------------------------------------
        # 0x11 ECU RESET
        # ----------------------------------------------------------
        elif sid == 0x11:
            # Require unlocked access
            if self.access_flag != 1:
                return b'\x7F\x11\x33'

            if len(req) < 2:
                return b'\x7F\x11\x13'

            sub = req[1]

            # 0x01 = HardReset (example), 0x03 = SoftReset (example)
            if sub in (0x01, 0x03):
                # Reset state to initial
                self.access_flag = 0
                self.session = 0x01
                self.session_token = None
                self.routine_results.clear()
                self.s3.stop()
                print("[DoIP][S3Timer] Stopped (ECU Reset)")
                return bytes([0x51, sub])

            return b'\x7F\x11\x12'

        # ----------------------------------------------------------
        # 0x22 READ DATA BY IDENTIFIER
        # ----------------------------------------------------------
        elif sid == 0x22:
            if len(req) < 3:
                return b'\x7F\x22\x13'

            did = (req[1] << 8) | req[2]

            # DID 0xF190 = VIN (restricted to non-default sessions here)
            if did == 0xF190:
                if self.session not in (0x02, 0x03):
                    return b'\x7F\x22\x33'
                return b'\x62\xF1\x90' + VIN

            # DID 0xF1A0 = program data (allowed in any session here)
            if did == 0xF1A0:
                return b'\x62\xF1\xA0' + self.program_data

            # 0x31 = RequestOutOfRange
            return b'\x7F\x22\x31'

        # ----------------------------------------------------------
        # 0x27 SECURITY ACCESS
        # ----------------------------------------------------------
        elif sid == 0x27:
            if len(req) < 2:
                return b'\x7F\x27\x13'

            sub = req[1]

            # Sub-function 0x01: request seed
            if sub == 0x01:
                val = random.randint(SEED_MIN, SEED_MAX)
                self.current_seed = val.to_bytes(4, 'big')
                # Clear token until successfully unlocked again
                self.session_token = None
                return b'\x67\x01' + self.current_seed

            # Sub-function 0x02: send key
            elif sub == 0x02:
                if not self.current_seed:
                    # 0x22 = ConditionsNotCorrect (used here when seed not requested)
                    return b'\x7F\x27\x22'

                if len(req) < 6:
                    return b'\x7F\x27\x13'

                # Validate key: req[2:6]
                if req[2:6] == self.seed_to_key(self.current_seed):
                    self.access_flag = 1
                    self.current_seed = None

                    # Optionally return token when MITM_PROTECTION enabled
                    if MITM_PROTECTION:
                        self.session_token = SESSION_TOKEN_STATIC
                        return b'\x67\x02' + self.session_token

                    return b'\x67\x02'

                # Invalid key
                self.access_flag = 0
                return b'\x7F\x27\x35'

        # ----------------------------------------------------------
        # 0x2E WRITE DATA BY IDENTIFIER
        # ----------------------------------------------------------
        elif sid == 0x2E:
            # Require unlocked access
            if self.access_flag != 1:
                return b'\x7F\x2E\x33'

            if len(req) < 4:
                return b'\x7F\x2E\x13'

            did = (req[1] << 8) | req[2]

            # DID 0xF1A0: write program data (restricted to non-default sessions here)
            if did == 0xF1A0:
                if self.session not in (0x02, 0x03):
                    return b'\x7F\x2E\x31'
                self.program_data = req[3:]
                return b'\x6E\xF1\xA0'

            return b'\x7F\x2E\x31'

        # ----------------------------------------------------------
        # 0x31 ROUTINE CONTROL
        # ----------------------------------------------------------
        elif sid == 0x31:
            if len(req) < 4:
                return b'\x7F\x31\x13'

            sub = req[1]
            rid = (req[2] << 8) | req[3]

            # RID 0x1234: "Self Test" example routine
            if rid == 0x1234:
                # StartRoutine
                if sub == 0x01:
                    # Cache a fake result to be read later
                    self.routine_results[rid] = b'\x0B\xB8\x50\x00'
                    return b'\x71\x01\x12\x34\x00'
                # RequestRoutineResults
                elif sub == 0x03:
                    if rid not in self.routine_results:
                        return b'\x7F\x31\x22'
                    return b'\x71\x03\x12\x34' + self.routine_results[rid]

            # RID 0x1390: "Checksum" example routine (restricted to non-default sessions here)
            elif rid == 0x1390:
                if self.session not in (0x02, 0x03):
                    # 0x7E = SubFunctionNotSupportedInActiveSession (used here)
                    return b'\x7F\x31\x7E'
                # StartRoutine
                if sub == 0x01:
                    self.routine_results[rid] = b'\xDE\xAD\xBE\xEF\x00'
                    # NOTE: This response uses 0x14 0x56 in payload as in your original code
                    return b'\x71\x01\x14\x56\x00'
                # RequestRoutineResults
                elif sub == 0x03:
                    if rid not in self.routine_results:
                        return b'\x7F\x31\x22'
                    return b'\x71\x03\x14\x56' + self.routine_results[rid]

            # 0x31 = RequestOutOfRange (used here as default for unsupported RID)
            return b'\x7F\x31\x31'

        # ----------------------------------------------------------
        # 0x3E TESTER PRESENT
        # ----------------------------------------------------------
        elif sid == 0x3E:
            if len(req) < 2:
                return b'\x7F\x3E\x13'

            sub = req[1]

            # Suppress response bit is bit7 of subfunction byte
            suppress = (sub & 0x80) == 0x80

            # In non-default session, reset S3 timer on TesterPresent
            if self.session in (0x02, 0x03):
                self.s3.reset()
                print("[DoIP][S3Timer] Timer Reset (TesterPresent)")

            # If suppress bit is NOT set, ECU replies with positive response (0x7E)
            if not suppress:
                return bytes([0x7E, sub & 0x7F])
            else:
                # Suppress response: return None so sender does not transmit DoIP diag ack
                return None

        # ----------------------------------------------------------
        # Default: ServiceNotSupported (0x11)
        # ----------------------------------------------------------
        return b'\x7F' + bytes([sid]) + b'\x11'

    def udp_server(self):
        # UDP server for DoIP Vehicle Identification Requests (discovery)
        # Uses IPv6 UDP socket bound on PORT_DOIP.
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((SERVER_IP_V6, PORT_DOIP))
        print(f"[*] [DoIP] UDP Listening on IPv6 {SERVER_IP_V6}:{PORT_DOIP}")

        while self.running:
            try:
                data, addr = sock.recvfrom(1024)

                # parse_header is expected to return (payload_type, payload_length, protocol_version_info/other)
                p_type, _, _ = parse_header(data)

                # If tester sends Vehicle ID Request, ECU responds with Vehicle ID Response
                if p_type == TYPE_VEHICLE_ID_REQ:
                    # Payload format (lab):
                    # VIN (17 bytes here) + Logical Address (2 bytes) + EID (6) + GID (6) + reserved (2)
                    payload = VIN + struct.pack('!H', LOGICAL_ADDR) + EID + GID + b'\x00\x00'
                    header = create_header(TYPE_VEHICLE_ID_RES, len(payload))
                    sock.sendto(header + payload, addr)
                    print(f"[DoIP] Sent Vehicle ID to {addr}")
            except:
                # Keep server alive even on transient socket/parse errors
                pass

    def handle_client(self, conn, addr):
        # Handles one TCP client session (DoIP diagnostic channel).
        # DoS Protection:
        # - client_semaphore is acquired before thread creation in start()
        # - released in finally block below
        print(
            f"[*] [TCP] Client {addr[0]} Connected. Active: {MAX_CLIENTS - client_semaphore._value + 1}/{MAX_CLIENTS}"
        )

        # Routing Activation state; must be True before diagnostics are accepted
        authenticated = False

        try:
            while True:
                # DoIP messages start with an 8-byte header
                header = conn.recv(8)
                if not header:
                    break

                # Decode header to determine message type and payload length
                p_type, p_len, _ = parse_header(header)

                # Read payload based on advertised length
                payload = conn.recv(p_len)

                # ----------------------------------------------------------
                # ROUTING ACTIVATION REQUEST
                # ----------------------------------------------------------
                if p_type == TYPE_ROUTING_ACTIVATION_REQ:
                    # Expect at least 7 bytes based on your lab format
                    if len(payload) < 7:
                        res_code = 0x01  # Invalid format
                    else:
                        # First 2 bytes: requested tester logical address
                        la = struct.unpack('!H', payload[:2])[0]

                        # Accept only if it matches configured TESTER_ADDR
                        if la == TESTER_ADDR:
                            res_code = 0x10  # Success
                            authenticated = True
                            self.tester_la = la
                            print(f"[+] Trusted client activated: {addr[0]} (LA=0x{la:04X})")
                        else:
                            res_code = 0x06  # Unknown source address
                            print(f"[-] Rejected unknown LA 0x{la:04X} from {addr[0]}")

                    # Response payload (9 bytes total in this implementation):
                    # - Echo tester LA (2)
                    # - ECU logical address / OEM specific (2)
                    # - Response code (1)
                    # - Reserved (4)
                    response_payload = (
                        struct.pack('!H', la) +
                        struct.pack('!H', LOGICAL_ADDR) +
                        bytes([res_code]) +
                        b'\x00\x00\x00\x00'
                    )

                    # Send routing activation response
                    conn.send(create_header(TYPE_ROUTING_ACTIVATION_RES, len(response_payload)) + response_payload)

                # ----------------------------------------------------------
                # DIAGNOSTIC MESSAGE (UDS over DoIP)
                # ----------------------------------------------------------
                elif p_type == TYPE_DIAGNOSTIC_MESSAGE:
                    # Block diagnostics until routing activation succeeded
                    if not authenticated:
                        conn.close()
                        break

                    # Diagnostic payload format (lab):
                    # First 4 bytes = (source LA, target LA) then UDS bytes after that
                    uds_req = payload[4:]
                    print(f"[RX] UDS Req: {uds_req.hex().upper()}")

                    # Process UDS and build response
                    uds_res = self.process_request(uds_req)

                    # If uds_res is None => suppress response (TesterPresent suppress bit)
                    if uds_res is not None:
                        # Build DoIP diagnostic positive ack payload:
                        # ECU LA + tester LA + UDS response
                        full = struct.pack('!HH', LOGICAL_ADDR, self.tester_la) + uds_res
                        conn.send(create_header(TYPE_DIAGNOSTIC_POS_ACK, len(full)) + full)
                        print(f"[TX] UDS Res: {uds_res.hex().upper()}")

                # ----------------------------------------------------------
                # NOTE:
                # The following block is a duplicate "elif p_type == TYPE_DIAGNOSTIC_MESSAGE"
                # and is unreachable due to the prior elif with the same condition.
                # Kept as-is per your requirement (no code removal/change).
                # ----------------------------------------------------------
                elif p_type == TYPE_DIAGNOSTIC_MESSAGE:
                    if not authenticated:
                        conn.close()
                        break
                    uds_res = self.process_request(payload[4:])
                    # Only send if response is not None (handles Suppress Bit)
                    if uds_res:
                        full = struct.pack('!HH', LOGICAL_ADDR, self.tester_la) + uds_res
                        conn.send(create_header(TYPE_DIAGNOSTIC_POS_ACK, len(full)) + full)
                        print(f"[TX] UDS Res: {uds_res.hex().upper()}")

        except:
            # Keep thread from crashing the server on unexpected client/socket errors
            pass
        finally:
            conn.close()
            client_semaphore.release()  # DoS Protection: Release slot
            print(f"[-] [TCP] Client {addr[0]} Disconnected")

    def start(self):
        # Start UDP discovery server in a background daemon thread
        threading.Thread(target=self.udp_server, daemon=True).start()

        # Start TCP server for DoIP diagnostics (IPv6)
        tcp = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp.bind((SERVER_IP_V6, PORT_DOIP))
        tcp.listen(5)
        print(f"[*] [DoIP] TCP Listening on IPv6 {SERVER_IP_V6}:{PORT_DOIP} (Max Clients: {MAX_CLIENTS})")

        while True:
            # Accept incoming TCP client
            c, a = tcp.accept()

            # DoS Protection:
            # Acquire a slot BEFORE starting a thread.
            # If no slot is available, reject connection immediately.
            if client_semaphore.acquire(blocking=False):
                threading.Thread(target=self.handle_client, args=(c, a), daemon=True).start()
            else:
                print(f"[!] [DoIP] REJECTED {a[0]} - Too many connections!")
                c.close()
