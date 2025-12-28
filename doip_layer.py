import socket
import struct
import threading
import random
import hmac
import hashlib
import select
import time

# --- Local Imports ---
# Ensure these files (doip_utils.py, s3_timer.py) are in the same directory
from doip_utils import *
from s3_timer import S3Timer

# ==============================================================================
#                               CONFIGURATION SECTION
#             Adjust these values to change ECU behavior and Security
# ==============================================================================

# --- NETWORK CONFIGURATION (IPv6) ---
SERVER_IP_V6 = '::'         # '::' binds to all available IPv6 interfaces on the machine
PORT_DOIP = 13400           # Standard TCP/UDP port for DoIP (ISO 13400)
TRUSTED_IP_V6 = 'fd00::40'  # The only IP allowed if IP_PROTECTION is set to True

# --- DOS PROTECTION ---
MAX_CLIENTS = 5             # Maximum number of simultaneous TCP connections allowed
client_semaphore = threading.Semaphore(MAX_CLIENTS) # Thread-safe counter to enforce the limit

# --- ECU IDENTITY ---
VIN = b'TESTVIN1234567890'       # Vehicle Identification Number (17 bytes)
LOGICAL_ADDR = 0x1000            # The Logical Address of this ECU
TESTER_ADDR = 0x0E50             # The expected Logical Address of the Tester (Client)
EID = b'\x00\x00\x00\x00\x00\x01' # Entity Identification (Unique MAC/ID for DoIP)
GID = b'\x00\x00\x00\x00\x00\x00' # Group Identification (for multicast, usually 0)

# --- SECURITY FLAGS & KEYS ---
# Set IP_PROTECTION = True to block any IP that isn't TRUSTED_IP_V6
IP_PROTECTION = False

# Set PROTECTED_MODE = True to use HMAC-SHA256 for key generation (False uses simple XOR)
PROTECTED_MODE = False

# Set MITM_PROTECTION = True to require a Session Token during session changes
MITM_PROTECTION = False

# Cryptographic Keys
SECRET_KEY = b"\x93\x11\xfa\x22\x8b"     # Key used for HMAC generation in Protected Mode
CONSTANT = b"\x11\x22\x33\x44"           # Constant used for XOR calculation in Legacy Mode
SESSION_TOKEN_STATIC = b"\xAA\xBB\xCC\xDD" # The token expected if MITM_PROTECTION is active

# Seed Generation Range (2 bytes)
SEED_MIN = 0x00001000
SEED_MAX = 0x00001FFF

# --- LOCKOUT CONFIGURATION ---
LOCKOUT_PROTECTION = True   # If True, ECU locks after MAX_ERROR_COUNT failed attempts
MAX_ERROR_COUNT = 3         # Number of allowed failed attempts before lockout
LOCKOUT_SECONDS = 30        # Duration (in seconds) the ECU refuses security access after lockout

# ==============================================================================
#                                   DoIP ECU LOGIC
# ==============================================================================
class DoIPECU:
    def __init__(self):
        self.running = True
        
        # UDS State Variables
        self.access_flag = 0        # 0 = Locked, 1 = Unlocked (Security Access granted)
        self.session = 0x01         # Current Diagnostic Session (0x01 = Default)
        self.current_seed = None    # Stores the seed generated for the current challenge
        self.session_token = None   # Stores the token (if MITM protection is used)
        self.program_data = b"\x10\x20\x30\x40" # Fake storage for "flashed" data
        self.routine_results = {}   # Stores results of Routine Controls
        self.tester_la = None       # Stores the Logical Address of the currently connected tester
        
        # S3 Timer handles session timeout (reverts to default session if idle)
        self.s3 = S3Timer(lambda: None, self.s3_expired, s3_timeout=5.0)

        # Lockout State Variables
        self.lockout_until = 0.0    # Timestamp when lockout expires
        self.error_num = 0          # Counter for failed security attempts

    def s3_expired(self):
        """Callback when the S3 timer runs out (Tester stopped sending messages)."""
        print("\n[DoIP][S3Timer] EXPIRED -> Resetting Session to Default Only")
        self.session = 0x01
        self.routine_results.clear()
        self.s3.stop()

    def seed_to_key(self, seed):
        """Generates the expected Key from a given Seed based on the mode."""
        if not PROTECTED_MODE:
            # Simple Mode: XOR Seed with Constant
            c = int.from_bytes(CONSTANT, "big")
            s = int.from_bytes(seed, "big")
            return (s ^ c).to_bytes(4, "big")
        else:
            # Protected Mode: HMAC-SHA256
            return hmac.new(SECRET_KEY, seed, hashlib.sha256).digest()[:4]

    def process_request(self, req):
        """Parses and processes raw UDS bytes (SID + Data). Returns response bytes."""
        if len(req) == 0: return b'\x7F\x00\x13' # NRC: Incorrect Message Length
        sid = req[0] # Service ID

        # ---------------------------------------------------------
        # SID 0x10: Diagnostic Session Control
        # ---------------------------------------------------------
        if sid == 0x10:
            if len(req) < 2: return b'\x7F\x10\x13'
            sub = req[1]
            
            # 0x01: Default Session (always allowed, resets timers)
            if sub == 0x01:
                self.session = 0x01
                self.s3.stop()
                return b'\x50\x01'
            
            # 0x02 (Programming) / 0x03 (Extended)
            elif sub in (0x02, 0x03):
                # Security Check: Must be unlocked
                if self.access_flag != 1: return b'\x7F\x10\x33' # NRC: Security Access Denied
                
                # MITM Check: Must provide session token if enabled
                if MITM_PROTECTION:
                    if len(req) < 6 or req[2:6] != self.session_token: return b'\x7F\x10\x33'
                
                # Success: Switch session and start S3 timer
                self.session = sub
                self.s3.start()
                print(f"[DoIP][S3Timer] Started (Session 0x{sub:02X})")
                return bytes([0x50, sub])
            return b'\x7F\x10\x12' # NRC: Sub-function not supported

        # ---------------------------------------------------------
        # SID 0x11: ECU Reset
        # ---------------------------------------------------------
        elif sid == 0x11:
            if self.access_flag != 1: return b'\x7F\x11\x33' # Requires Security Access
            if len(req) < 2: return b'\x7F\x11\x13'
            sub = req[1]
            
            # 0x01 (Hard) / 0x03 (Soft) Reset
            if sub in (0x01, 0x03):
                # Full Reset of ECU State
                self.access_flag = 0
                self.session = 0x01
                self.session_token = None
                self.routine_results.clear()
                self.s3.stop()

                # Reset Lockout State
                self.error_num = 0
                self.lockout_until = 0.0

                print("[DoIP][S3Timer] Stopped (ECU Reset)")
                return bytes([0x51, sub])
            return b'\x7F\x11\x12'

        # ---------------------------------------------------------
        # SID 0x22: Read Data By Identifier (DID)
        # ---------------------------------------------------------
        elif sid == 0x22:
            if len(req) < 3: return b'\x7F\x22\x13'
            did = (req[1] << 8) | req[2]
            
            # DID F190: Read VIN (Requires Non-Default Session)
            if did == 0xF190:
                if self.session not in (0x02, 0x03): return b'\x7F\x22\x33'
                return b'\x62\xF1\x90' + VIN
            
            # DID F1A0: Read Program Data
            if did == 0xF1A0: return b'\x62\xF1\xA0' + self.program_data
            return b'\x7F\x22\x31' # NRC: Request Out of Range

        # ---------------------------------------------------------
        # SID 0x27: Security Access
        # ---------------------------------------------------------
        elif sid == 0x27:
            if len(req) < 2: return b'\x7F\x27\x13'

            # --- LOCKOUT CHECK ---
            current_time = time.time()
            if LOCKOUT_PROTECTION:
                # If lockout is active (time hasn't passed)
                if current_time < self.lockout_until:
                    # Silent rejection (no print) to avoid log spam
                    return b'\x7F\x27\x37' # NRC: Required Time Delay Not Expired
                
                # If lockout JUST finished
                elif self.lockout_until > 0:
                    print(f"[DoIP] Lockout FINISHED at {time.ctime(current_time)}. Access restored.")
                    self.lockout_until = 0.0
                    self.error_num = 0

            sub = req[1]
            
            # Sub 0x01: Request Seed
            if sub == 0x01:
                val = random.randint(SEED_MIN, SEED_MAX)
                self.current_seed = val.to_bytes(4, 'big')
                self.session_token = None
                return b'\x67\x01' + self.current_seed
            
            # Sub 0x02: Send Key
            elif sub == 0x02:
                if not self.current_seed: return b'\x7F\x27\x22' # Conditions not correct (no seed requested)
                if len(req) < 6: return b'\x7F\x27\x13'

                # Validate Key
                if req[2:6] == self.seed_to_key(self.current_seed):
                    self.access_flag = 1
                    self.current_seed = None
                    self.error_num = 0 # Reset error counter on success

                    if MITM_PROTECTION:
                        self.session_token = SESSION_TOKEN_STATIC
                        return b'\x67\x02' + self.session_token
                    return b'\x67\x02'

                # --- KEY FAILURE LOGIC ---
                self.access_flag = 0
                if LOCKOUT_PROTECTION:
                    if self.error_num < MAX_ERROR_COUNT - 1:
                        self.error_num += 1
                        print(f"[DoIP] Invalid Key. Attempts: {self.error_num}/{MAX_ERROR_COUNT}")
                        return b'\x7F\x27\x35' # NRC: Invalid Key
                    else:
                        # Max attempts reached -> Trigger Lockout
                        self.error_num = 0
                        self.lockout_until = time.time() + LOCKOUT_SECONDS
                        finish_time = time.ctime(self.lockout_until)
                        print(f"[DoIP] MAX ATTEMPTS REACHED. Locking out for {LOCKOUT_SECONDS}s.")
                        print(f"[DoIP] Lockout will finish at: {finish_time}")
                        
                        # Return specific NRC 0x36. The TCP handler looks for this to disconnect the attacker.
                        return b'\x7F\x27\x36' # NRC: Exceeded Number of Attempts

                return b'\x7F\x27\x35'

        # ---------------------------------------------------------
        # SID 0x2E: Write Data By Identifier
        # ---------------------------------------------------------
        elif sid == 0x2E:
            if self.access_flag != 1: return b'\x7F\x2E\x33'
            if len(req) < 4: return b'\x7F\x2E\x13'
            did = (req[1] << 8) | req[2]
            
            # Write to Program Data (F1A0)
            if did == 0xF1A0:
                if self.session not in (0x02, 0x03): return b'\x7F\x2E\x31'
                self.program_data = req[3:]
                return b'\x6E\xF1\xA0'
            return b'\x7F\x2E\x31'

        # ---------------------------------------------------------
        # SID 0x31: Routine Control
        # ---------------------------------------------------------
        elif sid == 0x31:
            if len(req) < 4: return b'\x7F\x31\x13'
            sub = req[1]
            rid = (req[2] << 8) | req[3]

            if rid == 0x1234:  # Self Test Routine
                if sub == 0x01: # Start
                    self.routine_results[rid] = b'\x0B\xB8\x50\x00'
                    return b'\x71\x01\x12\x34\x00'
                elif sub == 0x03: # Get Results
                    if rid not in self.routine_results: return b'\x7F\x31\x22'
                    return b'\x71\x03\x12\x34' + self.routine_results[rid]
            
            elif rid == 0x1390:  # Checksum Routine
                if self.session not in (0x02, 0x03): return b'\x7F\x31\x7E'
                if sub == 0x01:
                    self.routine_results[rid] = b'\xDE\xAD\xBE\xEF\x00'
                    return b'\x71\x01\x14\x56\x00'
                elif sub == 0x03:
                    if rid not in self.routine_results: return b'\x7F\x31\x22'
                    return b'\x71\x03\x14\x56' + self.routine_results[rid]
            return b'\x7F\x31\x31'

        # ---------------------------------------------------------
        # SID 0x3E: Tester Present
        # ---------------------------------------------------------
        elif sid == 0x3E:
            if len(req) < 2: return b'\x7F\x3E\x13'
            sub = req[1]
            suppress = (sub & 0x80) == 0x80 # Check SuppressPosRspMsgIndication bit

            # Reset S3 timer to keep session alive
            if self.session in (0x02, 0x03):
                self.s3.reset()
                print("[DoIP][S3Timer] Timer Reset (TesterPresent)")

            if not suppress:
                return bytes([0x7E, sub & 0x7F])
            else:
                return None  # Suppress response (do not send anything back)

        return b'\x7F' + bytes([sid]) + b'\x11' # NRC: Service Not Supported

    def udp_server(self):
        """Handles UDP Vehicle Discovery (DoIP Identification Request)."""
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((SERVER_IP_V6, PORT_DOIP))
        print(f"[*] [DoIP] UDP Listening on IPv6 {SERVER_IP_V6}:{PORT_DOIP}")
        while self.running:
            try:
                data, addr = sock.recvfrom(1024)
                p_type, _, _ = parse_header(data)
                
                # If client requests Vehicle ID, respond with VIN, LA, EID, GID
                if p_type == TYPE_VEHICLE_ID_REQ:
                    payload = VIN + struct.pack('!H', LOGICAL_ADDR) + EID + GID + b'\x00\x00'
                    header = create_header(TYPE_VEHICLE_ID_RES, len(payload))
                    sock.sendto(header + payload, addr)
                    print(f"[DoIP] Sent Vehicle ID to {addr}")
            except:
                pass

    def handle_client(self, conn, addr):
        """Handles a single TCP connection (DoIP Session)."""
        print(
            f"[*] [TCP] Client {addr[0]} Connected. Active: {MAX_CLIENTS - client_semaphore._value}/{MAX_CLIENTS}")
        ip = addr[0]
        authenticated = False # Flag to track if Routing Activation was successful
        try:
            while True:
                # Read DoIP Header (8 bytes)
                header = conn.recv(8)
                if not header: break
                p_type, p_len, _ = parse_header(header)
                # Read Payload
                payload = conn.recv(p_len)

                # --- ROUTING ACTIVATION (Handshake) ---
                if p_type == TYPE_ROUTING_ACTIVATION_REQ:
                    if len(payload) < 7:
                        res_code = 0x01 # Invalid format
                    else:
                        la = struct.unpack('!H', payload[:2])[0] # Client's Source Address
                        
                        # VALIDATION: Check Logical Address AND IP Address (if protection enabled)
                        if la == TESTER_ADDR and (not IP_PROTECTION or ip == TRUSTED_IP_V6):
                            res_code = 0x10 # Success
                            authenticated = True
                            self.tester_la = la
                            print(f"[+] Trusted client activated: {addr[0]} (LA=0x{la:04X})")
                        else:
                            res_code = 0x06 # Target Unknown / Access Denied
                            print(f"[-] Rejected unknown LA 0x{la:04X} from {addr[0]}")

                    # Send Routing Activation Response
                    response_payload = (
                            struct.pack('!H', la) +
                            struct.pack('!H', LOGICAL_ADDR) +
                            bytes([res_code]) +
                            b'\x00\x00\x00\x00'
                    )
                    conn.send(create_header(TYPE_ROUTING_ACTIVATION_RES, len(response_payload)) + response_payload)

                # --- DIAGNOSTIC MESSAGE (UDS) ---
                elif p_type == TYPE_DIAGNOSTIC_MESSAGE:
                    if not authenticated: conn.close(); break

                    # Logic to identify if we should process parsing
                    uds_req = payload[4:] # Skip Source/Target Address bytes

                    # Log Spam Prevention: Don't print RX if already locked
                    is_locked = LOCKOUT_PROTECTION and (time.time() < self.lockout_until)
                    if not is_locked:
                        print(f"[RX] UDS Req: {uds_req.hex().upper()}")

                    # Process the UDS Request
                    uds_res = self.process_request(uds_req)

                    if uds_res is not None:
                        # Construct DoIP Diagnostic Message (Source=LogicAddr, Target=TesterLA)
                        full = struct.pack('!HH', LOGICAL_ADDR, self.tester_la) + uds_res
                        conn.send(create_header(TYPE_DIAGNOSTIC_POS_ACK, len(full)) + full)

                        # Log Spam Prevention
                        if not is_locked:
                            print(f"[TX] UDS Res: {uds_res.hex().upper()}")

                        # --- CRITICAL: DISCONNECT ON LOCKOUT ---
                        # If we sent 0x7F 0x27 0x36 (Exceeded Attempts), force disconnect the client.
                        if uds_res == b'\x7F\x27\x36':
                            print("[!] Lockout Triggered. Closing connection to stop attacker.")
                            break

        except Exception as e:
            # print(f"Error: {e}")
            pass
        finally:
            conn.close()
            client_semaphore.release() # Release slot in semaphore for other clients
            print(f"[-] [TCP] Client {addr[0]} Disconnected")

    def start(self):
        """Starts UDP Discovery and TCP Listener threads."""
        threading.Thread(target=self.udp_server, daemon=True).start()

        tcp = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp.bind((SERVER_IP_V6, PORT_DOIP))
        tcp.listen(5)
        print(f"[*] [DoIP] TCP Listening on IPv6 {SERVER_IP_V6}:{PORT_DOIP} (Max Clients: {MAX_CLIENTS})")

        while True:
            c, a = tcp.accept()
            # DoS Protection: Only accept if semaphore slots are available
            if client_semaphore.acquire(blocking=False):
                threading.Thread(target=self.handle_client, args=(c, a), daemon=True).start()
            else:
                print(f"[!] [DoIP] REJECTED {a[0]} - Too many connections!")
                c.close()


if __name__ == "__main__":
    ecu = DoIPECU()
    ecu.start()
