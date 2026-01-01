from dataclasses import dataclass
from someipy.serialization import SomeIpPayload, Uint8, Sint16
import time, struct
import threading
from typing import Callable, Optional

# --- Network Configuration ---
# SOME/IP Service Discovery (SD) uses multicast to announce and discover services.
# All ECUs participating in SD must use the same group/port.
SD_MULTICAST_GROUP = "224.224.224.245"  # SOME/IP-SD multicast group (IPv4)
SD_PORT = 30490                         # SOME/IP-SD UDP port (standard)

# ECU IPv4 addresses used inside the simulated network namespaces / veth topology.
# These must match the addresses assigned by your network setup script.
MIRROR_ECU_IP = "192.168.42.10"   # Main/Mirror ECU endpoint (service provider)
BUTTONS_ECU_IP = "192.168.42.20"  # Buttons ECU endpoint (HMI publisher/client)


# --- Service IDs ---
# Service ID identifies the logical function (what service is offered).
# Instance ID distinguishes multiple instances of the same service.
MIRROR_SERVICE_ID = 0x1000     # Mirror / Zonal Gateway service ID
MIRROR_INSTANCE_ID = 0x0001    # Mirror service instance ID

BUTTON_SERVICE_ID = 0x2000     # Buttons/HMI service ID
BUTTON_INSTANCE_ID = 0x0001    # Buttons service instance ID


# --- Event/Method IDs ---
# Method IDs are used for request/response RPC calls.
# Event IDs are notifications published by servers to subscribers.
# Event Group IDs allow subscribing to a group of events as one unit.

# RPC method to request the Main ECU to reset the mirror position/state.
METHOD_ID_RESET_MIRROR = 0x0100

# RPC method to request current mirror coordinates (request/response).
# Used by Buttons ECU via Ctrl+P to fetch X/Y from the Main ECU.
METHOD_ID_GET_POSITION = 0x0101  # <--- NEW METHOD ID

# Blind spot warnings are published as events by the Main/Mirror ECU.
EVENT_GROUP_BLIND_SPOT = 0x8000  # Event group used to subscribe/unsubscribe
EVENT_ID_BLIND_SPOT = 0x8001     # Event ID for Blind Spot Warning notifications

# Button press actions are published by Buttons ECU as events.
EVENT_GROUP_BUTTONS = 0x9000     # Event group for button press events
EVENT_ID_BUTTON_PRESS = 0x9001   # Event ID for Button Press events

# ==========================================
#              DoIP CONSTANTS
# ==========================================
# DoIP protocol version (ISO 13400 header fields)
PROTOCOL_VER = 0x02

# Inverse protocol version (must be bitwise inverse of PROTOCOL_VER for validity checks)
# For 0x02 -> inverse is 0xFD (0xFF - 0x02)
INV_PROT_VER = 0xFD

# ==========================================
#              DoIP PAYLOAD TYPES
# ==========================================
# 0x0001: Vehicle Identification Request (UDP discovery request)
TYPE_VEHICLE_ID_REQ = 0x0001

# 0x0004: Vehicle Identification Response (UDP discovery response)
TYPE_VEHICLE_ID_RES = 0x0004

# 0x0005: Routing Activation Request (TCP control message before diagnostics)
TYPE_ROUTING_ACTIVATION_REQ = 0x0005

# 0x0006: Routing Activation Response (TCP reply to activation)
TYPE_ROUTING_ACTIVATION_RES = 0x0006

# 0x8001: Diagnostic Message (UDS over DoIP payload wrapper)
TYPE_DIAGNOSTIC_MESSAGE = 0x8001

# 0x8002: Diagnostic Positive Acknowledgement (DoIP-level ACK)
TYPE_DIAGNOSTIC_POS_ACK = 0x8002

# --- Payload Definitions ---
# Payload classes define the binary format of SOME/IP messages.
# They are shared between sender and receiver to guarantee consistent encoding.

@dataclass
class ButtonEventPayload(SomeIpPayload):
    # Encodes a button direction command.
    # direction mapping:
    #   0 = Up, 1 = Right, 2 = Down, 3 = Left
    direction: Uint8

    def __init__(self, direction=0):
        # Uint8 ensures the serialized payload is exactly 1 byte (0..255).
        self.direction = Uint8(direction)


@dataclass
class BlindSpotPayload(SomeIpPayload):
    # Encodes blind spot warning level.
    # Larger values indicate higher severity (your UI prints "!!" or "!!!").
    warning_level: Uint8

    def __init__(self, level=0):
        # Uint8 ensures the serialized payload is exactly 1 byte.
        self.warning_level = Uint8(level)


# <--- NEW PAYLOAD CLASS
@dataclass
class PositionPayload(SomeIpPayload):
    # Encodes mirror position coordinates.
    # Signed 16-bit values allow negative and positive coordinates.
    x: Sint16
    y: Sint16

    def __init__(self, x=0, y=0):
        # Sint16 ensures each coordinate is 2 bytes, signed range: -32768..32767.
        self.x = Sint16(x)
        self.y = Sint16(y)

#Timer Class


class S3Timer:
    def __init__(
        self,
        send_tester_present_cb: Callable[[], None],
        expiry_callback: Callable[[], None],
        s3_timeout: float = 5.0,
        auto_tp: bool = False,
        tp_lead: float = 1.0,
    ):
        self.s3_timeout = s3_timeout
        self.auto_tp = auto_tp
        self.tp_lead = tp_lead
        self._send_tp = send_tester_present_cb
        self._expiry_cb = expiry_callback
        self._lock = threading.Lock()
        self._last_activity = 0.0
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def start(self) -> None:
        with self._lock:
            self._last_activity = time.time()
            if self._running: return
            self._running = True
            self._stop_event.clear()
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()

    def stop(self) -> None:
        with self._lock:
            self._running = False
            self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=0.5)

    def reset(self) -> None:
        with self._lock:
            self._last_activity = time.time()

    def _run(self) -> None:
        check_interval = min(0.2, max(0.05, self.s3_timeout / 30.0))
        while not self._stop_event.is_set():
            with self._lock:
                if not self._running: break
                now = time.time()
                elapsed = now - self._last_activity
                do_expire = elapsed >= self.s3_timeout

            if do_expire:
                with self._lock:
                    self._running = False
                    self._stop_event.set()
                try:
                    self._expiry_cb()
                except: pass
                return
            
            self._stop_event.wait(timeout=check_interval)

# ==========================================
#           DoIP HEADER BUILDING
# ==========================================
def create_header(payload_type, payload_length):
    # Builds the standard 8-byte DoIP header:
    # Byte 0: protocol version
    # Byte 1: inverse protocol version
    # Bytes 2-3: payload type (uint16, big-endian)
    # Bytes 4-7: payload length (uint32, big-endian)
    #
    # '!BBHL' means:
    # !  -> network byte order (big-endian)
    # B  -> uint8  (protocol version)
    # B  -> uint8  (inverse protocol version)
    # H  -> uint16 (payload type)
    # L  -> uint32 (payload length)
    return struct.pack('!BBHL', PROTOCOL_VER, INV_PROT_VER, payload_type, payload_length)


# ==========================================
#           DoIP HEADER PARSING
# ==========================================
def parse_header(data):
    # Extracts DoIP header fields from a raw byte buffer.
    #
    # Returns:
    # - p_type: payload type (uint16)
    # - p_len : payload length (uint32)
    # - rest  : remaining bytes after the 8-byte header
    #
    # If buffer is shorter than 8 bytes:
    # - returns (None, None, data) so caller can treat it as incomplete/invalid.
    if len(data) < 8:
        return None, None, data

    ver, inv_ver, p_type, p_len = struct.unpack('!BBHL', data[:8])

    # NOTE: This function does not validate (ver, inv_ver). If you need strict checks:
    # - ver must equal PROTOCOL_VER
    # - inv_ver must equal INV_PROT_VER
    # Keeping logic unchanged as requested.

    return p_type, p_len, data[8:]


# ==========================================
#       VEHICLE ANNOUNCEMENT PARSING
# ==========================================
def parse_vehicle_announcement(payload):
    # Parses the payload of a Vehicle Identification Response in your lab format.
    #
    # Expected layout (based on your ECU code):
    # - VIN         : 17 bytes (ASCII)
    # - LogicalAddr : 2 bytes  (uint16 BE)
    # - EID         : 6 bytes
    # - GID         : 6 bytes
    # Total (minimum) = 17 + 2 + 6 + 6 = 31 bytes
    #
    # NOTE: Your length check uses 33, which assumes extra bytes exist (e.g., reserved bytes).
    # Keeping this as-is per your requirement.

    if len(payload) < 33:
        return None

    # VIN is fixed-length 17 bytes
    vin = payload[0:17].decode()

    # Logical address is 2 bytes big-endian
    logical_addr = struct.unpack('!H', payload[17:19])[0]

    # Entity ID (6 bytes)
    eid = payload[19:25]

    # Group ID (6 bytes)
    gid = payload[25:31]

    # Return a dict with decoded/normalized values
    return {
        "vin": vin,
        "logical_addr": logical_addr,
        "eid": eid.hex(),
        "gid": gid.hex()
    }
