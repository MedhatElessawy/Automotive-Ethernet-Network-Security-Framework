import struct

PROTOCOL_VER = 0x02
INV_PROT_VER = 0xFD
TYPE_VEHICLE_ID_REQ = 0x0001
TYPE_VEHICLE_ID_RES = 0x0004
TYPE_ROUTING_ACTIVATIO```python
import struct

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
```
N_REQ = 0x0005
TYPE_ROUTING_ACTIVATION_RES = 0x0006
TYPE_DIAGNOSTIC_MESSAGE = 0x8001
TYPE_DIAGNOSTIC_POS_ACK = 0x8002

def create_header(payload_type, payload_length):
    return struct.pack('!BBHL', PROTOCOL_VER, INV_PROT_VER, payload_type, payload_length)

def parse_header(data):
    if len(data) < 8: return None, None, data
    ver, inv_ver, p_type, p_len = struct.unpack('!BBHL', data[:8])
    return p_type, p_len, data[8:]

def parse_vehicle_announcement(payload):
    if len(payload) < 33: return None
    vin = payload[0:17].decode()
    logical_addr = struct.unpack('!H', payload[17:19])[0]
    eid = payload[19:25]
    gid = payload[25:31]
    return {"vin": vin, "logical_addr": logical_addr, "eid": eid.hex(), "gid": gid.hex()}
