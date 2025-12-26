import struct

PROTOCOL_VER = 0x02
INV_PROT_VER = 0xFD
TYPE_VEHICLE_ID_REQ = 0x0001
TYPE_VEHICLE_ID_RES = 0x0004
TYPE_ROUTING_ACTIVATION_REQ = 0x0005
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