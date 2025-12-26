from dataclasses import dataclass
from someipy.serialization import SomeIpPayload, Uint8, Sint16

# --- Network Configuration ---
SD_MULTICAST_GROUP = "224.224.224.245"
SD_PORT = 30490

# We now define specific IPs for each ECU
MIRROR_ECU_IP = "192.168.42.10"
BUTTONS_ECU_IP = "192.168.42.20"

# --- Service IDs ---
MIRROR_SERVICE_ID = 0x1000
MIRROR_INSTANCE_ID = 0x0001
BUTTON_SERVICE_ID = 0x2000
BUTTON_INSTANCE_ID = 0x0001

# --- Event/Method IDs ---
METHOD_ID_RESET_MIRROR = 0x0100
METHOD_ID_GET_POSITION = 0x0101  # <--- NEW METHOD ID

EVENT_GROUP_BLIND_SPOT = 0x8000
EVENT_ID_BLIND_SPOT = 0x8001

EVENT_GROUP_BUTTONS = 0x9000
EVENT_ID_BUTTON_PRESS = 0x9001

# --- Payload Definitions ---
@dataclass
class ButtonEventPayload(SomeIpPayload):
    # 0=Up, 1=Right, 2=Down, 3=Left
    direction: Uint8
    def __init__(self, direction=0):
        self.direction = Uint8(direction)

@dataclass
class BlindSpotPayload(SomeIpPayload):
    warning_level: Uint8
    def __init__(self, level=0):
        self.warning_level = Uint8(level)

# <--- NEW PAYLOAD CLASS
@dataclass
class PositionPayload(SomeIpPayload):
    x: Sint16
    y: Sint16
    def __init__(self, x=0, y=0):
        self.x = Sint16(x)
        self.y = Sint16(y)