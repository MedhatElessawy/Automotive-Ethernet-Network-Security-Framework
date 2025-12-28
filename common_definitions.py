from dataclasses import dataclass
from someipy.serialization import SomeIpPayload, Uint8, Sint16

# =============================================================================
# common_definitions.py
# Central definitions for the SOME/IP simulation:
# - Network settings (SD multicast/port)
# - ECU IP addresses
# - SOME/IP Service/Instance IDs
# - SOME/IP Method/Event/EventGroup IDs
# - Payload schemas used across ECUs
#
# Purpose:
# Keeping these values in one place prevents mismatches between:
# - Main ECU (someip_layer.py)
# - Buttons ECU (buttons_ecu.py)
# Any change here must be reflected in all running nodes.
# =============================================================================


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
