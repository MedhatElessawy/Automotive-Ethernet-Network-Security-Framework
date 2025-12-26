```python
import asyncio
import ipaddress
import logging
from datetime import datetime

# --- Third Party / Custom Imports ---
# EventGroup: groups events under an EventGroup ID for subscription
# TransportLayerProtocol: UDP/TCP selection for SOME/IP transport
# ReturnCode: SOME/IP return codes for method replies
# MethodResult: container for method handler response (type/code/payload)
# MessageType: request/response/etc type for SOME/IP messages
from someipy import (
    EventGroup,
    TransportLayerProtocol,
    ReturnCode,
    MethodResult,
    MessageType
)

# ServiceBuilder: used to define service ID, version, eventgroups, methods
# Method: maps method_id -> async handler coroutine
from someipy.service import ServiceBuilder, Method

# Service Discovery object constructor (SD multicast)
from someipy.service_discovery import construct_service_discovery

# Server instance constructor (offers a service)
from someipy.server_service_instance import construct_server_service_instance

# Client instance constructor (subscribes/calls a service)
from someipy.client_service_instance import construct_client_service_instance

# --- Local Imports ---
# common_definitions expected to define:
# - MIRROR_ECU_IP, SD_MULTICAST_GROUP, SD_PORT
# - MIRROR_SERVICE_ID, MIRROR_INSTANCE_ID
# - BUTTON_SERVICE_ID, BUTTON_INSTANCE_ID
# - EVENT_GROUP_* and EVENT_ID_* constants
# - payload classes: PositionPayload, ButtonEventPayload, BlindSpotPayload
from common_definitions import *


# ==========================================
#               CONSOLE COLORS
# ==========================================
# ANSI escape codes for colored terminal output.
# Purely for UI; has no effect on SOME/IP behavior.
class Colors:
    G = '\033[92m'
    Y = '\033[93m'
    R = '\033[91m'
    B = '\033[94m'
    C = '\033[96m'
    M = '\033[95m'
    W = '\033[0m'
    BOLD = '\033[1m'


# ==========================================
#               SOME/IP LAYER
# ==========================================
# Role of this class:
# - Acts as a "Mirror ECU" SOME/IP server producing Blind Spot events.
# - Acts as a SOME/IP client subscribing to "Buttons ECU" events.
# - Maintains a simple (x,y) position state updated by button events.
class SomeIPLayer:
    def __init__(self):
        # Current position state updated by button events
        self.current_x = 0
        self.current_y = 0

        # Whether the client-side subscription is considered "enabled" by UI
        # (Note: turning OFF does not send an unsubscribe in this code)
        self.subscribe_active = False

        # someipy server instance handle (mirror service)
        self.server = None

        # someipy client instance handle (buttons service)
        self.client = None

        # service discovery handle (SD multicast sender/receiver)
        self.sd = None

        # Blind spot level state (used to send event only on changes)
        self.current_level = 0

    def print_header(self):
        # Prints a UI header showing:
        # - ECU identity + time
        # - current position
        # - subscription state
        # Purpose: visibility while testing the lab interactively.
        print(f"\n{Colors.C}{Colors.BOLD}+{'=' * 50}+{Colors.W}")
        print(f"  {Colors.C}MAIN ECU (MIRROR + DoIP) @ {MIRROR_ECU_IP:<15} {datetime.now().strftime('%H:%M:%S')}{Colors.W}")
        print(f"  Position : {Colors.Y}({self.current_x:>3}, {self.current_y:>3}){Colors.W}")
        print(f"  Subscribe to Buttons : {Colors.G if self.subscribe_active else Colors.R}{'ON ' if self.subscribe_active else 'OFF'}")
        print(f"  {Colors.B}Ctrl+Alt+S = Toggle Subscribe    Ctrl+Alt+Q = Quit{Colors.W}")
        print(f"{Colors.C}+{'=' * 50}+{Colors.W}\n")

    # ==========================================
    #        SERVER METHODS (REQUEST/RESPONSE)
    # ==========================================
    # These are SOME/IP methods offered by the Mirror ECU service.

    async def reset_handler(self, data, addr):
        # Method handler for "reset" request.
        # - Resets position state to (0,0)
        # - Returns a MethodResult with E_OK and empty payload.
        print(f"{Colors.M}[SOME/IP][RESET] From {addr[0]} - Position reset{Colors.W}")
        self.current_x = self.current_y = 0
        self.print_header()

        # MethodResult is used by someipy to format the response
        result = MethodResult()
        result.message_type = MessageType.RESPONSE
        result.return_code = ReturnCode.E_OK
        result.payload = b''
        return result

    async def get_position_handler(self, data, addr):
        # Method handler for "get position" request.
        # - Serializes current (x,y) into payload and returns it.
        print(f"{Colors.M}[SOME/IP][GET POS] Request from {addr[0]}{Colors.W}")
        payload = PositionPayload(x=self.current_x, y=self.current_y).serialize()

        result = MethodResult()
        result.message_type = MessageType.RESPONSE
        result.return_code = ReturnCode.E_OK
        result.payload = payload
        return result

    # ==========================================
    #        CLIENT EVENT CALLBACK (SUBSCRIBE)
    # ==========================================
    def on_button(self, msg):
        # Callback invoked when client receives a button event message.
        # - Parses direction from msg.payload
        # - Updates (x,y)
        # - Derives blind-spot "level" based on boundary conditions
        # - Sends blind-spot event if:
        #     1) level changed, and
        #     2) subscribe_active is True, and
        #     3) server exists (Mirror ECU server is running)
        try:
            d = ButtonEventPayload().deserialize(msg.payload).direction.value
            dirs = ["UP", "RIGHT", "DOWN", "LEFT"]

            # Update Position from direction value
            if d == 0:
                self.current_y += 1
            elif d == 1:
                self.current_x += 1
            elif d == 2:
                self.current_y -= 1
            elif d == 3:
                self.current_x -= 1

            print(f"{Colors.G}[SOME/IP][MOVE] {dirs[d]:<5} -> ({self.current_x:>3},{self.current_y:>3}){Colors.W}")

            # Blind Spot Logic:
            # Set a level based on reaching specific coordinate boundaries.
            new_level = 0
            if self.current_y == 5:
                new_level = 1
            elif self.current_y == -5:
                new_level = 2
            elif self.current_x == 5:
                new_level = 3
            elif self.current_x == -5:
                new_level = 4

            # Send blind-spot event only if the derived level changed
            if new_level != self.current_level:
                self.current_level = new_level
                if self.subscribe_active and self.server is not None:
                    print(f"{Colors.R}[BLIND SPOT] Level Changed to {self.current_level}! Sending Event...{Colors.W}")
                    payload = BlindSpotPayload(level=self.current_level).serialize()
                    self.server.send_event(EVENT_GROUP_BLIND_SPOT, EVENT_ID_BLIND_SPOT, payload)

        except:
            # Swallow parse/runtime errors to avoid crashing callback thread
            pass

    # ==========================================
    #        SUBSCRIPTION TOGGLE (UI CONTROL)
    # ==========================================
    async def toggle_subscribe(self):
        # Toggles whether this ECU should attempt to subscribe to the Buttons event group.
        # Purpose:
        # - Allow interactive enabling/disabling via keyboard hotkey in your main runner.
        self.subscribe_active = not self.subscribe_active

        if self.subscribe_active:
            print(f"\n{Colors.G}[SOME/IP] SUBSCRIBE ON - Sending Subscribe{Colors.W}")
            if self.client:
                # Sends SOME/IP SD subscribe for event group
                self.client.subscribe_eventgroup(EVENT_GROUP_BUTTONS)
        else:
            # NOTE: This code does not send an unsubscribe; it only stops sending new subscribe attempts.
            print(f"\n{Colors.R}[SOME/IP] SUBSCRIBE OFF - No more Subscribe packets{Colors.W}")

        self.print_header()

    # ==========================================
    #                STARTUP
    # ==========================================
    async def start(self):
        # Starts SD, server offer, and client registration.
        # Purpose:
        # - SD needed so ECUs can discover each other and exchange subscribe/offer messages.
        # - Server offers Mirror service and provides methods + blind-spot event group.
        # - Client subscribes to Buttons ECU events and receives them via on_button callback.

        self.print_header()

        # Create Service Discovery (SD) participant for this ECU
        self.sd = await construct_service_discovery(SD_MULTICAST_GROUP, SD_PORT, MIRROR_ECU_IP)

        # -------------------------
        # Server: Mirror ECU service
        # -------------------------
        # Defines:
        # - Service ID + major version
        # - Blind spot event group and event id
        # - Reset method and GetPosition method
        self.server = await construct_server_service_instance(
            ServiceBuilder()
            .with_service_id(MIRROR_SERVICE_ID).with_major_version(1)
            .with_eventgroup(EventGroup(id=EVENT_GROUP_BLIND_SPOT, event_ids=[EVENT_ID_BLIND_SPOT]))
            .with_method(Method(METHOD_ID_RESET_MIRROR, self.reset_handler))
            .with_method(Method(METHOD_ID_GET_POSITION, self.get_position_handler))  # Registered method
            .build(),
            instance_id=MIRROR_INSTANCE_ID,
            endpoint=(ipaddress.IPv4Address(MIRROR_ECU_IP), 3000),
            ttl=10,
            sd_sender=self.sd,
            cyclic_offer_delay_ms=10000,
            protocol=TransportLayerProtocol.UDP
        )
        self.sd.attach(self.server)
        self.server.start_offer()

        # -------------------------
        # Client: Buttons ECU service
        # -------------------------
        # Creates a client for the Buttons service so this ECU can subscribe
        # and receive button events via self.on_button.
        self.client = await construct_client_service_instance(
            service=ServiceBuilder().with_service_id(BUTTON_SERVICE_ID).with_major_version(1).build(),
            instance_id=BUTTON_INSTANCE_ID,
            endpoint=(ipaddress.IPv4Address(MIRROR_ECU_IP), 3001),
            ttl=10,
            sd_sender=self.sd,
            protocol=TransportLayerProtocol.UDP
        )
        self.client.register_callback(self.on_button)
        self.sd.attach(self.client)

    # ==========================================
    #                SHUTDOWN
    # ==========================================
    async def stop(self):
        # Stops offering, closes client socket, and closes SD.
        # Purpose:
        # - Release sockets and stop SD announcements cleanly.
        if self.server:
            self.server.stop_offer()
        if self.client:
            await self.client.close()
        if self.sd:
            self.sd.close()
```
