import asyncio
import ipaddress
import logging
from datetime import datetime

# --- Third Party / Custom Imports ---
from someipy import (
    EventGroup,
    TransportLayerProtocol,
    ReturnCode,
    MethodResult,
    MessageType
)
from someipy.service import ServiceBuilder, Method
from someipy.service_discovery import construct_service_discovery
from someipy.server_service_instance import construct_server_service_instance
from someipy.client_service_instance import construct_client_service_instance

# --- Local Imports ---
from common_definitions import *

class Colors:
    G = '\033[92m';
    Y = '\033[93m';
    R = '\033[91m'
    B = '\033[94m';
    C = '\033[96m';
    M = '\033[95m'
    W = '\033[0m';
    BOLD = '\033[1m'

class SomeIPLayer:
    def __init__(self):
        self.current_x = 0
        self.current_y = 0
        self.subscribe_active = False
        self.server = None
        self.client = None
        self.sd = None
        self.current_level = 0

    def print_header(self):
        print(f"\n{Colors.C}{Colors.BOLD}+{'=' * 50}+{Colors.W}")
        print(f"  {Colors.C}MAIN ECU (MIRROR + DoIP) @ {MIRROR_ECU_IP:<15} {datetime.now().strftime('%H:%M:%S')}{Colors.W}")
        print(f"  Position : {Colors.Y}({self.current_x:>3}, {self.current_y:>3}){Colors.W}")
        print(
            f"  Subscribe to Buttons : {Colors.G if self.subscribe_active else Colors.R}{'ON ' if self.subscribe_active else 'OFF'}")
        print(f"  {Colors.B}Ctrl+Alt+S = Toggle Subscribe    Ctrl+Alt+Q = Quit{Colors.W}")
        print(f"{Colors.C}+{'=' * 50}+{Colors.W}\n")

    async def reset_handler(self, data, addr):
        print(f"{Colors.M}[SOME/IP][RESET] From {addr[0]} - Position reset{Colors.W}")
        self.current_x = self.current_y = 0
        self.print_header()
        # FIX: Instantiate MethodResult empty and set attributes manually
        result = MethodResult()
        result.message_type = MessageType.RESPONSE
        result.return_code = ReturnCode.E_OK
        result.payload = b''
        return result

    async def get_position_handler(self, data, addr):
        print(f"{Colors.M}[SOME/IP][GET POS] Request from {addr[0]}{Colors.W}")
        payload = PositionPayload(x=self.current_x, y=self.current_y).serialize()
        # FIX: Instantiate MethodResult empty and set attributes manually
        result = MethodResult()
        result.message_type = MessageType.RESPONSE
        result.return_code = ReturnCode.E_OK
        result.payload = payload
        return result

    def on_button(self, msg):
        try:
            d = ButtonEventPayload().deserialize(msg.payload).direction.value
            dirs = ["UP", "RIGHT", "DOWN", "LEFT"]

            # Update Position
            if d == 0:
                self.current_y += 1
            elif d == 1:
                self.current_x += 1
            elif d == 2:
                self.current_y -= 1
            elif d == 3:
                self.current_x -= 1

            print(f"{Colors.G}[SOME/IP][MOVE] {dirs[d]:<5} -> ({self.current_x:>3},{self.current_y:>3}){Colors.W}")

            # --- Blind Spot Logic (Event Driven) ---
            new_level = 0
            if self.current_y == 5:
                new_level = 1
            elif self.current_y == -5:
                new_level = 2
            elif self.current_x == 5:
                new_level = 3
            elif self.current_x == -5:
                new_level = 4

            # Only send if level CHANGED
            if new_level != self.current_level:
                self.current_level = new_level
                if self.subscribe_active and self.server is not None:
                    print(f"{Colors.R}[BLIND SPOT] Level Changed to {self.current_level}! Sending Event...{Colors.W}")
                    payload = BlindSpotPayload(level=self.current_level).serialize()
                    self.server.send_event(EVENT_GROUP_BLIND_SPOT, EVENT_ID_BLIND_SPOT, payload)

        except:
            pass

    async def toggle_subscribe(self):
        self.subscribe_active = not self.subscribe_active
        if self.subscribe_active:
            print(f"\n{Colors.G}[SOME/IP] SUBSCRIBE ON - Sending Subscribe{Colors.W}")
            if self.client:
                self.client.subscribe_eventgroup(EVENT_GROUP_BUTTONS)
        else:
            print(f"\n{Colors.R}[SOME/IP] SUBSCRIBE OFF - No more Subscribe packets{Colors.W}")
        self.print_header()

    async def start(self):
        self.print_header()

        self.sd = await construct_service_discovery(SD_MULTICAST_GROUP, SD_PORT, MIRROR_ECU_IP)

        self.server = await construct_server_service_instance(
            ServiceBuilder()
            .with_service_id(MIRROR_SERVICE_ID).with_major_version(1)
            .with_eventgroup(EventGroup(id=EVENT_GROUP_BLIND_SPOT, event_ids=[EVENT_ID_BLIND_SPOT]))
            .with_method(Method(METHOD_ID_RESET_MIRROR, self.reset_handler))
            .with_method(Method(METHOD_ID_GET_POSITION, self.get_position_handler))  # <--- REGISTER NEW METHOD
            .build(),
            instance_id=MIRROR_INSTANCE_ID,
            endpoint=(ipaddress.IPv4Address(MIRROR_ECU_IP), 3000),
            ttl=10, sd_sender=self.sd, cyclic_offer_delay_ms=10000,
            protocol=TransportLayerProtocol.UDP
        )
        self.sd.attach(self.server)
        self.server.start_offer()

        self.client = await construct_client_service_instance(
            service=ServiceBuilder().with_service_id(BUTTON_SERVICE_ID).with_major_version(1).build(),
            instance_id=BUTTON_INSTANCE_ID,
            endpoint=(ipaddress.IPv4Address(MIRROR_ECU_IP), 3001),
            ttl=10, sd_sender=self.sd, protocol=TransportLayerProtocol.UDP
        )
        self.client.register_callback(self.on_button)
        self.sd.attach(self.client)

    async def stop(self):
        if self.server: self.server.stop_offer()
        if self.client: await self.client.close()
        if self.sd: self.sd.close()
