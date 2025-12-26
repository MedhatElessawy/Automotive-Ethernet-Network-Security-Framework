import asyncio
import ipaddress
import logging
from datetime import datetime
from someipy import (
    EventGroup,
    TransportLayerProtocol,
    ReturnCode
)
from someipy.service import ServiceBuilder
from someipy.service_discovery import construct_service_discovery
from someipy.server_service_instance import construct_server_service_instance
from someipy.client_service_instance import construct_client_service_instance
from someipy.logging import set_someipy_log_level

import keyboard
from common_definitions import *

# === STATE ===
subscribe_active = False

class Colors:
    G = '\033[92m'  # Green
    Y = '\033[93m'  # Yellow
    R = '\033[91m'  # Red
    B = '\033[94m'  # Blue
    C = '\033[96m'  # Cyan
    M = '\033[95m'  # Magenta
    W = '\033[0m'   # Reset
    BOLD = '\033[1m'

def print_header():
    print(f"\n{Colors.C}{Colors.BOLD}+{'='*50}+{Colors.W}")
    print(f"  {Colors.C}BUTTONS ECU @ {BUTTONS_ECU_IP:<15} {datetime.now().strftime('%H:%M:%S')}{Colors.W}")
    print(f"  Subscribe to Mirror : {Colors.G if subscribe_active else Colors.R}{'ON ' if subscribe_active else 'OFF'}")
    print(f"  {Colors.B}Controls: Ctrl+U/R/D/L = Move    Ctrl+X = Reset{Colors.W}")
    print(f"  {Colors.M}Ctrl+Shift+S = Toggle Subscribe    Ctrl+P = Get Pos{Colors.W}")
    print(f"{Colors.C}+{'='*50}+{Colors.W}\n")

def on_blind_spot(msg):
    try:
        level = BlindSpotPayload().deserialize(msg.payload).warning_level.value
        print(f"{Colors.R}BLIND SPOT WARNING - LEVEL {level}{'!!!' if level>1 else '!!'}{Colors.W}")
    except:
        pass

async def send_button(direction):
    names = ["UP", "RIGHT", "DOWN", "LEFT"]
    print(f"{Colors.G}[BUTTON] {names[direction]}{Colors.W}")
    payload = ButtonEventPayload(direction).serialize()
    server.send_event(EVENT_GROUP_BUTTONS, EVENT_ID_BUTTON_PRESS, payload)

async def send_reset(client):
    if not client.service_found():
        print(f"{Colors.Y}[INFO] Mirror ECU not found{Colors.W}")
        return
    print(f"{Colors.M}[RESET] Sending to Mirror...{Colors.W}")
    try:
        await client.call_method(METHOD_ID_RESET_MIRROR, b'')
        print(f"{Colors.G}[RESET] Success!{Colors.W}")
    except:
        print(f"{Colors.R}[RESET] Failed{Colors.W}")

# <--- NEW FUNCTION TO REQUEST POSITION
async def request_position(client):
    if not client.service_found():
        print(f"{Colors.Y}[INFO] Mirror ECU not found{Colors.W}")
        return
    print(f"{Colors.M}[GET POS] Requesting from Main ECU...{Colors.W}")
    try:
        # Call the new method on the server
        result = await client.call_method(METHOD_ID_GET_POSITION, b'')
        if result.return_code == ReturnCode.E_OK:
            # Deserialize the response
            pos = PositionPayload().deserialize(result.payload)
            print(f"{Colors.G}[GET POS] Received Coordinates: ({pos.x.value}, {pos.y.value}){Colors.W}")
        else:
            print(f"{Colors.R}[GET POS] Error Code: {result.return_code}{Colors.W}")
    except Exception as e:
        print(f"{Colors.R}[GET POS] Request Failed: {e}{Colors.W}")

async def toggle_subscribe(client):
    global subscribe_active
    subscribe_active = not subscribe_active
    if subscribe_active:
        print(f"\n{Colors.G}[SUBSCRIBE] ON - Sending Subscribe message{Colors.W}")
        client.subscribe_eventgroup(EVENT_GROUP_BLIND_SPOT)
    else:
        print(f"\n{Colors.R}[SUBSCRIBE] OFF - No more Subscribe packets{Colors.W}")
    print_header()

async def main():
    set_someipy_log_level(logging.WARNING)
    print_header()

    sd = await construct_service_discovery(SD_MULTICAST_GROUP, SD_PORT, BUTTONS_ECU_IP)

    # === SERVER ===
    global server
    server = await construct_server_service_instance(
        ServiceBuilder()
        .with_service_id(BUTTON_SERVICE_ID)
        .with_major_version(1)
        .with_eventgroup(EventGroup(id=EVENT_GROUP_BUTTONS, event_ids=[EVENT_ID_BUTTON_PRESS]))
        .build(),
        instance_id=BUTTON_INSTANCE_ID,
        endpoint=(ipaddress.IPv4Address(BUTTONS_ECU_IP), 3000),
        ttl=7,
        sd_sender=sd,
        cyclic_offer_delay_ms=7000,  # Offer every 7 seconds
        protocol=TransportLayerProtocol.UDP
    )
    sd.attach(server)
    server.start_offer()

    # === CLIENT ===
    client = await construct_client_service_instance(
        service=ServiceBuilder().with_service_id(MIRROR_SERVICE_ID).with_major_version(1).build(),
        instance_id=MIRROR_INSTANCE_ID,
        endpoint=(ipaddress.IPv4Address(BUTTONS_ECU_IP), 3001),
        ttl=5,
        sd_sender=sd,
        protocol=TransportLayerProtocol.UDP
    )
    client.register_callback(on_blind_spot)
    sd.attach(client)

    loop = asyncio.get_running_loop()

    # Hotkeys
    keyboard.add_hotkey('ctrl+u', lambda: asyncio.run_coroutine_threadsafe(send_button(0), loop))
    keyboard.add_hotkey('ctrl+r', lambda: asyncio.run_coroutine_threadsafe(send_button(1), loop))
    keyboard.add_hotkey('ctrl+d', lambda: asyncio.run_coroutine_threadsafe(send_button(2), loop))
    keyboard.add_hotkey('ctrl+l', lambda: asyncio.run_coroutine_threadsafe(send_button(3), loop))
    keyboard.add_hotkey('ctrl+x', lambda: asyncio.run_coroutine_threadsafe(send_reset(client), loop))
    keyboard.add_hotkey('ctrl+p', lambda: asyncio.run_coroutine_threadsafe(request_position(client), loop)) # <--- NEW HOTKEY
    keyboard.add_hotkey('ctrl+shift+s', lambda: asyncio.run_coroutine_threadsafe(toggle_subscribe(client), loop))
    keyboard.add_hotkey('ctrl+shift+q', lambda: asyncio.get_event_loop().stop())

    try:
        while True:
            await asyncio.sleep(1)
    except:
        pass
    finally:
        server.stop_offer()
        await client.close()
        sd.close()
        print(f"\n{Colors.C}Buttons ECU stopped.{Colors.W}")

if __name__ == "__main__":
    asyncio.run(main())