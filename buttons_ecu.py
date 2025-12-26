```python
import asyncio
import ipaddress
import logging
from datetime import datetime

# someipy imports:
# - EventGroup: groups events under a subscription unit (SD subscribes to event groups)
# - TransportLayerProtocol: selects UDP/TCP for SOME/IP transport
# - ReturnCode: SOME/IP return codes for method responses (E_OK, etc.)
from someipy import (
    EventGroup,
    TransportLayerProtocol,
    ReturnCode
)

# someipy building blocks:
# - ServiceBuilder: defines service metadata (service ID, version, events, methods)
# - construct_service_discovery: builds SOME/IP-SD node (multicast offers/finds)
# - construct_server_service_instance: creates a server instance that offers a service
# - construct_client_service_instance: creates a client instance that discovers/calls a service
from someipy.service import ServiceBuilder
from someipy.service_discovery import construct_service_discovery
from someipy.server_service_instance import construct_server_service_instance
from someipy.client_service_instance import construct_client_service_instance

# SomeIP internal logger control
from someipy.logging import set_someipy_log_level

# keyboard: used for global hotkeys (requires sudo/root privileges on Linux in most cases)
import keyboard

# Project constants & payload classes:
# expected to include:
# - IPs, ports, Service IDs, Instance IDs
# - EventGroup IDs, Event IDs, Method IDs
# - Payload serializers/deserializers (ButtonEventPayload, BlindSpotPayload, PositionPayload, ...)
from common_definitions import *

# === STATE ===
# subscribe_active controls whether this Buttons ECU sends subscription messages
# for Blind Spot events coming from the Mirror/Main ECU.
subscribe_active = False


class Colors:
    # ANSI escape codes for colored terminal output (UI only).
    G = '\033[92m'  # Green
    Y = '\033[93m'  # Yellow
    R = '\033[91m'  # Red
    B = '\033[94m'  # Blue
    C = '\033[96m'  # Cyan
    M = '\033[95m'  # Magenta
    W = '\033[0m'   # Reset
    BOLD = '\033[1m'


def print_header():
    """
    Prints a status banner for the Buttons ECU.
    Shows:
    - ECU IP + current time
    - current subscribe state
    - available hotkeys and their actions

    Note:
    - subscribe_active is global state toggled by Ctrl+Shift+S.
    """
    print(f"\n{Colors.C}{Colors.BOLD}+{'='*50}+{Colors.W}")
    print(f"  {Colors.C}BUTTONS ECU @ {BUTTONS_ECU_IP:<15} {datetime.now().strftime('%H:%M:%S')}{Colors.W}")
    print(f"  Subscribe to Mirror : {Colors.G if subscribe_active else Colors.R}{'ON ' if subscribe_active else 'OFF'}")
    print(f"  {Colors.B}Controls: Ctrl+U/R/D/L = Move    Ctrl+X = Reset{Colors.W}")
    print(f"  {Colors.M}Ctrl+Shift+S = Toggle Subscribe    Ctrl+P = Get Pos{Colors.W}")
    print(f"{Colors.C}+{'='*50}+{Colors.W}\n")


def on_blind_spot(msg):
    """
    Callback invoked when a Blind Spot event is received.
    - msg.payload contains SOME/IP event payload bytes.
    - BlindSpotPayload deserializes it into a structured object.
    - warning_level determines severity and is printed to terminal.

    If payload parsing fails, the exception is swallowed to keep the event loop alive.
    """
    try:
        level = BlindSpotPayload().deserialize(msg.payload).warning_level.value
        print(f"{Colors.R}BLIND SPOT WARNING - LEVEL {level}{'!!!' if level>1 else '!!'}{Colors.W}")
    except:
        # Keep the ECU running even if unexpected payloads arrive.
        pass


async def send_button(direction):
    """
    Publishes a button press event (UP/RIGHT/DOWN/LEFT) to subscribers.

    direction:
      0 = UP
      1 = RIGHT
      2 = DOWN
      3 = LEFT

    Flow:
    - Create payload: ButtonEventPayload(direction)
    - server.send_event(...) publishes it under EVENT_GROUP_BUTTONS / EVENT_ID_BUTTON_PRESS
    - Transport protocol is configured when server instance is built (UDP here).
    """
    names = ["UP", "RIGHT", "DOWN", "LEFT"]
    print(f"{Colors.G}[BUTTON] {names[direction]}{Colors.W}")
    payload = ButtonEventPayload(direction).serialize()
    server.send_event(EVENT_GROUP_BUTTONS, EVENT_ID_BUTTON_PRESS, payload)


async def send_reset(client):
    """
    Sends a Reset Mirror request to the Mirror/Main ECU via SOME/IP method call.

    Preconditions:
    - client.service_found() must be True (service discovery has found provider).
      Otherwise, method calls will fail or be sent to nowhere.

    Behavior:
    - Calls METHOD_ID_RESET_MIRROR with empty payload (b'')
    - Prints success/failure feedback
    """
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
    """
    Requests current mirror position (X/Y) from the Mirror/Main ECU via SOME/IP RPC.

    This is request/response (method) behavior, not an event:
    - client.call_method(METHOD_ID_GET_POSITION, b'') sends the request.
    - result.return_code indicates if ECU handled the request successfully.
    - result.payload carries PositionPayload when ReturnCode is E_OK.
    """
    if not client.service_found():
        print(f"{Colors.Y}[INFO] Mirror ECU not found{Colors.W}")
        return
    print(f"{Colors.M}[GET POS] Requesting from Main ECU...{Colors.W}")
    try:
        # Call the position method on the server
        result = await client.call_method(METHOD_ID_GET_POSITION, b'')
        if result.return_code == ReturnCode.E_OK:
            # Deserialize response payload into structured fields (x, y)
            pos = PositionPayload().deserialize(result.payload)
            print(f"{Colors.G}[GET POS] Received Coordinates: ({pos.x.value}, {pos.y.value}){Colors.W}")
        else:
            # Non-success return code: prints the error reason from SOME/IP layer
            print(f"{Colors.R}[GET POS] Error Code: {result.return_code}{Colors.W}")
    except Exception as e:
        # Any transport or parsing failure is reported with exception details
        print(f"{Colors.R}[GET POS] Request Failed: {e}{Colors.W}")


async def toggle_subscribe(client):
    """
    Toggles subscription state for Blind Spot events.

    Implementation detail:
    - subscribe_active flag is local UI state.
    - On enable: client.subscribe_eventgroup(EVENT_GROUP_BLIND_SPOT) sends SD subscribe messages.
    - On disable: this code only flips the flag and prints UI; it does not send an explicit unsubscribe.
      (If an explicit unsubscribe is desired, it must be implemented in the client logic.)
    """
    global subscribe_active
    subscribe_active = not subscribe_active
    if subscribe_active:
        print(f"\n{Colors.G}[SUBSCRIBE] ON - Sending Subscribe message{Colors.W}")
        client.subscribe_eventgroup(EVENT_GROUP_BLIND_SPOT)
    else:
        print(f"\n{Colors.R}[SUBSCRIBE] OFF - No more Subscribe packets{Colors.W}")
    print_header()


async def main():
    """
    Main async entry point for Buttons ECU.

    Responsibilities:
    1) Initialize SOME/IP Service Discovery (SD)
    2) Start a SOME/IP server instance:
       - Publishes button press events
       - Periodically offers the service via SD
    3) Start a SOME/IP client instance:
       - Discovers the Mirror/Main ECU service
       - Subscribes to Blind Spot events (when toggled)
       - Calls methods (reset / get position)
    4) Register keyboard hotkeys to trigger actions without blocking the asyncio loop
    """
    # Reduce someipy log noise; only warnings+ appear
    set_someipy_log_level(logging.WARNING)

    print_header()

    # Create SD node bound to Buttons ECU IP.
    # SD handles multicast offers/find/subscription messages.
    sd = await construct_service_discovery(SD_MULTICAST_GROUP, SD_PORT, BUTTONS_ECU_IP)

    # === SERVER ===
    # Server publishes "Buttons Service" events (Button Press).
    # global server is used by send_button() to send events.
    global server
    server = await construct_server_service_instance(
        ServiceBuilder()
        .with_service_id(BUTTON_SERVICE_ID)                      # Service ID of Buttons ECU
        .with_major_version(1)                                   # Service major version
        .with_eventgroup(EventGroup(id=EVENT_GROUP_BUTTONS, event_ids=[EVENT_ID_BUTTON_PRESS]))
        .build(),
        instance_id=BUTTON_INSTANCE_ID,                           # Instance ID of Buttons service
        endpoint=(ipaddress.IPv4Address(BUTTONS_ECU_IP), 3000),    # Local endpoint for server
        ttl=7,                                                    # Offer TTL in seconds
        sd_sender=sd,                                             # SD object used to broadcast offers
        cyclic_offer_delay_ms=7000,                               # Offer every 7 seconds
        protocol=TransportLayerProtocol.UDP                       # SOME/IP over UDP
    )
    sd.attach(server)      # Attach server to SD stack (so SD can offer it)
    server.start_offer()   # Begin periodic OfferService announcements

    # === CLIENT ===
    # Client discovers and communicates with the Mirror/Main ECU service.
    client = await construct_client_service_instance(
        service=ServiceBuilder().with_service_id(MIRROR_SERVICE_ID).with_major_version(1).build(),
        instance_id=MIRROR_INSTANCE_ID,                            # Expected instance to connect to
        endpoint=(ipaddress.IPv4Address(BUTTONS_ECU_IP), 3001),     # Local endpoint for client
        ttl=5,                                                     # Client TTL for SD interactions
        sd_sender=sd,                                              # SD object used for discovery
        protocol=TransportLayerProtocol.UDP                        # SOME/IP over UDP
    )

    # Register callback for incoming events (Blind Spot event notifications)
    client.register_callback(on_blind_spot)

    # Attach client to SD so it can discover service offers
    sd.attach(client)

    # Obtain current running loop to schedule coroutines from keyboard callbacks
    loop = asyncio.get_running_loop()

    # Hotkeys
    # keyboard callbacks run in separate threads/context; they cannot await directly.
    # asyncio.run_coroutine_threadsafe(...) schedules coroutine on the asyncio loop safely.
    keyboard.add_hotkey('ctrl+u', lambda: asyncio.run_coroutine_threadsafe(send_button(0), loop))
    keyboard.add_hotkey('ctrl+r', lambda: asyncio.run_coroutine_threadsafe(send_button(1), loop))
    keyboard.add_hotkey('ctrl+d', lambda: asyncio.run_coroutine_threadsafe(send_button(2), loop))
    keyboard.add_hotkey('ctrl+l', lambda: asyncio.run_coroutine_threadsafe(send_button(3), loop))

    # RPC-like method calls to Mirror/Main ECU
    keyboard.add_hotkey('ctrl+x', lambda: asyncio.run_coroutine_threadsafe(send_reset(client), loop))
    keyboard.add_hotkey('ctrl+p', lambda: asyncio.run_coroutine_threadsafe(request_position(client), loop))  # <--- NEW HOTKEY

    # Toggle event subscription state
    keyboard.add_hotkey('ctrl+shift+s', lambda: asyncio.run_coroutine_threadsafe(toggle_subscribe(client), loop))

    # Quit: stop the event loop (ends Buttons ECU)
    # Note: this uses asyncio.get_event_loop().stop() which stops the current loop.
    keyboard.add_hotkey('ctrl+shift+q', lambda: asyncio.get_event_loop().stop())

    try:
        # Keep process alive; actions are triggered by hotkeys and network events
        while True:
            await asyncio.sleep(1)
    except:
        # Catch-all to prevent ugly traceback on exit
        pass
    finally:
        # Cleanup: stop offering service and close client/SD resources
        server.stop_offer()
        await client.close()
        sd.close()
        print(f"\n{Colors.C}Buttons ECU stopped.{Colors.W}")


if __name__ == "__main__":
    # Run the async main() entry point.
    asyncio.run(main())
```
