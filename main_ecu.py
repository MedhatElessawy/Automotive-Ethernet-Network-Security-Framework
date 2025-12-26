import asyncio
import threading
import keyboard
import logging
from someipy.logging import set_someipy_log_level

# --- Local Imports ---
from doip_layer import DoIPECU
from someip_layer import SomeIPLayer, Colors


# ==========================================
#               MAIN ENTRY
# ==========================================
async def main():
    # 1. Start DoIP Logic in a separate DAEMON thread so it doesn't block Asyncio
    print(f"{Colors.B}[System] Starting DoIP Stack (IPv6)...{Colors.W}")
    doip_node = DoIPECU()
    doip_thread = threading.Thread(target=doip_node.start, daemon=True)
    doip_thread.start()

    # 2. Start SOME/IP Logic (Async - IPv4)
    print(f"{Colors.B}[System] Starting SOME/IP Stack (IPv4)...{Colors.W}")
    set_someipy_log_level(logging.WARNING)

    someip_node = SomeIPLayer()
    await someip_node.start()

    loop = asyncio.get_running_loop()
    # Note: Keyboard hotkeys might require sudo.
    keyboard.add_hotkey('ctrl+alt+s', lambda: asyncio.run_coroutine_threadsafe(someip_node.toggle_subscribe(), loop))
    keyboard.add_hotkey('ctrl+alt+q', lambda: asyncio.get_event_loop().stop())

    try:
        while True:
            # Main loop now just sleeps; logic is event-driven in on_button
            await asyncio.sleep(1)
    except:
        pass
    finally:
        await someip_node.stop()
        print(f"\n{Colors.C}Main ECU stopped.{Colors.W}")


if __name__ == "__main__":
    asyncio.run(main())