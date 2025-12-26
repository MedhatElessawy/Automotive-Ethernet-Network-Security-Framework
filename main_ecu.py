```python
import asyncio
import threading
import keyboard
import logging
from someipy.logging import set_someipy_log_level

# --- Local Imports ---
# DoIPECU:
#   Implements the DoIP ECU logic (IPv6, UDP discovery + TCP diagnostics)
# SomeIPLayer:
#   Implements SOME/IP services (Async, IPv4)
# Colors:
#   Simple ANSI color helper for console output
from doip_layer import DoIPECU
from someip_layer import SomeIPLayer, Colors


# ==========================================
#               MAIN ENTRY
# ==========================================
async def main():
    # --------------------------------------------------
    # 1) Start DoIP stack in a SEPARATE THREAD
    # --------------------------------------------------
    # Reason:
    # - DoIP logic uses blocking sockets (UDP/TCP)
    # - Running it directly inside asyncio would block the event loop
    # - Daemon thread ensures it exits automatically when main program exits
    print(f"{Colors.B}[System] Starting DoIP Stack (IPv6)...{Colors.W}")
    doip_node = DoIPECU()
    doip_thread = threading.Thread(target=doip_node.start, daemon=True)
    doip_thread.start()

    # --------------------------------------------------
    # 2) Start SOME/IP stack (Async / IPv4)
    # --------------------------------------------------
    # SOME/IP implementation is asyncio-based
    # It runs inside the same event loop as this main() coroutine
    print(f"{Colors.B}[System] Starting SOME/IP Stack (IPv4)...{Colors.W}")

    # Reduce SOME/IP internal logging noise
    set_someipy_log_level(logging.WARNING)

    someip_node = SomeIPLayer()
    await someip_node.start()

    # --------------------------------------------------
    # 3) Keyboard Hotkeys (Global)
    # --------------------------------------------------
    # These hooks are OS-level global shortcuts.
    # On Linux, they usually REQUIRE sudo/root privileges.
    loop = asyncio.get_running_loop()

    # Ctrl+Alt+S:
    # - Toggles SOME/IP subscription state
    # - run_coroutine_threadsafe is required because keyboard callbacks
    #   run outside the asyncio event loop thread
    keyboard.add_hotkey(
        'ctrl+alt+s',
        lambda: asyncio.run_coroutine_threadsafe(
            someip_node.toggle_subscribe(),
            loop
        )
    )

    # Ctrl+Alt+Q:
    # - Immediately stops the asyncio event loop
    # - This triggers cleanup in the finally block
    keyboard.add_hotkey(
        'ctrl+alt+q',
        lambda: asyncio.get_event_loop().stop()
    )

    # --------------------------------------------------
    # 4) Main idle loop
    # --------------------------------------------------
    # No active polling here.
    # - DoIP runs in its own thread
    # - SOME/IP reacts to async events (callbacks)
    # This loop simply keeps the asyncio loop alive.
    try:
        while True:
            await asyncio.sleep(1)
    except:
        # Broad catch to ensure graceful shutdown
        pass
    finally:
        # --------------------------------------------------
        # 5) Graceful shutdown
        # --------------------------------------------------
        # Stop SOME/IP services and release resources
        await someip_node.stop()
        print(f"\n{Colors.C}Main ECU stopped.{Colors.W}")


# ==========================================
#               PROGRAM START
# ==========================================
# asyncio.run():
# - Creates an event loop
# - Runs main() until completion
# - Closes the loop cleanly afterward
if __name__ == "__main__":
    asyncio.run(main())
```
