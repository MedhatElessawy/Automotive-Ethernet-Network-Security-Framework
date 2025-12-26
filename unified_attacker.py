#!/usr/bin/env python3
"""
Unified Automotive Attacker - Complete & Ready to Run
Entry Point

This is the main launcher script for the attack framework.
It provides a central menu to switch between:
1. DoIP/UDS Attacks (IPv6)
2. SOME/IP Attacks (IPv4)
"""
import os
import sys
import asyncio

# UDPATED IMPORT:
# Import global configuration (IPs, Ports, Interface settings)
from attack_config import *

# Import the specialized attack modules
from doip_attacker import DoIPAttacker
from someip_attacker import SomeIPAttacker


def check_root():
    """
    Checks if the script is running with root privileges (sudo).
    Root access is REQUIRED for:
    - Creating raw sockets (Scapy)
    - Sending spoofed packets
    - Modifying network interfaces
    """
    if os.geteuid() != 0:
        print("[-] This script requires root privileges for raw packets and spoofing.")
        sys.exit(1)


def print_top_menu():
    """
    Displays the main selection menu for the Unified Attacker.
    Users choose between the two major attack vectors here.
    """
    print("\n" + "=" * 70)
    print("     UNIFIED AUTOMOTIVE ATTACKER")
    print("=" * 70)
    print(" 1. DoIP/UDS Attacker (IPv6)")
    print(" 2. SOME/IP Attacker (IPv4)")
    print(" 3. Exit")
    print("=" * 70)


async def main():
    """
    Main asynchronous entry point.
    Initializes attack modules and handles the top-level menu loop.
    """
    # 1. Enforce security check
    check_root()
    print("\n=== Welcome to Unified Automotive Attacker ===\n")

    # 2. Instantiate attack modules
    # These classes load their specific configurations and prepare internal state
    doip_mod = DoIPAttacker()
    someip_mod = SomeIPAttacker()

    # 3. Main Event Loop
    while True:
        print_top_menu()
        
        # 'ainput' is an async wrapper for input() defined in attack_config.py
        # It allows the loop to stay responsive if extended with background tasks
        choice = await ainput("Select mode: ")
        choice = choice.strip()

        if choice == "1":
            # Switch context to the DoIP Attacker menu loop
            await doip_mod.run()
        elif choice == "2":
            # Switch context to the SOME/IP Attacker menu loop
            await someip_mod.run()
        elif choice == "3":
            # Clean exit
            print("\nGoodbye!")
            break
        else:
            print("[!] Invalid choice")


if __name__ == "__main__":
    try:
        # Start the asyncio event loop
        asyncio.run(main())
    except KeyboardInterrupt:
        # Handle Ctrl+C gracefully
        print("\n[!] Interrupted")
