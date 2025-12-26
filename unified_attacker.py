#!/usr/bin/env python3
"""
Unified Automotive Attacker - Complete & Ready to Run
Entry Point
"""
import os
import sys
import asyncio

# UDPATED IMPORT:
from attack_config import *

from doip_attacker import DoIPAttacker
from someip_attacker import SomeIPAttacker


def check_root():
    if os.geteuid() != 0:
        print("[-] This script requires root privileges for raw packets and spoofing.")
        sys.exit(1)


def print_top_menu():
    print("\n" + "=" * 70)
    print("     UNIFIED AUTOMOTIVE ATTACKER")
    print("=" * 70)
    print(" 1. DoIP/UDS Attacker (IPv6)")
    print(" 2. SOME/IP Attacker (IPv4)")
    print(" 3. Exit")
    print("=" * 70)


async def main():
    check_root()
    print("\n=== Welcome to Unified Automotive Attacker ===\n")

    # Instantiate modules
    doip_mod = DoIPAttacker()
    someip_mod = SomeIPAttacker()

    while True:
        print_top_menu()
        choice = await ainput("Select mode: ")
        choice = choice.strip()

        if choice == "1":
            await doip_mod.run()
        elif choice == "2":
            await someip_mod.run()
        elif choice == "3":
            print("\nGoodbye!")
            break
        else:
            print("[!] Invalid choice")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted")