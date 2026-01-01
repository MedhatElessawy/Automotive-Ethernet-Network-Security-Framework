# Automotive Ethernet Security Lab Manual

## Introduction

Welcome to the Automotive Ethernet Security Lab! This framework is a hands-on educational tool developed as a team milestone project to explore modern in-vehicle network protocols like Diagnostics over IP (DoIP) and Scalable service-Oriented MiddlewarE over IP (SOME/IP). By simulating a zonal ECU architecture, you'll gain deep insights into how these protocols work, their vulnerabilities, and mitigation strategies.

### Project Background
In modern vehicles, Ethernet is replacing legacy buses like CAN for high-bandwidth applications such as ADAS, infotainment, and diagnostics. DoIP (ISO 13400) enables UDS diagnostics over IP, often with TLS for security. SOME/IP (AUTOSAR standard) supports service-oriented communication for dynamic ECU interactions.

This lab models a simple vehicle network:
- **Main ECU** (Zonal Gateway): Handles diagnostics (DoIP) and mirror control (SOME/IP).
- **Buttons ECU** (HMI Simulator): Sends button events via SOME/IP.
- **Tester**: Legitimate diagnostic tool (plain/TLS).
- **Attacker**: Red-team console for exploiting weaknesses.

### Learning Objectives
- Understand DoIP and SOME/IP architecture.
- Implement and dissect ECU communication.
- Analyze attacks like brute force, downgrade, MitM, and DoS.
- Evaluate defenses (TLS, lockout, IP protection).

### Threat Model
- Attacker on the same L2 network (compromised ECU or plugged device).
- Goals: Enumerate services, hijack sessions, spoof data, deny service.

## Lab Architecture

### Network Topology
Using Linux namespaces and veth pairs (setup_network.sh):
- **ecu1**: Main ECU (192.168.42.10 / fd00::10)
- **ecu2**: Buttons ECU (192.168.42.20 / fd00::20)
- **ecu3**: Tester (192.168.42.40 / fd00::40)
- **attacker_ns**: Attacker (192.168.42.30 / fd00::30)

IPv4 for SOME/IP (multicast 224.224.224.245:30490). IPv6 for DoIP (UDP/TCP 13400 plain, 3496 TLS).

### Protocol Stack Explanation
- **DoIP (IPv6)**: UDP discovery, TCP sessions for UDS. TLS adds encryption/handshake.
- **SOME/IP (IPv4)**: UDP multicast SD for offers/subscribes. Events/methods for ECU interaction.
- **UDS Services**: Session (0x10), SecurityAccess (0x27), Reset (0x11), Read/Write (0x22/0x2E), Routines (0x31).

### Code Architecture
- **src/common_definitions.py**: Shared constants, payloads, helpers (e.g., create_header, S3Timer).
- **src/doip_layer.py**: DoIP ECU logic (dual plain/TLS, UDS processing, security).
- **src/someip_layer.py**: SOME/IP server/client (events, methods, SD).
- **src/main_ecu.py**: Launches DoIP thread + SOME/IP async.
- **src/buttons_ecu.py**: SOME/IP client/server for buttons (keyboard hotkeys).
- **src/tester.py**: Dual-mode DoIP tester (plain/TLS with downgrade loop).
- **attackers/attack_config.py**: Attacker configs, colors, utils.
- **attackers/doip_attacker.py**: DoIP attacks (enum, brute, MitM, replay).
- **attackers/someip_attacker.py**: SOME/IP attacks (enum, impersonate, fuzz, DoS).
- **attackers/downgrade_attack.py**: TLS downgrade via packet manipulation (Scapy).
- **attackers/unified_attacker.py**: Main attacker menu (DoIP/SOME/IP).

## Lab Setup & Running

Follow README.md for installation/network.

### Running Components
- Main ECU: Integrates DoIP (thread) and SOME/IP (async). Handles position/blind spot.
- Buttons ECU: Publishes button events, subscribes to blind spot (hotkeys: Ctrl+U/R/D/L, Ctrl+X, Ctrl+P).
- Tester: Discovers/connects, sends UDS (e.g., 27 01 for seed/key).
- Attacker: Unified menu launches DoIP/SOME/IP sub-menus.

## Legitimate Operations

### DoIP Discovery & Diagnostics
- Tester 'd': Broadcasts Vehicle ID Request → ECU responds with VIN/LA.
- Connect ('s'/'tls'): Routing Activation → UDS sessions.
- UDS: Send hex (e.g., '10 03' for extended session).

### SOME/IP Communication
- Buttons ECU: Hotkeys send events → Main ECU updates position, publishes blind spot if threshold met.
- Subscription: Ctrl+Alt+S toggles → Main ECU logs subscriptions.

## Attacks & Vulnerabilities

### DoIP Attacks (Mode 1)
1. **LA Enumeration ('l')**: Brute-forces tester LA (0x0E00-0x0EFF) for routing activation.
   - Explanation: ECUs validate LA → attacker finds valid one to hijack diagnostics.
2. **Brute Force ('b')**: Attacks SecurityAccess (0x27) key.
   - With lockout off: Exhausts range.
   - With on: Triggers disconnect after 3 tries (NRC 0x36).
   - Defense: Lockout protection, IP checks.
3. **Enumeration ('ed/er/ep')**: Scans DIDs/RIDs/PIDs.
   - Reveals ECU data/routines without auth (if unprotected).
4. **DoS ('dos')**: Floods connections → exhausts ECU semaphore.
5. **MitM/Sniff ('sniff')**: NDP poisoning → intercepts traffic for replay.
6. **Replay ('replay')**: Replays captured UDS sequences.

### SOME/IP Attacks (Mode 2)
1. **Service Enum (1)**: Probes IDs → detects hidden services.
2. **Impersonate (2)**: Spoofs events (e.g., blind spot warnings).
   - Exploits lack of auth in SOME/IP.
3. **Fuzz Methods (3)**: Calls random methods → finds undocumented RPCs.
4. **DoS (4)**: Floods offers → overwhelms SD.
5. **MAC Spoof (5)**: ARP poisoning + sniffing → intercepts IPv4 traffic.

### TLS Downgrade (downgrade_attack.py)
- Sniffs/drops TLS 1.2 ClientHello → forces tester fallback to 1.0.
- Explanation: Legacy ECUs may accept weak TLS; attacker exploits by blocking strong handshakes.

## Quick Look at Defenses

The lab includes several security mechanisms to show how attacks can be mitigated. You can enable/disable them to compare "vulnerable" vs. "protected" behavior.

### 1. Main ECU Defenses (Configured in `src/doip_layer.py`)

| Defense                  | Config Flag                     | What It Does                                                                 | How to Test / Observe                                      |
|--------------------------|---------------------------------|-------------------------------------------------------------------------------|------------------------------------------------------------|
| **IP Whitelisting**      | `IP_PROTECTION = True`          | Only allows Routing Activation from trusted tester IP (`fd00::40`)           | Try connecting from attacker namespace → rejected (code 0x06) |
| **Brute-Force Lockout**  | `LOCKOUT_PROTECTION = True`     | After 3 wrong SecurityAccess keys → 30-second lockout + disconnect (NRC 0x36) | Run brute force (`b`) → after 3 fails: lockout message + disconnect |
| **Strong Key Derivation**| `PROTECTED_MODE = True`         | Uses HMAC-SHA256 instead of simple XOR for seed → key                         | Brute force becomes infeasible even without lockout         |
| **Session Timeout (S3)** | Built-in (5 seconds)            | Resets to default session on inactivity (TesterPresent resets timer)         | Stop sending keep-alive → session drops after 5s            |
| **TLS Encryption**       | Use tester `tls` command        | All DoIP traffic encrypted (port 3496); handshake required                   | Use Wireshark → plain session visible, TLS session encrypted |
| **Connection Limiting**  | `MAX_CLIENTS = 5`               | Only 5 concurrent diagnostic sessions allowed                                | Run DoS attack (`dos`) with >5 threads → new connections rejected |

> **Tip**: Change these flags in `src/doip_layer.py` and restart `main_ecu.py` to see the effect immediately.

### 2. Network-Level Defenses (Setup Scripts)

| Defense                  | Script Used                              | What It Does                                                                 | How to Test / Observe                                      |
|--------------------------|------------------------------------------|-------------------------------------------------------------------------------|------------------------------------------------------------|
| **Basic Isolation**      | `scripts/setup_network.sh`               | Creates isolated namespaces + veth links (no encryption)                     | Default setup — attacker can sniff/spoof freely            |
| **MACsec Encryption**    | `scripts/setup_network_with_macsec.sh`   | Enables IEEE 802.1AE link-layer encryption/authentication on all veth pairs   | Run with MACsec → Wireshark shows encrypted Ethernet frames; plain attacks fail |

> **Tip**: Run the MACsec script once to enable encryption:
> ```bash
> sudo bash scripts/setup_network_with_macsec.sh
> ```
> Then restart all components. Try sniffing or MitM — you’ll only see encrypted traffic.

### 3. Combined Defense Scenario (Recommended Demo)
For the strongest protection:
1. Set in `doip_layer.py`:
   ```python
   IP_PROTECTION = True
   LOCKOUT_PROTECTION = True
   PROTECTED_MODE = True

## Observations & Analysis

- **Wireshark**: Filter "doip" or "someip" → analyze headers, payloads.
- **Security Lessons**:
  - Without TLS: Sniffing exposes UDS (e.g., seeds/keys).
  - With lockout: Brute force fails after few tries.
  - Downgrade: Weak ciphers expose data.
- **Mitigations**: TLS 1.3, IP whitelisting, rate limiting.

## Conclusion

This lab highlights automotive Ethernet risks. Extend with more attacks or defenses.

References:
- ISO 13400 (DoIP)
- AUTOSAR SOME/IP specs
- Scapy docs

For installation manual please check [README](https://github.com/MedhatElessawy/Automotive-Ethernet-Network-Security-Framework/blob/main/README.md) 

For more detailed Technical documentation, please check the [Technical Documentation](https://github.com/MedhatElessawy/Automotive-Ethernet-Network-Security-Framework/blob/main/docs/TECHNICAL_DOCUMENTATION.md).
