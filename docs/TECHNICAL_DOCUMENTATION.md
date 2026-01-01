# Automotive Ethernet Security Lab: Technical Documentation

This document provides an in-depth technical analysis of the lab's architecture, protocol implementations, demonstrated attacks, associated vulnerabilities, and mitigation strategies. It builds on the [Lab Manual](LAB_MANUAL.md) by focusing on the "why" and "how" — protocol internals, security flaws, and engineering trade-offs. This is designed for deeper study, research, or extension of the framework.

## 1. System Architecture

### 1.1 High-Level Design
The lab simulates a **zonal automotive Ethernet network** using Linux namespaces for isolation, mimicking a vehicle's domain controllers (e.g., zonal gateway). Key principles:
- **Modularity**: Core logic in `src/` (importable package), attacks in `attackers/`.
- **Dual-Stack**: IPv6 for DoIP (diagnostics, high security needs), IPv4 for SOME/IP (service-oriented, multicast-heavy).
- **Async/Sync Hybrid**: SOME/IP uses asyncio for event-driven comms; DoIP uses threads for blocking sockets.
- **Security Layers**: Configurable (e.g., `LOCKOUT_PROTECTION=True` & `PROTECTED_IP=True' in `doip_layer.py` toggles brute-force defenses \ enumeration defences).

#### Network Topology (Generated via setup_network.sh)
```
+------------------+     veth     +-------------------+      veth     +----------------+
|     ecu1         | <----------> |       ecu2        |  <----------> |     ecu3       |
|    (Main ECU)    |              |     (Buttons)     |               |    (Tester)    |
|  IPV6:fd00::10   |              |IPV4: 192.168.42.20|               | IPV6: fd00::40 |
|IPV4:192.168.42.10|              |                   |               |                |
+------------------+              +-------------------+               +----------------+
         |                                 |                                   |
         |     vatk (attacker bridge)      |                                   |
         +---------------------------------+-----------------------------------+
                                           |
                                  +---------------------+
                                  |     attacker_ns     |
                                  |      (Attacker)     |
                                  |  IPV6: fd00::30     |
                                  | IPV4  192.168.42.30 |
                                  +---------------------+
```
- **Bridges/Switches**: Simulated via veth pairs; no real switch (use `brctl` for extensions).
- **Isolation**: Namespaces prevent cross-talk; attacker (vatk) poisons via NDP/ARP.

### 1.2 Core Components Breakdown

#### src/doip_layer.py: DoIP ECU Implementation
- **Role**: Dual listener (plain TCP:13400, TLS:3496) for UDS diagnostics.
- **Key Classes/Functions**:
  - `DoIPECU`: Manages state (session, access_flag, S3 timer).
  - `process_request(req)`: Handles UDS SIDs (0x10 session, 0x27 security, etc.).
    - Security: Seed/key via XOR/HMAC; configurable `PROTECTED_MODE`.
    - Lockout: Tracks `error_num`; triggers NRC 0x36 after `MAX_ERROR_COUNT=3`.
  - `handle_client(conn, addr, secure)`: Authenticates via LA + IP (`IP_PROTECTION`).
- **S3 Timer**: Custom thread-based timeout (5s inactivity → session reset).
- **TLS**: SSL context with legacy ciphers (`@SECLEVEL=0`) for downgrade vuln.

#### src/someip_layer.py: SOME/IP ECU Layer
- **Role**: Server (Mirror service) + Client (Buttons subscription).
- **Key Elements**:
  - `SomeIPLayer`: Async class with event/method handlers.
  - Methods: `reset_handler` (METHOD_ID_RESET_MIRROR=0x0100), `get_position_handler` (0x0101).
  - Events: Blind spot (EVENT_ID_BLIND_SPOT=0x8001) triggered by position changes.
  - SD: Multicast offers/subscribes via `construct_service_discovery`.
- **Callbacks**: `on_button(msg)` updates position; publishes blind spot if |x|+|y|>threshold.

#### src/main_ecu.py: Orchestrator
- **Role**: Launches DoIP (thread) + SOME/IP (async loop).
- **Hotkeys**: Global (keyboard lib, sudo req'd): Ctrl+Alt+S (toggle sub), Ctrl+Alt+Q (quit).

#### src/buttons_ecu.py: HMI Simulator
- **Role**: SOME/IP client/server for button events.
- **Hotkeys**: Ctrl+U/R/D/L (send directions), Ctrl+X (reset), Ctrl+P (get pos), Ctrl+Shift+S (toggle sub).
- **Callbacks**: `on_blind_spot(msg)` logs warnings.

#### src/tester.py: Diagnostic Client
- **Role**: Dual-mode DoIP tester with downgrade simulation.
- **Key**: TLS loop tries 1.2→1.1→1.0; UDS via `send_uds` (skips non-0x8001 msgs).
- **Security**: Auto-unlock (0x27) computes key from seed.

#### attackers/*: Red-Team Tools
- **unified_attacker.py**: Menu switches DoIP/SOME/IP modes.
- **doip_attacker.py**: Enum, brute, MitM (NDP), replay; colored CLI.
- **someip_attacker.py**: Probes services, impersonates events, fuzzes methods, DoS floods.
- **downgrade_attack.py**: Scapy-based TLS drop (blocks 1.2 hello → forces 1.0).
- **attack_config.py**: Shared configs (IPs, ports, colors, ainput).

#### scripts/setup_*.sh: Namespace Creator
- `setup_network.sh`: Creates veth pairs, assigns IPs, routes.
- `setup_network_with_macsec.sh`: Adds MACsec encryption (mitigation demo).

### 1.3 Code Flow Example
1. **Startup**: `main_ecu.py` → DoIP thread + SOME/IP async.
2. **SOME/IP Offer**: SD multicasts service (0x1000) every 10s.
3. **Button Event**: Hotkey → `send_button` → Event publish → Main ECU callback updates pos.
4. **DoIP Session**: Tester 's' → Routing Act (0x0005) → UDS (0x8001) → `process_request`.
5. **Attack**: Unified → DoIP mode → 'b' → Seed req (0x27 01) → Key brute → Lockout if enabled.

## 2. Protocol Deep Dive

### 2.1 DoIP (ISO 13400)
- **Layers**: Ethernet → IPv6 → UDP (discovery) / TCP (sessions) → DoIP header (8B: ver=0x02, inv=0xFD, type, len) → UDS.
- **Discovery**: TYPE_VEHICLE_ID_REQ (0x0001) → RES (0x0004) with VIN/LA.
- **Sessions**: Routing Act (0x0005) validates LA; S3 timer (5s inactivity → reset).
- **UDS Integration**: Encapsulates ISO 14229 (e.g., 0x27 seed/key).
- **TLS Extension**: Optional wrapper; handshake before DoIP.

### 2.2 SOME/IP (AUTOSAR)
- **SD Phase**: Multicast OfferService/FindService (UDP 30490).
- **Runtime**: Events (pub/sub), Methods (RPC req/resp).
- **Payloads**: Structured (e.g., ButtonEventPayload: Uint8 direction).
- **No Native Security**: Relies on external (e.g., SecOC for integrity).

## 3. Demonstrated Attacks & Vulnerabilities

Each attack maps to a real vuln, with code refs and research citations.

### 3.1 DoIP Attacks
1. **Logical Address Enumeration** (`doip_attacker.py: enumerate_la`)
   - **Vuln**: Routing Activation lacks auth beyond LA check; brute-force reveals valid tester IDs (0x0E50).
   - **Impact**: Attacker impersonates tester, accesses UDS.
   - **Research**: ISO 13400 lacks mandatory client auth [Wachter 2022, arXiv:2211.12177].
   - **Code**: Loops 0x0E00-0x0EFF; checks res code 0x10.

2. **SecurityAccess Brute Force** (`brute_force_attack`)
   - **Vuln**: Weak seed/key (XOR/HMAC); no rate limit without config.
   - **Impact**: Gains extended session (0x02/03) → reset/write data.
   - **Research**: DoIP exposes diagnostics; TLS optional [Embitel 2018].
   - **Code**: Requests seed (0x27 01) → tries keys → detects lockout (0x36).

3. **DID/RID/PID Enumeration** (`did_enumeration` etc.)
   - **Vuln**: Unprotected scans reveal ECU data/routines.
   - **Impact**: Maps attack surface (e.g., VIN via 0xF190).
   - **Research**: Pre-auth info leaks [EWA 2024, Automotive DoIP Analysis].

4. **DoS (Connection Flood)** (`dos_attack`)
   - **Vuln**: Fixed client limit (semaphore=5); no rate limiting.
   - **Impact**: Blocks legit testers.
   - **Research**: Resource exhaustion in ISO 13400 [Luo 2024, SAE 2024-01-2807].

5. **NDP MitM/Sniff** (`impersonate_and_sniff`)
   - **Vuln**: IPv6 NDP lacks auth; poisons neighbor cache.
   - **Impact**: Intercepts DoIP traffic for replay.
   - **Research**: Link-layer spoofing in Ethernet IVNs [Keysight 2023].

6. **UDS Replay** (`replay_mode`)
   - **Vuln**: No replay protection in plain DoIP.
   - **Impact**: Re-sends captured commands (e.g., resets).
   - **Research**: Session hijacking without TLS [Wachter 2022].

### 3.2 SOME/IP Attacks
1. **Service Enumeration** (`someip_attacker.py: enumerate_services`)
   - **Vuln**: SD multicast reveals hidden services (no encryption).
   - **Impact**: Maps ECU functions.
   - **Research**: SOME/IP lacks auth; MITM via SD spoof [PMC 2023, Sensors].

2. **Service Impersonation** (`impersonate_service_someip`)
   - **Vuln**: No verification of offerer; spoof events (e.g., blind spot).
   - **Impact**: False warnings/triggers safety faults.
   - **Research**: Event spoofing in AUTOSAR [ACM ARES 2021].

3. **Method Fuzzing** (`fuzz_methods`)
   - **Vuln**: Undocumented methods; no input validation.
   - **Impact**: Crashes ECUs or leaks data.
   - **Research**: RPC fuzzing exposes flaws [Cybellum 2024].

4. **DoS (Offer Flood)** (`dos_attacks_someip`)
   - **Vuln**: Unbounded SD responses; floods overwhelm multicast.
   - **Impact**: DoS on subscriptions.
   - **Research**: SD amplification attacks [arXiv 2024, SISSA].

5. **MAC/ARP Spoof** (`mac_spoof_menu`)
   - **Vuln**: L2 poisoning (ARP for IPv4).
   - **Impact**: Intercepts SOME/IP traffic.
   - **Research**: Ethernet IVN spoofing [Plaxidityx 2025].

### 3.3 TLS Downgrade (`downgrade_attack.py`)
- **Vuln**: Legacy support (TLS 1.0/1.1, weak ciphers); attacker drops strong hellos.
- **Impact**: Forces insecure channel → exposes UDS.
- **Research**: DoIP TLS optional; downgrade common [Keysight 2023, Embitel 2018].
- **Code**: Scapy sniffs/drops 0x0303 (TLS 1.2) → forwards 0x0301 (1.0).

## 4. Vulnerabilities & Root Causes

### 4.1 DoIP (ISO 13400)
- **No Mandatory TLS**: Plaintext UDP discovery; TCP optional TLS [Wachter 2022].
- **Weak Auth**: LA checks insufficient; no mutual auth [EWA 2024].
- **Resource Limits**: Fixed connections → DoS [Luo 2024].
- **Replay Risk**: No nonces/timestamps in UDS.

### 4.2 SOME/IP (AUTOSAR)
- **Unauthenticated SD**: Multicast exposes services [PMC 2023].
- **No Integrity**: Events/methods lack signing [ACM ARES 2021].
- **Fuzzable RPC**: No bounds checks [Cybellum 2024].
- **L2 Weaknesses**: ARP/NDP spoofing [Plaxidityx 2025].

### 4.3 Cross-Cutting
- **IPv6/4 Mismatch**: Dual-stack complexity → misconfigs.
- **Async/Sync**: Threading leaks (e.g., DoIP in main_ecu.py).

## 5. Mitigations and Security Recommendations

This lab intentionally demonstrates vulnerabilities to teach automotive protocol security. Below are practical mitigations for each attack, with references to standards, real-world implementations, and how they are partially simulated in this framework.

### 5.1. DoIP (Diagnostics over IP) Mitigations

#### 5.1.1 Logical Address Enumeration & Routing Activation Hijacking
- **Vulnerability**: Weak source authentication (only LA check).
- **Mitigation**:
  - **Mutual Authentication**: Use certificate-based TLS client authentication (not just server cert).
  - **IP Whitelisting**: Restrict routing activation to trusted tester IPs (simulated via `IP_PROTECTION=True` in `doip_layer.py`).
  - **EID/GID Validation**: Check Entity/Group IDs in vehicle announcement (ISO 13400-2 recommendation).
- **Real-World**: OEMs use proprietary tester certificates + IP binding.

#### 5.1.2 SecurityAccess Brute Force
- **Vulnerability**: Predictable seed/key, no rate limiting.
- **Mitigation**:
  - **Strong Key Derivation**: Use HMAC-SHA256 with long secrets (toggle `PROTECTED_MODE=True`).
  - **Lockout Mechanism**: Temporary disable after failed attempts (implemented: `LOCKOUT_PROTECTION=True`, 3 errors → 30s lockout + disconnect on NRC 0x36).
  - **Delay Insertion**: Increasing delay per failed attempt (exponential backoff).
- **Real-World**: UNECE WP.29 R155 requires brute-force protection.

#### 5.1.3 Information Disclosure (DID/RID/PID Enumeration)
- **Vulnerability**: Pre-auth data access.
- **Mitigation**:
  - **Session-Based Access Control**: Require extended/programming session (0x02/0x03) after SecurityAccess (already enforced for sensitive DIDs).
  - **Minimal Exposure**: Only expose necessary identifiers.
- **Real-World**: Diagnostic specs restrict F190 (VIN) to non-default sessions.

#### 5.1.4 DoS via Connection Flooding
- **Vulnerability**: Limited concurrent clients.
- **Mitigation**:
  - **Connection Limiting + Rate Limiting**: Semaphore (MAX_CLIENTS=5) + per-IP throttling.
  - **Timeout Aggressive Cleanup**: Close idle sockets quickly.
- **Real-World**: Gateways use hardware offloading and SYN cookies.

#### 5.1.5 Man-in-the-Middle & Replay
- **Vulnerability**: Plaintext DoIP or weak TLS.
- **Mitigation**:
  - **Mandatory TLS**: Enforce encrypted channel (port 3496) with strong ciphers.
  - **Replay Protection**: Add timestamps/nonces in UDS (not in ISO 14229, but possible via OEM extensions).
  - **Certificate Pinning**: Prevent rogue CA interception.
- **Real-World**: Modern diagnostics require TLS 1.3 + mutual auth.

### 5.2. SOME/IP Mitigations

#### 5.2.1 Service Enumeration & Impersonation
- **Vulnerability**: Unauthenticated multicast SD.
- **Mitigation**:
  - **SecOC (Secure On-board Communication)**: AUTOSAR mechanism adding MACs to messages (future extension possible).
  - **Authentication Tickets**: Central authority issues tokens for service access.
  - **VLAN Segmentation**: Isolate domains (not in lab, but real vehicles use).
- **Real-World**: AUTOSAR 22-11 introduces optional security for SOME/IP-SD.

#### 5.2.2 Method Fuzzing & Undocumented RPCs
- **Vulnerability**: No input validation.
- **Mitigation**:
  - **Interface Definition Enforcement**: Validate against IDL (Interface Definition Language).
  - **Fuzz-Resistant Parsing**: Bounds checks, safe deserialization.
- **Real-World**: Static analysis + runtime assertions in production ECUs.

#### 5.2.3 DoS via Offer Flooding
- **Vulnerability**: Unbounded multicast processing.
- **Mitigation**:
  - **Rate Limiting SD Messages**: Ignore excessive offers from one source.
  - **TTL Validation**: Reject very low TTLs.
- **Real-World**: Gateways filter multicast traffic.

#### 5.2.4 MAC/ARP Spoofing
- **Vulnerability**: L2 trust.
- **Mitigation**:
  - **MACsec (802.1AE)**: Link-layer encryption/authentication (simulated via `setup_network_with_macsec.sh`).
  - **Port Security**: Bind MAC to switch port (hardware switches in vehicles).
- **Real-World**: Automotive Ethernet switches support MACsec.

### 5.3. TLS Downgrade Mitigation
- **Vulnerability**: Support for legacy versions.
- **Mitigation**:
  - **Enforce Minimum Version**: Server rejects < TLS 1.2 or 1.3.
  - **Strong Cipher Suites Only**: Disable 3DES, RC4, etc.
  - **HSTS-like Policy**: Remember secure policy per client.
- **Real-World**: OEM diagnostic servers mandate TLS 1.3.

### 5.4. General Best Practices (UNECE WP.29 R155/R156)
- **Secure Boot & Firmware Signing**
- **Intrusion Detection System (IDS)**: Monitor for enumeration/brute force.
- **Network Segmentation**: Separate diagnostics from functional traffic.
- **Continuous Monitoring & Logging**

### 5.5 Trade-Offs
- **Performance**: TLS adds ~10-20% latency; mitigations increase CPU (e.g., HMAC).
- **Complexity**: SecOC requires key mgmt; overkill for non-critical ECUs.
- **Testing**: Lab configs toggle protections for "before/after" demos.

## 6. Extensions & Future Work
- Add DDS support for data-centric pub/sub.
- Integrate real hardware (e.g., Raspberry Pi ECUs).
- Formal Verification: Use Tamarin for DoIP proofs [Wachter 2022].
- Metrics: Measure attack success rates vs. mitigations.

## References
- Wachter & Kleber (2022). Analysis of DoIP Protocol Vulnerabilities. arXiv:2211.12177.
- Luo et al. (2024). DoIP Model Learning. SAE 2024-01-2807.
- Iorio et al. (2023). SOME/IP MITM Protection. Sensors (PMC).
- AUTOSAR (2022). SOME/IP Specs.
- ISO 13400 (2019). DoIP Standard.
- Plaxidityx (2025). SOME/IP MITM Hijacking.
- Cybellum (2024). AUTOSAR Buffer Overflows.

This document evolves with the project. Contribute via PRs!

For installation manual please check [README](README.md) 
For Lab Manual please check [Lab Manual](LAB_MANUAL.md) 
