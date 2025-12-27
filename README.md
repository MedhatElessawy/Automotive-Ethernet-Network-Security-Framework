# 🚗 Automotive Ethernet Network Security Framework

A Python-based automotive lab implementing **DoIP** (UDS over DoIP with and without TLS) and **SOME/IP** with Service Discovery, simulating ECU, tester, and attacker behavior for learning and security experimentation.

---

## 📖 Overview

This project is a **high-fidelity Automotive Ethernet simulation and security testing framework** designed to model, analyze, and attack modern in-vehicle network architectures.

It emulates a **realistic Zonal Gateway–based vehicle network** using **Linux Network Namespaces** and **virtual Ethernet (veth) pairs**, allowing full isolation of ECUs while preserving real protocol behavior. The goal is to provide a hands-on environment for understanding **how automotive Ethernet works**, **where it breaks**, and **how security mechanisms affect attack feasibility**.

### 🔌 Dual-Stack Automotive Network Design
The framework implements a **dual-stack communication model**, reflecting how modern vehicles separate concerns across protocols:

* **IPv6 — DoIP (Diagnostics over IP, ISO 13400-2)**
  Used for diagnostic communication (UDS over DoIP). Two variants are implemented and co-exist:
  * **Plain DoIP (non-TLS):** Demonstrates legacy or misconfigured deployments.
  * **DoIP over TLS:** Models secured diagnostic channels, including authentication, session handling, and access control.

* **IPv4 — SOME/IP with Service Discovery**
  Used for **service-oriented ECU communication**, including:
  * Multicast Service Discovery
  * Service offering and subscription
  * Event-driven ECU-to-ECU messaging

### 🎭 ECU, Tester, and Attacker Roles
The system explicitly separates roles to mirror real automotive environments:
* **ECUs:** Simulate functional nodes (e.g., zonal/mirror/buttons ECUs).
* **Tester Nodes:** Perform legitimate diagnostic and control operations.
* **Attacker Modules:** Interact with both SOME/IP and DoIP stacks to explore enumeration, SecurityAccess abuse, brute-force, and TLS downgrade scenarios.

### 🎯 Purpose and Scope
This framework is built for:
* Automotive cybersecurity research and training
* Protocol-level understanding of DoIP and SOME/IP
* Controlled attack experimentation in a safe, local lab

> **Note:** This is **not intended for production use**, but as a precise, hands-on reference for how Automotive Ethernet systems behave under both normal and adversarial conditions.

---

## 🏗️ System Architecture

The simulation models a **zonal automotive Ethernet architecture** using isolated Linux namespaces. Each node runs a well-defined role and communicates using real DoIP and SOME/IP protocol flows.

[Image of network topology diagram for automotive ethernet simulation]

### 1️⃣ Main ECU (`main_ecu.py`)
The **central zonal gateway ECU**. It exposes both diagnostic and functional services using a **dual-stack design**.

#### 🔹 DoIP Layer (Diagnostics over IPv6)
Two independent implementations exist to allow security comparison.

| Variant | Description |
| :--- | :--- |
| **DoIP without TLS**<br>(`doip_layer.py`) | • Uses **plain TCP/UDP over IPv6** (ISO 13400-2).<br>• Listens on **port 13400**.<br>• Implements core **UDS services (ISO 14229)**.<br>• Simulates legacy or misconfigured ECUs with no transport encryption. |
| **DoIP with TLS**<br>(`doip_layer_tls.py`) | • Wraps DoIP traffic inside **TLS (SSL)** using `server.crt` / `server.key`.<br>• Enforces a **TLS handshake** before messages are accepted.<br>• Adds confidentiality and authentication boundaries.<br>• Vulnerable to **logic and downgrade attacks** (intentionally). |

#### 🧠 UDS Services Implemented over DoIP
The DoIP server implements a **realistic UDS (ISO 14229) service set**, designed to model both secure and intentionally weak ECU behaviors.

* **Diagnostic Session Control (0x10):** Supports Default, Extended, and Programming sessions.
* **SecurityAccess (0x27):** Seed/Key–based authentication behavior depends on the configured security mode.
* **ECU Reset (0x11):** Restricted service; executable only after successful SecurityAccess.
* **ReadDataByIdentifier (0x22):** Access to VIN, ECU serial, and simulated program image metadata.
* **WriteDataByIdentifier (0x2E):** Persistent modification of simulated program image (requires unlocked state).
* **RoutineControl (0x31):** Implements routines like ECU self-test and checksum calculation.
* **TesterPresent (0x3E):** Keeps sessions alive; enforces **S3 Server Timeout**.

##### 🔐 Security Modes
The ECU supports two configurable modes to demonstrate deployment postures:
* **🛡️ Protected Mode:** Limits incorrect key attempts (lockout), uses secure seed validation, and requires session tokens for sensitive transitions.
* **⚠️ Unprotected Mode:** Allows unlimited attempts and uses simplified validation logic, representing a deliberately weak configuration for educational analysis.

#### 🔹 SOME/IP Layer (`someip_layer.py`)
Handles **service-oriented ECU communication** over IPv4. This implementation follows the standard SOME/IP service model:

| Component | Description |
| :--- | :--- |
| **1. Service** | A logical function offered by the ECU, identified by a **Service ID**.<br>*(e.g., MirrorControlService, BlindSpotService)* |
| **2. Methods**<br>*(Request/Response)* | Operations that can be called by other ECUs which require a response.<br>*(e.g., `GetMirrorPosition()`, `ResetMirror()`)* |
| **3. Events**<br>*(Notifications)* | One-way updates sent to subscribers. No response is required.<br>*(e.g., `BlindSpotWarning`, `ObjectDetected`)* |
| **4. Event Groups** | A logical grouping of related events under one subscription to manage efficient data transmission.<br>*(e.g., `MirrorStatusGroup` → includes X-pos, Y-pos, and motor status events)* |

---

### 2️⃣ Buttons ECU (`buttons_ecu.py`)
Represents the **Human–Machine Interface (HMI)** inside the vehicle.
* Runs as an independent ECU in its own namespace.
* **Client & Server Role:** Publishes Button Press events and subscribes to Blind Spot Warning events.
* **Request/Response Capability:** Sends a SOME/IP request to the Main ECU to retrieve the current mirror X/Y position (`METHOD_ID_GET_POSITION`). Uses a synchronous **request–response** pattern to display feedback to the user.
* **Simulation:** Uses keyboard input to simulate mirror movement (Up/Down/Left/Right) and reset commands.

---

### 3️⃣ Diagnostic Tester (`tester.py` / `tester_tls.py`)
Simulates an **external diagnostic tool** (garage scanner / OEM tester).

* **Tester without TLS (`tester.py`):** Uses plain DoIP over IPv6. Sends Vehicle Identification Requests (VIR), connects via TCP, performs Routing Activation, and executes UDS services.
* **Tester with TLS (`tester_tls.py`):** Uses DoIP over TLS. Requires a successful SSL handshake to demonstrate security improvements and downgrade feasibility.

---

## ⚔️ Attack Capabilities

Attacks are **explicitly separated by protocol stack** and implemented as modular scripts.

---

### 🛡️ DoIP & UDS Attacks (IPv6)

- **TLS Downgrade Attack**
  - Drops or blocks TLS `ClientHello` packets.
  - Forces fallback to plaintext DoIP.
  - Demonstrates insecure negotiation behavior.
  - 
- **Spoofed DoIP Vehicle Announcement**
  - Sends DoIP Vehicle Identification Requests.
  - Identifies active ECUs and their logical addresses.
  - Maps diagnostic entry points.
    
- **Logical Address Enumeration**
  - Iterates through logical address space.
  - Identifies valid ECU logical addresses responding to DoIP.
    
- **DID Enumeration**
  - Enumerates **ReadDataByIdentifier (0x22)** values.
  - Identifies readable diagnostic data items.

- **RID Enumeration**
  - Enumerates **RoutineControl (0x31)** routines.
  - Detects implemented ECU routines.

- **UDS Security Access Brute Force**
  - Repeatedly targets Service `0x27`.
  - Attempts random or calculated keys.
  - Exploits weak Seed/Key logic.

- **DoIP Denial of Service (DoS)**
  - Opens multiple Routing Activation sessions.
  - Exhausts ECU connection limits.
  - Blocks legitimate testers.

- **IPv6 NDP Spoofing and Sniffing  (Man-in-the-Middle)**
  - Sends fake Neighbor Advertisements.
  - Redirects Tester–ECU traffic through attacker.
  - Enables inspection or manipulation.
  - Impersonates ECU or Tester.
  - Intercepts and logs DoIP traffic.

- **Replay Attack **
  - Replays a captured legitimate tester sequence.
  - Sends packets using the attacker’s IPv6 identity.
  - Demonstrates lack of request binding or session integrity.
---

### 🌐 SOME/IP Attacks (IPv4)

- **Service Enumeration (Active Probing)**
  - Scans the Service ID space.
  - Discovers offered and undocumented vehicle services.
  - Maps service, instance, and event group identifiers.

- **Event Impersonation (Fake Events)**
  - Injects forged SOME/IP events.
  - Triggers mirror movement or blind-spot alerts without user input.
  - Demonstrates lack of message authentication.

- **Method Fuzzing**
  - Sends random or sequential Method IDs to valid services.
  - Identifies implemented, undocumented, or unstable RPC methods.
  - Observes ECU error handling behavior.

- **Denial of Service (Offer Flood)**
  - Floods the network with fake SOME/IP **Service Offer** messages.
  - Overwhelms Service Discovery listeners.
  - Causes service instability or prevents legitimate subscriptions.

- **MAC Spoofing & Sniffing (ARP Poisoning)**
  - Performs ARP cache poisoning on IPv4.
  - Intercepts unencrypted SOME/IP unicast traffic.
  - Enables traffic inspection, replay, and manipulation.
---
## 🧩 Requirements
- System Requirements
  - **Linux OS** (required)
    - Tested on Kali 
    - Must support:
      - Linux **Network Namespaces**
      - Virtual Ethernet (**veth**) interfaces
  - **Python** 
- Python Dependencies
  Install using `pip` (preferably inside a virtual environment):
  
  - **someipy**  
    SOME/IP and Service Discovery implementation
  - **scapy**  
    Packet crafting, sniffing, ARP/NDP spoofing, replay attacks
  - **keyboard**  
    Global hotkey handling for ECU HMI simulation  
    *(requires root privileges on Linux)*
  - **cryptography** / **ssl** (Python standard / pip-backed)  
    TLS support for DoIP over TLS
- Optional Tools 
  - **Wireshark**
    - Used for **packet inspection and validation**
    - Not required to run the framework

---
## ▶️ How to Run the Simulation

### ⚠️ Critical: Choose Your Security Mode (TLS vs Non-TLS)
By default, the simulation runs in **Non-TLS (Plain)** mode. To switch modes, you must edit the imports in `main_ecu.py`.

* **For Plain DoIP (Default):**
    * In `main_ecu.py`, use: `from doip_layer import DoIPECU`
    * Run `tester.py` as the client.
    * Run `unified_attacker.py` for attacks.

* **For DoIP over TLS (Secure):**
    * In `main_ecu.py`, change import to: `from doip_layer_tls import DoIPECU`
    * Run `tester_tls.py` as the client.
    * Run `downgrade_attack_tls.py` to test TLS stripping.
---
### Step 1: Activate virtual environment
```bash
#It is recommended to run the project inside a Python virtual environment to isolate dependencies.

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```
### Step 2: Network Setup
```bash
# If you want to use MACsec with TLS
sudo ./setuo_network_with_MACsec.sh

# If you want TLS only
sudo ./setup_network.sh
```
### Step 3: Start the ECUs
```bash
# Terminal 1: Main ECU
sudo ip netns exec ecu1 bash
source venv/bin/activate
python3 main_ecu.py

# Terminal 2: Buttons ECU
sudo ip netns exec ecu2 bash
source venv/bin/activate
python3 buttons_ecu.py

```
### Step 4: Start the Tester
```bash
# Terminal 3:  Tester

# If using Plain DoIP:
sudo ip netns exec ecu3 python3 tester.py


# If using TLS DoIP:
sudo ip netns exec ecu3 python3 tester_tls.py
```
### Step 5: Start the Attacker
```bash
# Terminal 4: Attacker

# For General Attacks (DOIP, SOME/IP):
sudo ip netns exec attacker_ns bash
source venv/bin/activate
python3 unified_attacker.py

# For TLS Downgrade Attack (Specific to TLS Mode):
sudo ip netns exec attacker_ns python3 downgrade_attack_tls.py

```
## 🕹️ Interface & Interactive Controls

Once the simulation is running, each component has a specific interface for interaction.

### 1. ECU Controls (Keyboard Hotkeys)
Since the ECUs run in the background, they listen for global hotkeys to simulate driver input.

| Node | Action | Hotkey | Description |
| :--- | :--- | :--- | :--- |
| **Buttons ECU** | **Subscribe** | `Ctrl` + `Shift` + `S` | Toggle subscription to "Blind Spot" events. |
| | **Move Mirror** | `Ctrl` + `U` / `D` / `L` / `R` | Sends Up, Down, Left, or Right commands via SOME/IP. | 
| | **Get Position** | `Ctrl` + `P` | Request current X/Y coordinates from Main ECU. |
| | **Reset Position** | `Ctrl` + `X` | Request Main ECU to reset coordinates to (0,0). |
| **Main ECU** | **Subscribe** | `Ctrl` + `Alt` + `S` | Toggle subscription to "Button Press" events. |
| | **Quit** | `Ctrl` + `Alt` + `Q` | Stop the Main ECU. |

> **Note:** You may need to run the scripts with `sudo` for keyboard hooks to work on Linux.

---

### 2. Tester Interface (CLI Commands)
The Tester script provides a command-line loop. Type the letter and press Enter.

| Command | Action | Details |
| :--- | :--- | :--- |
| `d` | **Discover** | Broadcasts IPv6 UDP request to find the vehicle. |
| `s` | **Connect** | Establishes TCP (or TLS) connection + Routing Activation. |
| `t` | **Disconnect** | Closes the TCP/TLS connection. |
| `e` | **Enable Keep-Alive** | Starts sending `3E 80` (TesterPresent) every 4 seconds. |
| `x` | **Disable Keep-Alive** | Stops the auto-sender. |
| `q` | **Quit** | Exits the program. |

---

### 3. Attacker Interface (Unified Tool)

The attacker operates via a unified menu. Select **Mode 1** for IPv6 attacks or **Mode 2** for IPv4 attacks.

#### 🛡️ Mode 1: DoIP/UDS Attacker (IPv6)
A command-line interface similar to the tester, but equipped with offensive tools.

| Command | Action | Details |
| :--- | :--- | :--- |
| `d` | **Discover** | Multicast discovery to find ECU IP and Logical Address (LA). |
| `s` | **Connect** | Connects to target (TCP Handshake + Routing Activation). |
| `t` | **Disconnect** | Closes the active TCP connection. |
| `l` | **Enumerate LA** | Brute-forces Routing Activation to find valid Tester LAs (0x0E00–0x0F00). |
| `e` / `x` | **Keep-Alive** | `e` = Enable auto `3E 80` sender; `x` = Disable. |
| `ed` | **Enum DIDs** | Scans Data Identifiers (0xF180–0xF1AF) for valid data. |
| `er` | **Enum RIDs** | Scans Routine Identifiers (0x0200–0x0300) to find executable routines. |
| `dos` | **DoS Attack** | Exhausts ECU resources by flooding TCP connections (Max Clients). |
| `b` | **Brute Force** | Attacks Security Access (0x27) to find the valid Key. |
| `sniff` | **MitM Attack** | Performs IPv6 NDP Poisoning to intercept Tester traffic. |
| `list` | **Show Packets** | Displays packets captured during sniffing. |
| `replay` | **Replay Attack** | Replays captured Tester sequences using the Attacker's IP. |
| `q` | **Quit** | Returns to the main menu. |

#### 🌐 Mode 2: SOME/IP Attacker (IPv4)
A numeric menu system for service-oriented attacks.

| Option | Action | Details |
| :--- | :--- | :--- |
| `1` | **Enumerate Services** | Actively probes Service IDs to discover hidden endpoints. |
| `2` | **Impersonate Service** | Injects fake events (e.g., Blind Spot Warning) to trick subscribers. |
| `3` | **Method Fuzzing** | Calls random Method IDs to find undocumented RPCs. |
| `4` | **DoS Attack** | Floods `OfferService` packets to overwhelm the network. |
| `5` | **MAC Spoofing** | Launches Scapy to perform ARP Poisoning & Sniffing. |
| `6` | **Back** | Returns to the main menu. |

---

### 📡 Traffic Observation 

Wireshark was used during development and testing to **observe, verify, and analyze packet-level behavior** for DoIP, UDS, and SOME/IP communication.

- Used only for **passive inspection and validation**
- Not required for running the simulation or executing attacks
- All attacks, sniffing, and replay functionality are implemented **programmatically** using Scapy and custom tooling

Wireshark serves as a **verification and learning aid**, allowing visibility into:
- DoIP message flows (UDP discovery, TCP/TLS sessions)
- UDS request/response frames
- SOME/IP Service Discovery, events, and RPC traffic
---
## License

This project is licensed under the MIT License.
This project is for educational and research purposes only. Use responsibly in controlled lab environments

## Disclaimer

This project is intended strictly for educational, research, and laboratory use.
Do not use this software against real vehicles, production ECUs, or automotive systems without explicit authorization.  
