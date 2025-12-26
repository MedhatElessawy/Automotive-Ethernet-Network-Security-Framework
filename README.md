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

- **UDS Security Access Brute Force**
  - Repeatedly targets Service `0x27`.
  - Attempts random or calculated keys.
  - Exploits weak Seed/Key logic.

- **DoIP Denial of Service (DoS)**
  - Opens multiple Routing Activation sessions.
  - Exhausts ECU connection limits.
  - Blocks legitimate testers.

- **IPv6 NDP Spoofing (Man-in-the-Middle)**
  - Sends fake Neighbor Advertisements.
  - Redirects Tester–ECU traffic through attacker.
  - Enables inspection or manipulation.

---

### 🌐 SOME/IP Attacks (IPv4)

- **Service Enumeration**
  - Scans Service ID space.
  - Discovers undocumented vehicle services.

- **Event Impersonation**
  - Injects fake SOME/IP events.
  - Triggers mirror movement or blind-spot alerts.

- **Method Fuzzing**
  - Sends random Method IDs.
  - Identifies hidden or unstable RPC endpoints.

- **ARP Poisoning & Sniffing**
  - Intercepts unencrypted SOME/IP traffic.
  - Enables replay and manipulation.

---

## ▶️ How to Run the Simulation

### Step 1: Network Setup
```bash
sudo ./setup_network.sh
