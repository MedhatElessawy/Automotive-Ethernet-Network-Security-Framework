# Automotive Ethernet Network Security Framework

A Python-based framework for simulating and testing automotive protocols like DoIP (over IPv6 with optional TLS) and SOME/IP (over IPv4), with focus on security vulnerabilities.

## Overview

This project provides a complete lab environment for exploring Automotive Ethernet protocols, including diagnostics (DoIP over IPv6 with optional TLS) and service-oriented communication (SOME/IP over IPv4). It includes ECU simulations, a legitimate tester, and attacker tools to demonstrate real-world security issues like brute-force attacks, downgrade vulnerabilities, and DoS.

Key goals:
- Educate on automotive network protocols
- Demonstrate security weaknesses
- Provide hands-on red-team tools

## Team Members
+  [Medhat Elessawy](https://github.com/MedhatElessawy)
+  [Omar Mohsen](https://github.com/OmarMohsen9)
  
## Prerequisites

- Linux (Kali recommended for security tools)
- Python 3.8+
- Scapy, keyboard, someipy (install via `pip install -r requirements.txt`)
- Sudo access for network setup and keyboard hotkeys

## Setup

1. Clone the repo:
```bash
https://github.com/MedhatElessawy/Automotive-Ethernet-Network-Security-Framework
cd Automotive-Ethernet-Network-Security-Framework
```
2. Create virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate
```
3. Install dependencies:
```bash
pip3 install -r requirements.txt
```
4. Setup network namespaces (run as sudo):
```bash
sudo bash scripts/setup_network.sh
```
(or with MACsec: `sudo bash scripts/setup_network_with_macsec.sh`)

## Running the Lab

Open 4 terminals, enter namespaces, activate venv:

1. **Main ECU** (Zonal Gateway):
- Enter namespace: `sudo ip netns exec ecu1 bash`
- Activate venv: `source /path/to/venv/bin/activate`
- Run: `python3 src/main_ecu.py`

2. **Buttons ECU** (HMI Simulator):
- Enter namespace: `sudo ip netns exec vbuttons bash`
- Activate venv
- Run: `python3 src/buttons_ecu.py`

3. **Tester** (Diagnostic Tool):
- Enter namespace: `sudo ip netns exec ecu2 bash`
- Activate venv
- Run: `python3 src/tester.py`

4. **Attacker** (Unified Tool):
- Enter namespace: `sudo ip netns exec attacker_ns bash`
- Activate venv
- Run: `python3 attackers/unified_attacker.py `

For downgrade attack:
- Run: `python3 attackers/downgrade_attack.py` (in attacker namespace)

For Lab Manual please check [Lab Manual](LAB_MANUAL.md) 
For more detailed Technical documentation please check [Technical documentation](TECHNICAL_DOCUMENTATION.md) 
   
