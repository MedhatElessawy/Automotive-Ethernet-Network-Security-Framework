#!/bin/bash

set -e

# =========================
# MACsec CONSTANTS
# =========================
M_KEY="0102030405060708090a0b0c0d0e0f10"
M_ALG="GCM-AES-128"

echo "=== CLEANUP OLD SETUP ==="
sudo ip -all netns delete 2>/dev/null || true
sudo ip link del ns-bridge 2>/dev/null || true
for i in v1-br v2-br v3-br vatk-br; do
    sudo ip link del "$i" 2>/dev/null || true
done

echo "=== Creating namespaces ==="
ip netns add ecu1
ip netns add ecu2
ip netns add ecu3
ip netns add attacker_ns

echo "=== Creating veth pairs ==="
ip link add v1 type veth peer name v1-br          # ECU1 (Main)
ip link add v2 type veth peer name v2-br          # ECU2 (Buttons)
ip link add v3 type veth peer name v3-br          # ECU3 (Tester)
ip link add vatk type veth peer name vatk-br      # Attacker

# Move into namespaces
ip link set v1    netns ecu1
ip link set v2    netns ecu2
ip link set v3    netns ecu3
ip link set vatk  netns attacker_ns

BRIDGE_NAME="ns-bridge"

echo "=== Creating bridge $BRIDGE_NAME ==="
ip link add name $BRIDGE_NAME type bridge
ip link set dev $BRIDGE_NAME up
# Gateway IPs on the bridge (Plaintext side)
ip addr add 192.168.42.1/24 dev $BRIDGE_NAME
ip -6 addr add fd00::1/64 dev $BRIDGE_NAME

echo "=== Connecting everything to bridge ==="
ip link set v1-br   master $BRIDGE_NAME
ip link set v2-br   master $BRIDGE_NAME
ip link set v3-br   master $BRIDGE_NAME
ip link set vatk-br master $BRIDGE_NAME

ip link set v1-br   up
ip link set v2-br   up
ip link set v3-br   up
ip link set vatk-br up


# ==========================================================
#  HELPER FUNCTION: SETUP MACSEC
# ==========================================================
# Args: 1=Namespace, 2=Dev, 3=My_SCI, 4=Peer1_SCI, 5=Peer2_SCI
setup_macsec() {
    NS=$1; DEV=$2; MY_SCI=$3; P1_SCI=$4; P2_SCI=$5

    echo "   [+] Configuring MACsec on $NS ($DEV) -> macsec0"
    
    # 1. Create Device
    ip netns exec $NS ip link add link $DEV macsec0 type macsec \
        sci $MY_SCI cipher $M_ALG encrypt on send_sci on

    # 2. Configure TX (My Key)
    ip netns exec $NS ip macsec add macsec0 tx sa 0 pn 1 on key 00 $M_KEY

    # 3. Configure RX (Peer 1)
    if [ ! -z "$P1_SCI" ]; then
        ip netns exec $NS ip macsec add macsec0 rx sci $P1_SCI on
        ip netns exec $NS ip macsec add macsec0 rx sci $P1_SCI sa 0 pn 1 on key 00 $M_KEY
    fi

    # 4. Configure RX (Peer 2)
    if [ ! -z "$P2_SCI" ]; then
        ip netns exec $NS ip macsec add macsec0 rx sci $P2_SCI on
        ip netns exec $NS ip macsec add macsec0 rx sci $P2_SCI sa 0 pn 1 on key 00 $M_KEY
    fi

    ip netns exec $NS ip link set macsec0 up
}


echo "=== Configuring ECU1 (Main) - MACSEC IPv4 & IPv6 ==="
# Bring up physical link (No IP here anymore!)
ip netns exec ecu1 ip link set v1 up
ip netns exec ecu1 ip link set lo up

# MACsec Setup: My SCI=1, Peers: 2 (Buttons), 3 (Tester)
setup_macsec ecu1 v1 1 2 3

# ASSIGN IPs to MACSEC0 (This encrypts everything)
# IPv4 for SOME/IP
ip netns exec ecu1 ip addr add 192.168.42.10/24 dev macsec0
# IPv6 for DoIP
ip netns exec ecu1 ip -6 addr add fd00::10/64 dev macsec0

# Routes default to the bridge (which won't understand MACsec, but peers will)
ip netns exec ecu1 ip route add default dev macsec0
ip netns exec ecu1 ip -6 route add default dev macsec0


echo "=== Configuring ECU2 (Buttons) - MACSEC IPv4 ==="
# Bring up physical link
ip netns exec ecu2 ip link set v2 up
ip netns exec ecu2 ip link set lo up

# MACsec Setup: My SCI=2, Peer: 1 (Main)
setup_macsec ecu2 v2 2 1 ""

# ASSIGN IP to MACSEC0
# IPv4 for SOME/IP (Matches Main ECU subnet)
ip netns exec ecu2 ip addr add 192.168.42.20/24 dev macsec0

# Route
ip netns exec ecu2 ip route add default dev macsec0


echo "=== Configuring ECU3 (Tester) - MACSEC IPv6 Only ==="
# IPv4 (Plain) remains on physical v3
ip netns exec ecu3 ip addr add 192.168.42.40/24 dev v3
ip netns exec ecu3 ip link set v3 up
ip netns exec ecu3 ip link set lo up
ip netns exec ecu3 ip route add default via 192.168.42.1

# MACsec Setup: My SCI=3, Peer: 1 (Main)
setup_macsec ecu3 v3 3 1 ""

# IPv6 on MACSEC0 (Encrypted DoIP)
ip netns exec ecu3 ip -6 addr add fd00::40/64 dev macsec0


echo "=== Configuring ATTACKER - NO MACSEC (Plaintext Sniffer) ==="
ip netns exec attacker_ns ip addr add 192.168.42.30/24 dev vatk
ip netns exec attacker_ns ip link set vatk up
ip netns exec attacker_ns ip link set lo up
ip netns exec attacker_ns ip route add default via 192.168.42.1
ip netns exec attacker_ns ip -6 addr add fd00::30/64 dev vatk


echo "=== Enabling multicast ==="
sudo sysctl -w net.ipv4.conf.all.mc_forwarding=1 >/dev/null 2>&1
sudo sysctl -w net.ipv4.conf.$BRIDGE_NAME.mc_forwarding=1 >/dev/null 2>&1
sudo bridge mcast_snooping $BRIDGE_NAME 0 2>/dev/null || true

# Multicast setup
for ns in ecu1 ecu2 attacker_ns; do
    # Note: For ECU1/2, we enable multicast on macsec0 because that's where the IP is
    if [ "$ns" == "attacker_ns" ]; then
        iface="vatk"
    else
        iface="macsec0"
    fi
    ip netns exec $ns ip link set $iface multicast on
    ip netns exec $ns ip route add 224.0.0.0/4 dev $iface 2>/dev/null || true
done

echo
echo "=== NETWORK READY ==="
echo "   ECU1 (Main)   : 192.168.42.10 (MACsec) | fd00::10 (MACsec)"
echo "   ECU2 (Buttons): 192.168.42.20 (MACsec)"
echo "   ECU3 (Tester) : 192.168.42.40 (Eth)    | fd00::40 (MACsec)"
echo "   ATTACKER      : 192.168.42.30 (Eth)    | fd00::30 (Eth)"
echo
