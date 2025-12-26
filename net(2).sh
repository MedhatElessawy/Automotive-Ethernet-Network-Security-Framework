#!/bin/bash
# setup_network_with_ipv6.sh

set -e

echo "=== CLEANUP OLD SETUP ==="
sudo ip -all netns delete 2>/dev/null || true
sudo ip link del ns-bridge 2>/dev/null || true
for i in v1-br v2-br vatk-br; do
    sudo ip link del "$i" 2>/dev/null || true
done

echo "=== Creating namespaces ==="
ip netns add ecu1
ip netns add ecu2
ip netns add ecu3
ip netns add attacker_ns

echo "=== Creating veth pairs (short names!) ==="
ip link add v1 type veth peer name v1-br          # ECU1
ip link add v2 type veth peer name v2-br          # ECU2
ip link add v3 type veth peer name v3-br
ip link add vatk type veth peer name vatk-br       # Attacker (vatk = 4 chars, safe)

# Move into namespaces
ip link set v1    netns ecu1
ip link set v2    netns ecu2
ip link set v3    netns ecu3
ip link set vatk  netns attacker_ns

BRIDGE_NAME="ns-bridge"

echo "=== Creating bridge $BRIDGE_NAME ==="
ip link add name $BRIDGE_NAME type bridge
ip link set dev $BRIDGE_NAME up
# IPv4 Gateway
ip addr add 192.168.42.1/24 dev $BRIDGE_NAME
# IPv6 Gateway (Added)
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

echo "=== Configuring ECU1 (Mirror/Main) → 192.168.42.10 & fd00::10 ==="
# IPv4
ip netns exec ecu1 ip addr add 192.168.42.10/24 dev v1
ip netns exec ecu1 ip link set v1 up
ip netns exec ecu1 ip link set lo up
ip netns exec ecu1 ip route add default via 192.168.42.1
# IPv6 (Added for DoIP)
ip netns exec ecu1 ip -6 addr add fd00::10/64 dev v1
ip netns exec ecu1 ip -6 route add default via fd00::1

echo "=== Configuring ECU2 (Buttons) → 192.168.42.20 ==="
# IPv4 Only (as requested)
ip netns exec ecu2 ip addr add 192.168.42.20/24 dev v2
ip netns exec ecu2 ip link set v2 up
ip netns exec ecu2 ip link set lo up
ip netns exec ecu2 ip route add default via 192.168.42.1

echo "=== Configuring ECU3 (Tester) → 192.168.42.40 & fd00::40 ==="
# IPv4
ip netns exec ecu3 ip addr add 192.168.42.40/24 dev v3
ip netns exec ecu3 ip link set v3 up
ip netns exec ecu3 ip link set lo up
ip netns exec ecu3 ip route add default via 192.168.42.1
# IPv6 (Added for DoIP)
ip netns exec ecu3 ip -6 addr add fd00::40/64 dev v3
ip netns exec ecu3 ip -6 route add default via fd00::1

echo "=== Configuring ATTACKER → 192.168.42.30 & fd00::30 ==="
# IPv4
ip netns exec attacker_ns ip addr add 192.168.42.30/24 dev vatk
ip netns exec attacker_ns ip link set vatk up
ip netns exec attacker_ns ip link set lo up
ip netns exec attacker_ns ip route add default via 192.168.42.1
# IPv6 (Added for Attack)
ip netns exec attacker_ns ip -6 addr add fd00::30/64 dev vatk
ip netns exec attacker_ns ip -6 route add default via fd00::1

echo "=== Enabling multicast ==="
sudo sysctl -w net.ipv4.conf.all.mc_forwarding=1 >/dev/null 2>&1
sudo sysctl -w net.ipv4.conf.$BRIDGE_NAME.mc_forwarding=1 >/dev/null 2>&1
sudo bridge mcast_snooping $BRIDGE_NAME 0 2>/dev/null || true

# Enable multicast on all three interfaces
for ns in ecu1 ecu2 attacker_ns; do
    iface=$(ip netns exec $ns ip link | grep -o "v[1-2]\|vatk" | head -1)
    ip netns exec $ns ip link set $iface multicast on
    ip netns exec $ns ip route add 224.0.0.0/4 dev $iface 2>/dev/null || true
done

echo
echo "   ECU1 (Main_ECU)      : 192.168.42.10 | fd00::10"
echo "   ECU2 (Buttons)       : 192.168.42.20"
echo "   ECU3 (Tester)        : 192.168.42.40 | fd00::40"
echo "   ATTACKER             : 192.168.42.30 | fd00::30"
echo
