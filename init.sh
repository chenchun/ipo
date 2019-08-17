#!/usr/bin/env bash

set -e

node1=${node1-10.0.0.2}
node2=${node2-10.0.0.3}
rmmod ipo &> /dev/null || true
make clean; make DEBUG=${DEBUG} && insmod ipo.ko

set +e
ip a | grep "inet ${node2}" &> /dev/null
is_node1=$?
set -e

ip netns del ctn 2> /dev/null || true
ip=192.168.1.3
if [ $is_node1 -eq 0 ]; then
    ip=192.168.2.3
fi
ip netns add ctn
ip link add v1 type veth peer name v2
tc qdisc replace dev v2 root pfifo limit 100; ifconfig v2 txqueuelen 0; tc qdisc del dev v2 root;
tc qdisc replace dev v1 root pfifo limit 100; ifconfig v1 txqueuelen 0; tc qdisc del dev v1 root;
ip link set v1 mtu 1500
ip link set v2 mtu 1500
ip link set v2 up
ip link set v1 netns ctn
ip netns exec ctn ip add add $ip/32 dev v1
ip netns exec ctn ip link set v1 up
ip netns exec ctn ip link set lo up
ip netns exec ctn ip r add 169.254.0.1 dev v1 scope link
ip netns exec ctn ip r add default via 169.254.0.1 dev v1 scope global
ip netns exec ctn ip n add 169.254.0.1 dev v1 lladdr `cat /sys/class/net/v2/address`
ip route add $ip dev v2

ip link add link eth1 name ipo0 type ipo
ip link set ipo0 mtu 1500
if [ $is_node1 -eq 1 ]; then
    ip ad add 192.168.1.2/24 dev ipo0
    ip link set ipo0 up
    #ip route add 192.168.2.0/24 via $node2 dev eth1 || true
    ip r add 192.168.2.0/24 via $node2 dev ipo0 onlink || true
else
    ip ad add 192.168.2.2/24 dev ipo0
    ip link set ipo0 up
    #ip route add 192.168.1.0/24 via $node1 dev eth1 || true
    ip r add 192.168.1.0/24 via $node1 dev ipo0 onlink || true
fi

sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.all.rp_filter=0
sysctl -w net.ipv4.conf.default.rp_filter=0
sysctl -w net.ipv4.conf.eth1.rp_filter=0
sysctl -w net.ipv4.conf.ipo0.rp_filter=0
sysctl -w net.ipv4.conf.v2.rp_filter=0
ip link del docker0 2>/dev/null || true