ip ad add 192.168.1.2/24 dev ipo0
ip link set ipo0 up
ip route add 192.168.2.0/24 via 10.0.0.3 dev eth1 || true