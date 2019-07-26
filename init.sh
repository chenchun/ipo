rmmod ipo; make clean; make DEBUG=${DEBUG} && insmod ipo.ko

ip netns del ctn
ip=192.168.1.3
if [ "$(hostname)" = "node1" ]; then
    ip=192.168.2.3
fi
ip netns add ctn
ip link add v1 type veth peer name v2
ip link set v2 up
ip link set v1 netns ctn
ip netns exec ctn ip add add $ip/32 dev v1
ip netns exec ctn ip link set v1 mtu 1496
ip netns exec ctn ip link set v1 up
ip netns exec ctn ip link set lo up
ip netns exec ctn ip r add 169.254.0.1 dev v1 scope link
ip netns exec ctn ip r add default via 169.254.0.1 dev v1 scope global
ip netns exec ctn ip n add 169.254.0.1 dev v1 lladdr `cat /sys/class/net/v2/address`
ip route add $ip dev v2

ip link add ipo0 type ipo
if [ $(hostname) = 'master' ]; then
    ip ad add 192.168.1.2/24 dev ipo0
    ip link set ipo0 up
    #ip route add 192.168.2.0/24 via 10.0.0.3 dev eth1 || true
    ip r add 192.168.2.0/24 via 10.0.0.3 dev ipo0 onlink || true
else
    ip ad add 192.168.2.2/24 dev ipo0
    ip link set ipo0 up
    #ip route add 192.168.1.0/24 via 10.0.0.2 dev eth1 || true
    ip r add 192.168.1.0/24 via 10.0.0.2 dev ipo0 onlink || true
fi