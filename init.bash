ip netns add pc1
ip netns add r1
ip netns add r2
ip netns add r3
ip netns add pc2
ip link add pc1-r1-pc1 type veth peer name pc1-r1-r1
ip link set pc1-r1-pc1 netns pc1
ip link set pc1-r1-r1 netns r1
ip netns exec pc1 ip link set pc1-r1-pc1 up
ip netns exec pc1 ip addr add 192.168.1.2/24 dev pc1-r1-pc1
ip netns exec r1 ip link set pc1-r1-r1 up
ip netns exec r1 ip addr add 192.168.1.1/24 dev pc1-r1-r1
ip link add r1-r2-r1 type veth peer name r1-r2-r2
ip link set r1-r2-r1 netns r1
ip link set r1-r2-r2 netns r2
ip netns exec r1 ip link set r1-r2-r1 up
ip netns exec r1 ip addr add 192.168.3.1/24 dev r1-r2-r1
ip netns exec r2 ip link set r1-r2-r2 up
ip netns exec r2 ip addr add 192.168.3.2/24 dev r1-r2-r2
ip link add r2-r3-r2 type veth peer name r2-r3-r3
ip link set r2-r3-r2 netns r2
ip link set r2-r3-r3 netns r3
ip netns exec r2 ip link set r2-r3-r2 up
ip netns exec r2 ip addr add 192.168.4.1/24 dev r2-r3-r2
ip netns exec r3 ip link set r2-r3-r3 up
ip netns exec r3 ip addr add 192.168.4.2/24 dev r2-r3-r3
ip link add r3-pc2-r3 type veth peer name r3-pc2-pc2
ip link set r3-pc2-r3 netns r3
ip link set r3-pc2-pc2 netns pc2
ip netns exec r3 ip link set r3-pc2-r3 up
ip netns exec r3 ip addr add 192.168.5.2/24 dev r3-pc2-r3
ip netns exec pc2 ip link set r3-pc2-pc2 up
ip netns exec pc2 ip addr add 192.168.5.1/24 dev r3-pc2-pc2



