## How to run it
- make
- ./create_topo.sh
- sudo ip netns exec ns1  ./l4_lb -c "config.yaml" -i "veth1" (these are also the default options)

Testing has been done with a send.py and wireshark on "veth2"
