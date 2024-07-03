#!/bin/bash

COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_OFF='\033[0m' # No Color

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# include helper.bash file: used to provide some common function across testing scripts
source "${DIR}/../libs/helpers.bash"

# Read the YAML file into a variable
yaml=$(cat ${DIR}/config.yaml)

# Check if shyaml is installed, if not install it
if ! [ -x "$(command -v shyaml)" ]; then
  echo -e "${COLOR_YELLOW} WARNING: shyaml is not installed ${COLOR_OFF}" >&2
  echo -e "${COLOR_YELLOW} Installing shyaml... ${COLOR_OFF}"
  sudo pip install shyaml
fi

# Check if ethtool is installed, if not install it
if ! [ -x "$(command -v ethtool)" ]; then
  echo -e "${COLOR_YELLOW} WARNING: ethtool is not installed ${COLOR_OFF}" >&2
  echo -e "${COLOR_YELLOW} Installing ethtool... ${COLOR_OFF}"
  sudo apt-get install ethtool -y
fi

# Check if nmap is installed, if not install it
if ! [ -x "$(command -v nmap)" ]; then
  echo -e "${COLOR_YELLOW} WARNING: nmap is not installed ${COLOR_OFF}" >&2
  echo -e "${COLOR_YELLOW} Installing nmap... ${COLOR_OFF}"
  sudo apt-get install nmap -y
fi

#clean
sudo ip link del veth2
sudo ip netns del ns1

set -e



#get VIP
vip=$(echo "$yaml" | shyaml get-value vip)
echo -e "${COLOR_GREEN} VIP: $vip ${COLOR_OFF}"

be_nodes=$(echo "$yaml" | shyaml get-length backends)

for ((i=0 ; i<be_nodes ; i++));do
  elem=$(echo "$yaml" | shyaml get-value backends.$i)
  ip=$(echo "$elem" | shyaml get-value ip)
  echo -e "${COLOR_GREEN} IP: $ip ${COLOR_OFF}"

done
sudo ip netns add ns1
#sudo ip netns add ns2
sudo ip link add veth1 type veth peer name veth2

#ip link show

sudo ip link set veth1 netns ns1
sudo ip netns exec ns1 ip link set dev veth1 up

#sudo ip link set veth2 netns ns2
sudo ip link set dev veth2 up

sudo ip netns exec ns1 ip addr add $vip/16 dev veth1 && sudo ip netns exec ns1 ip link set dev veth1 up
sudo ip addr add 192.168.9.2/16 dev veth2 && sudo ip link set dev veth2 up

mac1=$(sudo ip netns exec ns1 ifconfig veth1 | grep ether | awk '{print $2}')
mac2=$(sudo ifconfig veth2 | grep ether | awk '{print $2}')
echo -e "${COLOR_GREEN} MAC1: $mac1 ${COLOR_OFF}"
echo -e "${COLOR_GREEN} MAC2: $mac2 ${COLOR_OFF}"

##$mac1
sudo arp -s $vip $mac1 -i veth2
sudo ip netns exec ns1 arp -s 192.168.9.2 $mac2

sleep 2

sudo  ./xdp_loader -i veth2 