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

# Get the number of elements in the backends list
num_backends=$(echo "$yaml" | shyaml get-length backends)

# function cleanup: is invoked each time script exit (with or without errors)
function cleanup {
  set +e
  delete_veth 2
  # Check is second parameter is not empty
  if [ ! -z "$2" ]; then
    echo -e "${COLOR_GREEN} Topology deleted successfully ${COLOR_OFF}"
  else
    echo -e "${COLOR_RED} Error while running the script ${COLOR_OFF}"
    echo -e "${COLOR_YELLOW} Topology deleted successfully ${COLOR_OFF}"
  fi
}
trap 'cleanup "$1"' ERR

# Enable verbose output
set +x

cleanup ${num_backends} 1

# Check if xdp_loader is compiled, if not compile it
if ! [ -x "$(command -v ${DIR}/xdp_loader)" ]; then
  echo -e "${COLOR_YELLOW} WARNING: xdp_loader is not compiled ${COLOR_OFF}" >&2
  echo -e "${COLOR_YELLOW} Compiling xdp_loader... ${COLOR_OFF}"
  make -C ${DIR} xdp_loader
fi

if ! [ -x "$(command -v ${DIR}/xdp_loader)" ]; then
  echo -e "${COLOR_RED} ERROR: xdp_loader is not compiled ${COLOR_OFF}" >&2
  exit 1
fi

# Makes the script exit, at first error
# Errors are thrown by commands returning not 0 value
set -e


# Create two network namespaces and veth pairs
create_veth 2


vip=$(echo "$yaml" | shyaml get-value vip)
echo -e "${COLOR_GREEN} VIP: $vip ${COLOR_OFF}"

for ((i=0 ; i<num_backends ; i++));do
  elem=$(echo "$yaml" | shyaml get-value backends.$i)
  ip=$(echo "$elem" | shyaml get-value ip)
  echo -e "${COLOR_GREEN} IP: $ip ${COLOR_OFF}"

done
sudo ip netns add ns1
sudo ip link add veth1 type veth peer name veth2


sudo ip link set veth1 netns ns1
sudo ip netns exec ns1 ip link set dev veth1 up

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


sudo ifconfig veth1 ${vip}/24 up
sudo ./xdp_loader -i veth2


echo -e "${COLOR_GREEN} Topology created successfully ${COLOR_OFF}"
