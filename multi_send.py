#!/usr/bin/env python3

import sys
import socket
import random
from subprocess import Popen, PIPE
import re
import argparse
from scapy.all import sendp, get_if_list, get_if_hwaddr
from scapy.all import Ether, IP, UDP, TCP, Dot1Q
import threading
import time

def get_if():
    ifs = get_if_list()
    iface = None
    for i in get_if_list():
        if "veth2" in i:
            iface = i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def get_dst_mac(ip):
    try:
        pid = Popen(["arp", "-n", ip], stdout=PIPE)
        s = str(pid.communicate()[0])
        mac = re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", s).groups()[0]
        return mac
    except:
        return None

def send_packet(args, iface, addr, ether_dst, sport):
    tos = 0
    pkt = Ether(src=get_if_hwaddr(iface), dst=ether_dst)
    pkt = pkt / IP(dst=addr, tos=tos) / UDP(dport=args.dport, sport=sport) / args.message

    for _ in range(args.packets):
        sendp(pkt, iface=iface, verbose=False)

def main():
    parser = argparse.ArgumentParser(description='Script to send packets to a specific destination')
    parser.add_argument("-d", "--destination", required=True, type=str, help="The IP address of the destination")
    parser.add_argument("-p", "--packets", type=int, required=True, help="Number of packets to send per thread")
    parser.add_argument("-m", "--message", type=str, required=True, help="Message to send")
    parser.add_argument("-dp", "--dport", type=int, required=True, help="Destination port")
    parser.add_argument("-sp", "--sport", type=int, required=True, help="Base source port")
    parser.add_argument("-t", "--threads", type=int, default=4, help="Number of threads to use")

    args = parser.parse_args()

    ip_addr = args.destination
    message = args.message
    dport = args.dport
    sport = args.sport
    num_threads = args.threads

    addr = socket.gethostbyname(ip_addr)
    iface = get_if()

    ether_dst = get_dst_mac(addr)
    if not ether_dst:
        print("Mac address for %s was not found in the ARP table" % addr)
        exit(1)

    print("Sending on interface %s to %s with %d threads" % (iface, str(addr), num_threads))

    # Create threads
    threads = []
    for i in range(num_threads):
        thread_sport = sport + random.randint(0, 100)
        thread = threading.Thread(target=send_packet, args=(args, iface, addr, ether_dst, thread_sport))
        threads.append(thread)
        thread.start()
        time.sleep(.100)

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

if __name__ == '__main__':
    main()
