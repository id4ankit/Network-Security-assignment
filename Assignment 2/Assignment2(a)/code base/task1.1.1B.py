#!/usr/bin/env python3
# Task 1.1B part 2 
from scapy.all import *

packets_numuber=0
def print_pkt(pkt):
  print_pkt.packets_numuber += 1
  print("\n-----------------------TCP packet:{}\n".format(print_pkt.packets_numuber))
  pkt.show()
print_pkt.packets_numuber =0
# The interface can be found with
# 'docker network ls' in the VM
# or 'ifconfig' in the containner

#Capture any TCP packet that comes from a particular IP and with a destination port number 23.
source_ip = "10.9.0.5"
# Set destination port number for TCP packets
destination_port = 23
#Construct the filter expression for TCP packets
filter_TCP = f"tcp and host {source_ip} and dst port {destination_port}"

pkt = sniff(iface='br-70a143fa7795', filter=filter_TCP, prn=print_pkt) 
