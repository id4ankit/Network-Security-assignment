#!/usr/bin/env python3
# Task 1.1B part 3
from scapy.all import *

packets_numuber=0
def print_pkt(pkt):
  print_pkt.packets_numuber += 1
  print("\n-----------------------packet:{}\n".format(print_pkt.packets_numuber))
  pkt.show()
print_pkt.packets_numuber =0
# The interface can be found with
# 'docker network ls' in the VM
# or 'ifconfig' in the containner
#Capture any TCP packet that comes from a particular IP and with a destination port number 23.

pkt = sniff(iface='br-70a143fa7795', filter='net 128.230.0.0/16', prn=print_pkt)  
