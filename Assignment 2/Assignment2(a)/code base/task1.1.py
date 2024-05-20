#!/usr/bin/env python3
# Task 1.1 
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
pkt = sniff(iface='br-70a143fa7795', filter='icmp', prn=print_pkt)  

