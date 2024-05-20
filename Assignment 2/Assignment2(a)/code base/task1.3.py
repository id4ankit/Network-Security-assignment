'''
#!/usr/bin/env python3

from scapy.all import *

a = IP()
a.dst = '8.8.4.4'
#a.ttl = 3
a.ttl=int(sys.argv[1])
b = ICMP()
#send(a/b)

a = sr1(a/b)

print("Source: ",a.src)

'''
#!/usr/bin/env python3




from scapy.all import *

ttl = 1
    
while True:
    # Create IP packet with specified TTL
    a = IP()
    a.dst = '8.8.4.4'
    a.ttl = ttl
    b = ICMP()

    # Send the packet and receive response
    reply = sr1(a/b, timeout=1, verbose=False)

    if reply is None:  # No response received
        print(f"TTL: {ttl} - No response")
    elif reply.type == 0:  # ICMP echo reply received
        print(f"TTL: {ttl} - Destination reached ({reply.src})")
        break
    elif reply.type == 11:  # ICMP time exceeded
        print(f"TTL: {ttl} - {reply.src} (ICMP Time Exceeded)")
    else:  # Other response received
        print(f"TTL: {ttl} - {reply.src} (Unknown)")

    # Increment TTL for next iteration
    ttl += 1



    
    
   

