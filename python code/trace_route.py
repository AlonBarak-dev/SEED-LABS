from scapy.all import *
from scapy.layers.inet import IP, ICMP

reached_dest = False
counter = 1

while not reached_dest:
    packet = IP(dst='8.8.8.8', ttl=counter)  # random packet to be tested ,ttl changing each time
    icmp = ICMP()
    res = sr1(packet / icmp, timeout=10, verbose=0)  # a response packet

    if res is not None:
        if res.type == 0:
            print("ttl: {} , response source : {}".format(counter, res.src))
            reached_dest = True
        else:
            print("ttl: {} , response source : {}".format(counter, res.src))
    else:
        print("ttl : {}, time out!".format(counter))

    counter += 1    # increasing the TTL by one


