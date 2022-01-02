from scapy.all import *

packet = IP()

packet.src = '1.1.1.1'  # random IP address
packet.dst = '10.0.2.15'  # our IP address in the local network
pck_icmp = ICMP()

send(packet/pck_icmp)  # sending the edited packet away far away from it LAN
# we called the ICMP packet - pck - because of Ran.
ls(packet)

