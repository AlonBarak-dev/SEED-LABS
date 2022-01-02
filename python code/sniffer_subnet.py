from scapy.all import *

def print_pkt(pkt):
    pkt.show()


pkt = sniff(iface='enp0s3', filter='dst net 192.168.0.0/16', prn=print_pkt)

