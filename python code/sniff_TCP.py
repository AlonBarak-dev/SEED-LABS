from scapy.all import *
from scapy.layers.inet import TCP, IP


def print_pkt(pkt):
    if pkt[TCP] is not None:
        print("TCP Packet=====")
        print("\tSource: {}".format(pkt[IP].src))
        print("\tDestination: {}".format(pkt[IP].dst))
        print("\tSource Port: {}".format(pkt[TCP].sport))
        print("\tDestination Port: {}".format(pkt[TCP].dport))


pkt = sniff(iface='enp0s3', filter='tcp dst port 23 and src host 10.0.2.15', prn=print_pkt)
