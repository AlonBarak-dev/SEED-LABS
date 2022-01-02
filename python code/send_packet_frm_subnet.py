from scapy.all import *

ip_packet = IP()
ip_packet.dst = '192.168.0.0/16'
send(ip_packet)
