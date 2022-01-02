from scapy.all import *
from scapy.layers.inet import IP, ICMP


def send_packet(pkt):

    if pkt[2].type == 8:

        source = pkt[1].src
        destination = pkt[1].dst
        sequence = pkt[2].seq
        id = pkt[2].id
        load = pkt[3].load

        print("Flip: source {} destination {} type 8 request".format(source, destination))
        print("Flop: source {} destination {} type 0 reply\n".format(destination, source))

        reply = IP(src=destination, dst=source)/ICMP(type=0, id=id, seq=sequence)/load
        send(reply, verbose=0)


pkt = sniff(iface='enp0s3', filter='icmp', prn=send_packet)
