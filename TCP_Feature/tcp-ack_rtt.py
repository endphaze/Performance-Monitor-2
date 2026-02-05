import os
import statistics

import pyshark
from utility import read_pcap

ack_rtt_lst = []


def file_callback(file):
    global ack_rtt_lst
    print(f"run TCP Feature - ACK_RTT: {os.path.basename(file)}")
    cap = pyshark.FileCapture(file, display_filter="ip.addr == 64.29.17.131")
    # ... ใส่ Logic วนลูปดู Stream ที่นี่ ...
    
    limit = 32
    i = 0
    for pkt in cap:
        num = pkt.number
        source = getattr(pkt.ip, "src_host", "-")
        src_port = getattr(pkt.tcp, "srcport", "-")
        destination = getattr(pkt.ip, "dst_host", "-")
        dst_port = getattr(pkt.tcp, "dstport", "-")
        flags = getattr(pkt.tcp, "flags", "-")
        ack_rtt = getattr(pkt.tcp, "analysis_ack_rtt", '-')
        print(num, source, src_port, destination, dst_port, getattr(flags, "showname",'-'), round(float(ack_rtt) * 1000,4) if ack_rtt != "-" else "-" , sep='\t')
        if not i < limit:
            break
        i += 1

            
    cap.close()

read_pcap("test_pcap/TCP Test 5.pcap", src_ip="64.29.17.131", callback=file_callback)
# print("ack_rtt mean =", statistics.mean(ack_rtt_lst) * 1000, "ms")
