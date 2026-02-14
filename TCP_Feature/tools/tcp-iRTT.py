import os
import statistics

import pyshark
from TCP_Feature.tools.utility import read_pcap

ack_rtt_lst = []


def file_callback(file):
    global ack_rtt_lst
    print(f"run TCP Feature - ACK_RTT: {os.path.basename(file)}")
    cap = pyshark.FileCapture(file, display_filter="tcp.analysis.ack_rtt", keep_packets=False)
    # ... ใส่ Logic วนลูปดู Stream ที่นี่ ...
    for pkt in cap:
        ack_rtt = pkt.tcp.analysis_ack_rtt
        ack_rtt_lst.append(float(ack_rtt))
        print(ack_rtt)
    cap.close()


read_pcap("test_pcap/TCP Test 5.pcap", dst_ip="216.198.79.67", callback=file_callback)


print("ack_rtt mean =", statistics.mean(ack_rtt_lst) * 1000, "ms")
