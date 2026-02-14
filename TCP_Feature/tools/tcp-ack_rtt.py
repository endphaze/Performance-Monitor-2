from collections import Counter

import pyshark


ack_rtt_cumulative = 0
endpoints_count = Counter()
ports_count = Counter()

def tcp_analzye(file):
    global ack_rtt_lst
    # print(f"run TCP Feature - ACK_RTT: {os.path.basename(file)}")
    cap = pyshark.FileCapture(file, display_filter="ip.src == 64.29.17.131 and tcp.analysis.ack_rtt",use_json=True,  keep_packets=False)
    # ... ใส่ Logic วนลูปดู Stream ที่นี่ ...
    
    
    # for pkt in cap:
    #     print(dir(pkt.tcp.flags))
    #     print(pkt.tcp.flags.showname_value)
    #     break
    
    limit = 32
    i = 0
    for pkt in cap:
        num = pkt.number
        source = getattr(pkt.ip, "src_host", "-")
        src_port = getattr(pkt.tcp, "srcport", "-")
        destination = getattr(pkt.ip, "dst_host", "-")
        dst_port = getattr(pkt.tcp, "dstport", "-")
        flags = getattr(pkt.tcp, "flags", "-")
        ack_rtt = getattr(pkt.tcp.analysis, "ack_rtt", '-')
        
        
        
        print(num, source, src_port, destination, dst_port, flags, round(float(ack_rtt) * 1000,4) if ack_rtt != "-" else "-" , sep='\t')
        i += 1

            
    cap.close()


# print("ack_rtt mean =", statistics.mean(ack_rtt_lst) * 1000, "ms")
