import pyshark

pcap_file="pcap/mininet_test3.pcap"
target_ip = "192.168.1.11"
ports = [8080]

if ports:
    port_filter = " or ".join([f"tcp.port == {p}" for p in ports])
    display_filter = f"ip.addr == {target_ip} and ({port_filter}) and tcp.analysis.retransmission and tcp.payload > 0"
else:
    display_filter = f"ip.addr == {target_ip} and tcp.payload > 0 and tcp.analysis.retransmission"

cap = pyshark.FileCapture(pcap_file, display_filter=display_filter, keep_packets=False, use_json=True)


# i = 0

for pkt in cap:
    print(dir(pkt.tcp.analysis))
    break

# for i in range(10):
#     pkt = cap[i]
#     print(f"pkt {pkt.number} is retransmission")
    