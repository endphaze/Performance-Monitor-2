import pyshark

# โหลด .pcap ไฟล์แล้วใส่ filter ip ของ server
#


cap = pyshark.FileCapture(
    "test_pcap/TCP Test 2.pcap",
    display_filter=f"tcp.port == 8080 and http.time",
)


http_times = []

for p in cap:
    time = p.http.time
    print(round(float(time) * 1000, 2))


cap.close()
