import pyshark

# โหลด .pcap ไฟล์แล้วใส่ filter ip ของ server
#
target_ip = input("Target IP : ")

cap = pyshark.FileCapture(
    "test_pcap/ICMP Test 2.pcap",
    display_filter=f"ip.addr == {target_ip} and icmp.resptime",
)


print("No.\tTime (s)\tResponse To (No.)\tType\t\t\t\t\tResponse Time (ms)")
for packet in cap:
    print(
        f"{packet.number}\t{packet.frame_info.time_relative}\t{packet.icmp.resp_to}\t\t\t{packet.icmp.type.showname}\t\t\t{packet.icmp.resptime}"
    )


cap.close()
