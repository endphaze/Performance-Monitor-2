from scapy.all import ICMP, IP, rdpcap


def analyze_icmp_response_time(pcap_file, server_ip):
    packets = rdpcap(pcap_file)

    # เก็บ Request ที่รอ Reply: {sequence_number: timestamp}
    pending_requests = {}
    results = []

    for pkt in packets:
        if pkt.haslayer(ICMP) and pkt.haslayer(IP):
            # ตรวจสอบว่าเป็น ICMP Echo Request จาก Client ไปยัง Server
            if pkt[IP].dst == server_ip and pkt[ICMP].type == 8:
                seq = pkt[ICMP].seq
                # save pending. key = seq
                pending_requests[seq] = pkt.time

            # ตรวจสอบว่าเป็น ICMP Echo Reply จาก Server กลับมา
            elif pkt[IP].src == server_ip and pkt[ICMP].type == 0:
                seq = pkt[ICMP].seq
                if seq in pending_requests:
                    rtt = (pkt.time - pending_requests[seq]) * 1000  # แปลงเป็น ms
                    # print(f"{pending_requests[seq]} - {pkt.time} = {rtt} ms")
                    results.append((seq, rtt))
                    del pending_requests[seq]  # ลบออกเมื่อจับคู่ได้แล้ว

    # แสดงผลลัพธ์
    if results:
        print(f"{'Sequence':<10} | {'Response Time (ms)':<20}")
        print("-" * 35)
        for seq, rtt in results:
            print(f"{seq:<10} | {rtt:.3f} ms")

        avg_rtt = sum(r[1] for r in results) / len(results)
        print("-" * 35)
        print(f"Average RTT: {avg_rtt:.3f} ms")
    else:
        print("ไม่พบข้อมูล ICMP ที่ตรงกับเงื่อนไข")


def show_icmp_time(pcap_file, server_ip):
    packets = rdpcap(pcap_file)
    first_packet_time = packets[0].time

    for pkt in packets:
        if pkt.haslayer(ICMP) and pkt.haslayer(IP):
            print(pkt.time - first_packet_time)


# การใช้งาน
if __name__ == "__main__":
    # file_input = input("ระบุชื่อไฟล์ .pcap: ")
    # server_input = input("ระบุ IP ของ Server: ")
    analyze_icmp_response_time("test_pcap/ICMP Test 2.pcap", "1.1.1.1")
# show_icmp_time("test_pcap/ICMP Test 2.pcap", "192.168.182.150")
