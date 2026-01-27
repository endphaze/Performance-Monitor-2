import pyshark

# โหลด .pcap ไฟล์แล้วใส่ filter ip ของ server
target_ip = input("Target IP : ")

cap = pyshark.FileCapture(
    "test_pcap/ICMP Test 2 (packet loss).pcap",
    display_filter=f"ip.addr == {target_ip} and icmp",  # เพิ่ม icmp เพื่อความชัวร์
    custom_parameters=["-2"],  # บังคับ Two-pass เพื่อให้คำนวณ resptime และ no_resp ได้แม่นยำ
)

# หัวตาราง (ใช้ f-string กำหนดความกว้างเพื่อความสวยงาม)
header = f"{'No.':<6} {'Time (s)':<12} {'Resp To':<10} {'Type':<35} {'Response Time (ms)':<10} {'No Resp'}"
print(header)
print("-" * len(header))

for packet in cap:
    try:
        # ใช้ getattr เพื่อป้องกัน AttributeError หากฟิลด์ไม่มีอยู่จริง
        # สำหรับ resptime และ no_resp จะให้ค่าเริ่มต้นเป็น "null" หากหาไม่เจอ
        no = packet.number
        time_rel = f"{float(packet.frame_info.time_relative):.6f}"
        resp_to = getattr(packet.icmp, "resp_to", "-")
        icmp_type = packet.icmp.type.showname
        resptime = getattr(packet.icmp, "resptime", "")
        no_resp = getattr(packet.icmp, "no_resp", "")

        # พิมพ์ออกมาในรูปแบบตารางที่จัดคอลัมน์ไว้แล้ว
        print(
            f"{no:<6} {time_rel:<12} {resp_to:<10} {icmp_type:<35} {resptime:<12} {no_resp}"
        )

    except AttributeError:
        # ในกรณีที่เลเยอร์ ICMP หายไปในบางแพ็กเก็ต (แม้จะ filter แล้วก็ตาม)
        continue

cap.close()
