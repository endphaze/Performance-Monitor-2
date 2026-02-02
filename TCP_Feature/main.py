import glob
import os
import statistics
import subprocess

import pyshark


def process_with_splitcap(input_pcap):
    # 1. เช็คขนาดไฟล์ (หน่วย MB)
    file_size_mb = os.path.getsize(input_pcap) / (1024 * 1024)
    print(f"กำลังตรวจสอบไฟล์: {input_pcap} ({file_size_mb:.2f} MB)")

    output_dir = f"{input_pcap}_split"

    # ล้างโฟลเดอร์เก่าก่อนเริ่ม (เพื่อไม่ให้ไฟล์ปนกัน)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # 2. เงื่อนไขการตัดไฟล์ (เช่น ถ้า > 100MB ให้แยกตาม Session)
    if file_size_mb > 100:
        print("ไฟล์มีขนาดใหญ่ กำลังแยกไฟล์ตาม TCP Session...")
        try:
            # คำสั่ง SplitCap:
            # -r: ไฟล์ต้นทาง, -s session: แยกตาม flow, -o: โฟลเดอร์ปลายทาง
            subprocess.run(
                ["SplitCap.exe", "-r", input_pcap, "-s", "session", "-o", output_dir],
                check=True,
            )

            # ดึงรายชื่อไฟล์ย่อยที่ได้ (.pcap)
            files_to_process = glob.glob(os.path.join(output_dir, "*.pcap"))
            print(f"แยกเสร็จสิ้น ได้ไฟล์ย่อยทั้งหมด {len(files_to_process)} ไฟล์")

        except subprocess.CalledProcessError as e:
            print(f"SplitCap ทำงานผิดพลาด: {e}")
            return
    else:
        files_to_process = [input_pcap]

    # 3. วนลูปใช้ pyshark อ่านไฟล์ย่อย
    for f in files_to_process:
        print(f"--- เริ่มวิเคราะห์: {os.path.basename(f)} ---")
        # ใช้ FileCapture พร้อมกั้น filter ให้ดึงแค่ข้อมูลที่ต้องการ
        cap = pyshark.FileCapture(
            f, display_filter="tcp.port == 8080 and tcp.analysis.ack_rtt"
        )

        try:
            list_ack_rtts = []
            for pkt in cap:
                # ตัวอย่าง: ดึงค่า IP และ Hostname (ถ้ามี)
                src_ip = pkt.ip.src
                dst_ip = pkt.ip.dst
                src_port = pkt.tcp.srcport
                dst_port = pkt.tcp.dstport
                ack_rtt = pkt.tcp.analysis_ack_rtt
                # print(
                #     f"Packet ใน Flow: {src_ip} {src_port} -> {dst_ip} {dst_port} ack_rtt : {ack_rtt.showname}"
                # )
                # หยุดแค่ 1 packet ต่อไฟล์เพื่อทดสอบ (ถ้าต้องการ)
                list_ack_rtts.append(float(ack_rtt))

            print(statistics.mean(list_ack_rtts) * 1000, "ms")
        except Exception as e:
            print(f"Error ขณะอ่านไฟล์ {f}: {e}")
        finally:
            cap.close()  # คืน memory


# เรียกใช้งาน
process_with_splitcap("test_pcap/TCP Test 3.pcap")
