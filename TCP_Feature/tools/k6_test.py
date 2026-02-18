import subprocess
import os
import pyshark
import multiprocessing
import time
import shutil

def _start_pyshark_task(interface, pcap_file, duration):
    """ฟังก์ชันภายในสำหรับรันใน Process แยก (Internal use only)"""
    try:
        # ตรวจสอบ tshark path สำหรับ Windows
        cap = pyshark.LiveCapture(
            interface=interface, 
            output_file=pcap_file,
            display_filter="tcp.port == 8080" # ดักเฉพาะ port ที่สนใจเพื่อลดขนาดไฟล์
        )
        print(f"[*] PyShark: เริ่มดักจับบน {interface}...")
        cap.sniff(timeout=duration)
        cap.close()
    except Exception as e:
        print(f"PyShark Error: {e}")

def run_k6_test_sniff(vus, target_url, output_prefix, interface, duration=45):
    # 1. เตรียม Path และโฟลเดอร์
    output_dir = os.path.dirname(output_prefix)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)

    csv_file = f"{output_prefix}.csv"
    pcap_file = f"{output_prefix}.pcap"
    
    # 2. ตั้งค่า Environment Variables สำหรับ k6
    env_vars = os.environ.copy()
    env_vars["K6_WEB_DASHBOARD"] = "true"

    # 3. เริ่มต้น Process ดักจับ Packet ขนานไปกับ Process หลัก
    sniff_process = multiprocessing.Process(
        target=_start_pyshark_task, 
        args=(interface, pcap_file, duration)
    )
    sniff_process.start()
    
    print(f"--- [1/3] เริ่มต้นระบบ Sniffing (รอ 5 วินาทีให้ Driver พร้อม) ---")
    time.sleep(5) 

    # 4. รัน k6 Load Test ใน Process หลัก
    try:
        # ใช้ shell=True เพื่อให้ Windows หา k6 ใน Path เจอแน่นอน
        command = f'k6 run -e VUS={vus} -e TARGET_URL={target_url} --out csv="{csv_file}" script.js'
        print(f"--- [2/3] กำลังรัน k6 Load Test ---")
        subprocess.run(command, env=env_vars, shell=True, check=True)
        print("[+] k6: รันเสร็จสิ้น")
    except Exception as e:
        print(f"[!] k6 Error: {e}")
    
    # 5. รอให้ PyShark ทำงานจนครบเวลาที่กำหนด
    print(f"--- [3/3] รอให้ PyShark บันทึกไฟล์ PCAP ({duration}s) ---")
    sniff_process.join()
    
    # ตรวจสอบความสำเร็จ
    if os.path.exists(pcap_file) and os.path.getsize(pcap_file) > 0:
        print(f"=== สำเร็จ: ข้อมูลทั้งหมดอยู่ที่ {output_prefix}.* ===")
    else:
        print(f"=== ล้มเหลว: ไม่พบไฟล์ PCAP กรุณารันด้วยสิทธิ์ Administrator ===")