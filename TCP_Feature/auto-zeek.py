import os
import subprocess
from pathlib import Path

pcap_path = os.path.abspath("test_pcap/TCP Test 5.pcap")
# output_dir = os.path.abspath("zeek_results")
script_path = os.path.abspath("retransmit_logger.zeek")

path_obj = Path(pcap_path)
pcap_name = path_obj.stem
output_dir = os.path.join(path_obj.parent, "zeek_" + pcap_name)


# 1. สร้างโฟลเดอร์รอไว้
os.makedirs(output_dir, exist_ok=True)

# 2. สั่ง Zeek รัน โดยกำหนดจุดวางไฟล์ (cwd) ไปที่โฟลเดอร์ output
subprocess.run(["zeek", "-C", "-r", pcap_path],)

# print(f"เสร็จแล้ว! ไฟล์ Log ทั้งหมดจะไปอยู่ที่: {output_dir}")
