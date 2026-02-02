import glob
import os
import re
import subprocess
from pathlib import Path

# def filter_pcap_files(
#     abs_file_list, src_ip="any", src_port="any", dst_ip="any", dst_port="any"
# ):
#     filtered_abs_paths = []

#     # ฟังก์ชันช่วยแปลง 1.1.1.1 -> 1-1-1-1
#     def format_ip(ip):
#         return ip.replace(".", "-") if ip != "any" else "any"

#     target_src_ip = format_ip(src_ip)
#     target_dst_ip = format_ip(dst_ip)

#     # Regex แบบใหม่: มองหา IP-แบบ-ขีด และ Port ที่ตามหลังด้วย _ หรือ .
#     # มันจะมองหา [IP]_[Port]_[IP]_[Port] ตรงไหนก็ได้ในชื่อไฟล์
#     # pattern นี้จะจับกลุ่มได้ 4 กลุ่มหลัก: SIP, SPORT, DIP, DPORT
#     regex_pattern = r"_(?P<sip>[\d-]+)_(?P<sport>\d+)_(?P<dip>[\d-]+)_(?P<dport>\d+)\."
#     pattern = re.compile(regex_pattern)

#     for full_path in abs_file_list:
#         file_name = os.path.basename(full_path)

#         # ค้นหา pattern ภายในชื่อไฟล์ (ใช้ search แทน match เพราะ match ต้องเริ่มที่ต้นประโยค)
#         match = pattern.search(file_name)

#         if not match:
#             continue

#         data = match.groupdict()

#         # ตรวจสอบเงื่อนไข
#         match_src_ip = target_src_ip == "any" or target_src_ip == data["sip"]
#         match_src_port = src_port == "any" or str(src_port) == data["sport"]
#         match_dst_ip = target_dst_ip == "any" or target_dst_ip == data["dip"]
#         match_dst_port = dst_port == "any" or str(dst_port) == data["dport"]

#         if all([match_src_ip, match_src_port, match_dst_ip, match_dst_port]):
#             filtered_abs_paths.append(full_path)

#     return filtered_abs_paths


# def _filter_pcap_files(
#     abs_file_list,
#     protocol="any",
#     src_ip="any",
#     src_port="any",
#     dst_ip="any",
#     dst_port="any",
# ):
#     filtered_abs_paths = []

#     def format_ip(ip):
#         return ip.replace(".", "-") if ip != "any" else "any"

#     target_src_ip = format_ip(src_ip)
#     target_dst_ip = format_ip(dst_ip)
#     target_proto = protocol.upper() if protocol != "any" else "any"

#     # Regex ใหม่:
#     # \. จับจุดหน้าโปรโตคอล
#     # (?P<proto>\w+) จับ TCP หรือ UDP
#     # _ ตามด้วยกลุ่ม IP และ Port เดิม
#     regex_pattern = r"\.(?P<proto>\w+)_(?P<sip>[\d-]+)_(?P<sport>\d+)_(?P<dip>[\d-]+)_(?P<dport>\d+)\."
#     pattern = re.compile(regex_pattern)

#     for full_path in abs_file_list:
#         file_name = os.path.basename(full_path)

#         match = pattern.search(file_name)
#         if not match:
#             continue

#         data = match.groupdict()

#         # ตรวจสอบเงื่อนไข (เพิ่ม Protocol)
#         match_proto = target_proto == "any" or target_proto == data["proto"].upper()
#         match_src_ip = target_src_ip == "any" or target_src_ip == data["sip"]
#         match_src_port = src_port == "any" or str(src_port) == data["sport"]
#         match_dst_ip = target_dst_ip == "any" or target_dst_ip == data["dip"]
#         match_dst_port = dst_port == "any" or str(dst_port) == data["dport"]

#         # ต้องผ่านทุกเงื่อนไข
#         if all(
#             [match_proto, match_src_ip, match_src_port, match_dst_ip, match_dst_port]
#         ):
#             filtered_abs_paths.append(full_path)

#     return filtered_abs_paths


def _filter_pcap_files(
    abs_file_list,
    protocol="any",
    src_ip="any",
    src_port="any",
    dst_ip="any",
    dst_port="any",
):
    filtered_abs_paths = []

    def format_ip(ip):
        return ip.replace(".", "-") if ip != "any" else "any"

    target_src_ip = format_ip(src_ip)
    target_dst_ip = format_ip(dst_ip)
    target_proto = protocol.upper() if protocol != "any" else "any"

    # Regex สำหรับแกะโครงสร้างชื่อไฟล์จาก SplitCap
    regex_pattern = r"\.(?P<proto>\w+)_(?P<sip>[\d-]+)_(?P<sport>\d+)_(?P<dip>[\d-]+)_(?P<dport>\d+)\."
    pattern = re.compile(regex_pattern)

    for full_path in abs_file_list:
        file_name = os.path.basename(full_path)
        match = pattern.search(file_name)

        if not match:
            continue

        data = match.groupdict()

        # ข้อมูลที่แกะได้จากชื่อไฟล์ (f = from filename)
        f_proto = data["proto"].upper()
        f_sip, f_sport = data["sip"], data["sport"]
        f_dip, f_dport = data["dip"], data["dport"]

        # 1. เช็ค Protocol ก่อน (ถ้าไม่ตรงก็ข้ามเลย)
        if target_proto != "any" and target_proto != f_proto:
            continue

        # 2. เช็คแบบ Forward (ตรงตัว: src->sip, dst->dip)
        match_forward = all(
            [
                target_src_ip == "any" or target_src_ip == f_sip,
                src_port == "any" or str(src_port) == f_sport,
                target_dst_ip == "any" or target_dst_ip == f_dip,
                dst_port == "any" or str(dst_port) == f_dport,
            ]
        )

        # 3. เช็คแบบ Backward (สลับฝั่ง: src->dip, dst->sip)
        match_backward = all(
            [
                target_src_ip == "any" or target_src_ip == f_dip,
                src_port == "any" or str(src_port) == f_dport,
                target_dst_ip == "any" or target_dst_ip == f_sip,
                dst_port == "any" or str(dst_port) == f_sport,
            ]
        )

        # ถ้าตรงเงื่อนไขทิศทางใดทิศทางหนึ่ง ให้เก็บ Path นี้ไว้
        if match_forward or match_backward:
            filtered_abs_paths.append(full_path)

    return filtered_abs_paths


def read_pcap(
    input_pcap: str,
    protocol="any",
    src_ip="any",
    src_port="any",
    dst_ip="any",
    dst_port="any",
    callback=None,
):
    # 1. ตั้งค่า Path ให้เป็นแบบ Absolute เพื่อลดปัญหา

    # เช็คว่ามีอยู่จริงไหม
    if not os.path.exists(input_pcap):
        print(f"this {input_pcap} not exist")
        return
    elif not input_pcap.lower().endswith(".pcap"):
        print(f"this {input_pcap} is not .pcap")
        return

    # base_dir = os.path.dirname(os.path.abspath(__file__))
    # input_pcap = os.path.join(base_dir, "test_pcap", "TCP Test 5.pcap")

    # 2. ตั้งชื่อโฟลเดอร์ Output ให้สั้นและไม่มีจุดทศนิยมของไฟล์เดิม
    path_obj = Path(input_pcap)
    pcap_name = path_obj.stem  # เอานามสกุลไฟล์ออก
    abs_path = os.path.abspath(input_pcap)
    output_dir = os.path.join(path_obj.parent.name, pcap_name + ".splited")

    # สร้างโฟลเดอร์ถ้ายังไม่มี
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    print(f"กำลังเริ่มตัดไฟล์: {input_pcap}")

    try:
        # 3. รัน SplitCap โดยครอบเครื่องหมายคำพูดป้องกันเรื่องช่องว่างใน Path
        subprocess.run(
            ["SplitCap.exe", "-r", abs_path, "-s", "session", "-o", output_dir],
            check=True,
        )
        print("ตัดไฟล์สำเร็จ!")
    except subprocess.CalledProcessError as e:
        print(f"เกิดข้อผิดพลาดในการรัน SplitCap: {e}")
        exit()

    # 4. วนลูปอ่านไฟล์ที่ได้
    files_to_process = glob.glob(os.path.join(output_dir, "*.pcap"))

    # กรองไฟล์ เรียกใช้ฟังก์ชัน _filter_pcap_files แล้วส่ง parameter
    filterd_files = _filter_pcap_files(
        files_to_process,
        protocol=protocol,
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
    )

    for f in filterd_files:
        # print(f)
        if callback:  # ถ้ามี Call Back Function
            callback(f)
    print("filterd files count", len(filterd_files))

read_pcap("test_pcap/TCP Test 5.pcap", src_ip="216.198.79.67")
