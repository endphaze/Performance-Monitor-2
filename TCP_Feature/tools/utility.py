import glob, os
import re, subprocess
import time, json
import statistics, csv

from dataclasses import dataclass
from pathlib import Path
from pydantic import BaseModel, IPvAnyAddress, Field, computed_field
from datetime import datetime

def _filter_pcap_files(abs_file_list, protocol="any", src_ip="any", src_port="any", dst_ip="any", dst_port="any"):
    filtered_abs_paths = []

    def format_ip(ip):
        return ip.replace(".", "-") if ip != "any" else "any"

    target_src_ip = format_ip(src_ip)
    target_dst_ip = format_ip(dst_ip)
    target_proto = protocol.upper()
    
    # ปรับ Regex ให้ยืดหยุ่นขึ้น โดยไม่บังคับว่าต้องมีจุดปิดท้าย dport ทันที
    regex_pattern = r"(?P<proto>\w+)_(?P<sip>[\d-]+)_(?P<sport>\d+)_(?P<dip>[\d-]+)_(?P<dport>\d+)"
    pattern = re.compile(regex_pattern, re.IGNORECASE)

    for full_path in abs_file_list:
        file_name = os.path.basename(full_path)
        match = pattern.search(file_name)
        if not match: continue

        data = match.groupdict()
        f_proto = data["proto"].upper()
        f_sip, f_sport = data["sip"], data["sport"]
        f_dip, f_dport = data["dip"], data["dport"]

        if target_proto != "ANY" and target_proto != f_proto:
            continue

        # ใช้ฟังก์ชันช่วยเช็คเพื่อลดความซับซ้อนของโค้ด
        def check_match(s_ip, s_p, d_ip, d_p):
            return (
                (target_src_ip == "any" or target_src_ip == s_ip) and
                (src_port == "any" or str(src_port) == s_p) and
                (target_dst_ip == "any" or target_dst_ip == d_ip) and
                (dst_port == "any" or str(dst_port) == d_p)
            )

        match_forward = check_match(f_sip, f_sport, f_dip, f_dport)
        match_backward = check_match(f_dip, f_dport, f_sip, f_sport)

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
            ["./tools/PcapSplitter", "-f", abs_path, "-o", output_dir, "-m", "connection"],
            check=True,
        )
        print("ตัดไฟล์สำเร็จ!")
    except subprocess.CalledProcessError as e:
        print(f"เกิดข้อผิดพลาดในการรัน SplitCap: {e}")
        exit()

    # 4. วนลูปอ่านไฟล์ที่ได้
    files_to_process = glob.glob(os.path.join(output_dir, "*.pcap"))

    # กรองไฟล์ เรียกใช้ฟังก์ชัน _filter_pcap_files แล้วส่ง parameter
    # filterd_files = _filter_pcap_files(
    #     files_to_process,
    #     protocol="any",
    #     src_ip="any",
    #     src_port="any",
    #     dst_ip="any",
    #     dst_port="any"
    # )
    
    
    for f in files_to_process:
        print(f)
    
    # start_time = time.time()
    # for f in filterd_files:
    #     # print(f)
    #     if callback:  # ถ้ามี Call Back Function
    #         callback(f)
    #     #
    # end_time = time.time()
    # print("filtered files count", len(filterd_files))
    # print("process time =", end_time-start_time)




class ConfigModel(BaseModel):
    target_ip : IPvAnyAddress = "127.0.0.1"
    ports : list[int] = [80, 443, 8080]
    
    @computed_field
    @property
    def output_graph(self) -> str:
        return f"graph_resp-t_{self.target_ip}.png"

    @computed_field
    @property
    def output_pdf(self) -> str:
        return f"report_tcp_{self.target_ip}.pdf"

    @computed_field
    @property
    def title(self) -> str:
        return f"TCP Analysis Report for {self.target_ip}"
    
    
class MinMaxAvg(BaseModel):
    """กลุ่มข้อมูลสถิติพื้นฐาน Min Max Average"""
    min: float
    max: float
    avg: float

class TCPOutputModel(BaseModel):
    target_ip : IPvAnyAddress
    total_packets_count : int
    relevant_packets_count : int
    request_size : MinMaxAvg
    response_size : MinMaxAvg
    response_time : MinMaxAvg
    exec_time : float
    tshark_filterd_time : float
    top_ports : list[tuple]
    top_endpoints : list[tuple]
    csv_file: str
    
@dataclass(slots=True)
class PacketMetrics:
    time: datetime
    response_time: float
    conn_count: int
    pending_req: int
    stream_id: str
    role: str



def get_MinMaxAvg(list_data) -> MinMaxAvg:
    """Input [] for MinMaxAvg"""
    if not list_data:   
        return MinMaxAvg(min=0,max=0,avg=0)
    return MinMaxAvg(min=min(list_data),
                     max=max(list_data),
                     avg=statistics.mean(list_data))

def get_config(file_path="config.json"):
    # ถ้าไม่มีไฟล์ ให้สร้างไฟล์เริ่มต้นจาก ConfigModel
    if not os.path.exists(file_path):
        default_config = ConfigModel()
        with open(file_path, "w") as f:
            f.write(default_config.model_dump_json(indent=4))
        print(f"สร้างไฟล์ {file_path} เริ่มต้นให้แล้ว")
        return default_config
    
    # ถ้ามีไฟล์อยู่แล้ว ให้โหลดมาใช้
    with open(file_path, "r") as f:
        return ConfigModel(**json.load(f))
    
    
def save_data_to_csv(data, filename="result/analysis_result.csv"):
    # data คือ list ของ tuple เช่น [(1.23, 150), (2.45, 160), ...]
    with open(filename, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        
        # เขียน Header (ชื่อหัวคอลัมน์)
        writer.writerow(['timestamp', 'response_time'])
        
        # เขียนข้อมูลทั้งหมดลงไป
        writer.writerows(data)
    
    print(f"บันทึกข้อมูลลงใน {filename} เรียบร้อยแล้ว")