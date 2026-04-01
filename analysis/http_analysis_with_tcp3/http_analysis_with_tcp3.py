from utility.base_analysis import BaseAnalysis
from dataclasses import dataclass
from core.config import settings
from collections import Counter, defaultdict

from colorama import Fore, Back, Style, init
import time


class HTTP11_Analysis_By_TCP(BaseAnalysis):
    
    @dataclass(slots=True)
    class RowData:
        number: int
        time: float
        endpoint : str
        port : int
        payload_len : int
        request_size : int
        response_time: int
        stream_id: str
        type: str
        retransmission: bool
        response_of : int
        
    def __init__(self, target_ip = "192.168.1.11", ports = [8080]):
        super().__init__(target_ip, ports)
        self.pending_requests = defaultdict(dict)

    def fields(self):
        return ["frame.number", "ip.src", "ip.dst", "tcp.seq", "tcp.ack",
                "tcp.len", "tcp.stream", "tcp.srcport", "tcp.dstport", "frame.time_epoch", "tcp.analysis.retransmission", 
                "tcp.nxtseq" , "tls.handshake", "tls.change_cipher_spec", "tls.alert_message"]

    def display_filter(self):
        if self.ports:
            port_filter = " or ".join([f"tcp.port == {p}" for p in self.ports])
            display_filter = f"ip.addr == {self.target_ip} and ({port_filter}) and tcp.len > 0"
        else:
            display_filter = f"ip.addr == {self.target_ip} and tcp.len > 0"
        return display_filter
    
    # def get_all_pending_reqs(self):
    #     """ฟังก์ชันช่วยหา Request ตกค้างโดยลูปเข้าไปดูใน pending request"""
    #     all = 0
    #     for v in self.pending_requests.values():
    #         all += len(v)
    #     return all
    
    def custom_tshark_options(self):
        # สำหรับใช้ field Retransmission
        return [["-o", "tcp.analyze_sequence_numbers:TRUE"]]
    
    def analyze(self, pkt):
        frame_number = pkt["frame_number"]
        ip_src = pkt["ip_src"]
        ip_dst = pkt["ip_dst"]
        tcp_seq = int(pkt["tcp_seq"])
        tcp_ack = int(pkt["tcp_ack"])
        tcp_len = int(pkt["tcp_len"])
        tcp_nxtseq = int(pkt["tcp_nxtseq"])
        tcp_dstport = pkt["tcp_dstport"]
        tcp_srcport = pkt.get("tcp_srcport")
        tcp_keep_alive = bool(pkt.get("tcp_analysis_keep_alive")) or  bool(pkt.get("tcp_analysis_keep_alive_ack"))
        stream_id = pkt["tcp_stream"]
        is_tls_process = bool(pkt.get("tls_handshake")) or bool(pkt.get("tls_change_cipher_spec")) or bool(pkt.get("tls_alert_message"))
        retransmission = bool(pkt.get("tcp_analysis_retransmission")) or bool(pkt.get("tcp_analysis_fast_retransmission"))
        curr_time = float(pkt["frame_time_epoch"])
        
        # test
        # print(f"http_analysis_work | {ip_src}:{tcp_srcport} > {ip_dst}:{tcp_dstport}")
        
        
        row_data = self.RowData(
                    number=frame_number,
                    time=int(curr_time),
                    payload_len=tcp_len,
                    response_time=0,
                    endpoint="",
                    port=None,
                    stream_id=stream_id,
                    request_size=0,
                    type="",
                    response_of=0,
                    retransmission=retransmission
                )
        
        is_from_client = None
        # แยกฝั่ง Client และ Server      
            
        if ip_src == ip_dst:
            # กรณี Loopback: ใช้ Port เป็นตัวตัดสินหลัก
            if isinstance(self.ports, list):
                is_from_client = (int(tcp_dstport) in self.ports)
            else:
                is_from_client = (int(tcp_dstport) == self.ports)
        else:
            # กรณีทั่วไป: ใช้ IP ปลายทางเป็นตัวตัดสิน
            is_from_client = (ip_dst == self.target_ip)
            
        
        
        # 1. ถ้ามี Data จาก Client -> Server ตัดสินว่าเป็น Request
        if is_from_client and tcp_len > 0 and not tcp_keep_alive and not is_tls_process:
            
            if stream_id in self.pending_requests:
                        
                if not retransmission:
                    
                    if tcp_nxtseq > self.pending_requests[stream_id]["nxtseq"]:
                        # print(f"{stream_id} update time {self.pending_requests[stream_id]["time"]} to {curr_time}")
                        # self.pending_requests[stream_id]["time"] = curr_time
                        self.pending_requests[stream_id]["nxtseq"] = tcp_nxtseq
                        self.pending_requests[stream_id]["size"] += tcp_len
                        self.pending_requests[stream_id]["frame_number"] = frame_number
                        
                    row_data.type = "request_continue"
                    
        
            else:
                # ถ้าไม่เจอ Request เดิม สร้างข้อมูล Request ใหม่และนับค่าสถิติ
                  
                if not retransmission:
                    self.pending_requests[stream_id] = {"time":curr_time,
                                                        "nxtseq": tcp_seq+tcp_len,
                                                        "size": tcp_len,
                                                        "frame_number": frame_number}
                    row_data.port = tcp_dstport
                    row_data.endpoint = ip_src
                    row_data.type = "request"
                    # print(f"pkt {frame_number} in stream id {stream_id} {Fore.CYAN}{Back.WHITE} is First Request Segment Found{Fore.RESET}{Back.RESET}")
                
                
        # 2. ถ้ามี Data จาก Server -> Client ตัดสินว่าเป็น Response
        elif not is_from_client and tcp_len > 0 and not tcp_keep_alive and not is_tls_process:
            if stream_id in self.pending_requests:
                
                # เมื่อพบ Response โดยไม่สนว่า Out of Order หรือไม่ 
                
                if tcp_ack == self.pending_requests[stream_id]["nxtseq"]:
                    request = self.pending_requests.pop(stream_id)
                    resp_time = round(curr_time-request["time"],6)*1000
                    
                    # print(f"pkt {frame_number} {Fore.GREEN} is response in pkt {request["frame_number"]} stream id {stream_id} with response time {resp_time}{Fore.RESET}{Back.RESET}")
                    # print(f"time {curr_time} - {request["time"]}")
                    row_data.response_time = resp_time
                    row_data.type = "response"
                    row_data.request_size = request["size"]
                    
                    
        self.result_chunk.append(row_data)