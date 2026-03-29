from utility.base_analysis import BaseAnalysis
from dataclasses import dataclass
from core.config import settings
from collections import Counter, defaultdict

from colorama import Fore, Back, Style, init
import time



class PacketNode:
        def __init__(self, number, seq, payload_len, time):
            self.seq = int(seq)
            self.payload_len = payload_len
            self.time = time
            self.nxtseq = int(seq) + payload_len
            self.number = number
            self.next = None
    
    
class RequestLinkList:
    def __init__(self):
        self.head = None
        self.tail = None
        self.lastest_node = None
        self.total_payload = 0
        self.retransmission_payload = 0
        self.start_time = 0
        self.dup_ack = defaultdict(int)
    
    def insert_ack(self, ack):
        if ack in self.dup_ack:
            print(f"{Fore.RED}found dup ack")
            self.dup_ack[ack] += 1
        else:
            self.dup_ack[ack] += 1
        print(self.dup_ack)
            
        

    def insert_sorted(self, number, seq, ack, payload_len, time, row_data):
        new_node = PacketNode(number, seq, payload_len, time)
        print(f"found node {new_node.seq} ", end="")
        
        # if seq in self.dup_ack and self.dup
        # กรณีที่ 1: ลิสต์ว่าง หรือ seq ใหม่น้อยกว่าตัวแรกต้องแทรกที่หัว
        if self.head is None or new_node.seq < self.head.seq:
            if self.head is None:
                self.start_time = time
            
            new_node.next = self.head
            self.head = new_node
            if self.tail is None:
                self.tail = new_node
            self.total_payload += payload_len
            self.lastest_node = new_node
            self.traverse()
            return

        # กรณีที่ 2: วนลูปหาตำแหน่งที่เหมาะสม 
        
        current = self.head
        while current.next is not None and new_node.seq > current.next.seq:
            current = current.next
        
        
        # if current.next and (new_node.seq == current.next.seq):
        #     print(f"{Fore.RED}this is retransmission")
        #     self.retransmission_payload += payload_len
        #     row_data.retransmission = True
        #     return
        # elif new_node.seq == current.seq:
        #     self.retransmission_payload += payload_len
        #     row_data.retransmission = True
        #     print(f"{Fore.RED}this is retransmission")
        #     return
        
        # แทรก node
        if new_node.seq > self.tail.seq:
            self.tail = new_node
            print(f"{Fore.BLUE}set new tail")

        new_node.next = current.next
        current.next = new_node
        self.lastest_node = new_node
        self.total_payload += payload_len
        self.traverse()
        
    def traverse(self):
        current = self.head
        while current is not None:
            print(f"{current.seq}>", end="")
            current = current.next
        print(f"{Fore.LIGHTYELLOW_EX}head = {self.head.seq} and tail = {self.tail.seq} lastest node next seq = {self.lastest_node.nxtseq}")
        print()
        
        

        
class HTTP11_Analysis_By_TCP(BaseAnalysis):
    
    @dataclass(slots=True)
    class RowData:
        number: int
        time: float
        endpoint : str
        port : int
        payload_len: int
        request_size : int
        response_time: int
        stream_id: str
        type: str
        retransmission: bool
        response_of : int
        
    
    def __init__(self, target_ip, ports):
        super().__init__(target_ip, ports)
        self.pending_requests = defaultdict(dict)

    def fields(self):
        return ["frame.number", "ip.src", "ip.dst", "tcp.seq", "tcp.ack", "tcp.nxtseq",
                "tcp.len", "tcp.stream", "tcp.dstport", "frame.time_epoch", "tcp.analysis.retransmission", 
                "tcp.analysis.fast_retransmission", "tcp.flags.syn", "tcp.flags.ack", "tcp.analysis.acks_frame"]

    def display_filter(self):
        if self.ports:
            port_filter = " or ".join([f"tcp.port == {p}" for p in self.ports])
            display_filter = f"ip.addr == {self.target_ip} and ({port_filter}) and tcp.len > 0"
        else:
            display_filter = f"ip.addr == {self.target_ip} and tcp.len > 0"
        return display_filter
    
    def get_all_pending_reqs(self):
        """ฟังก์ชันช่วยหา Request ตกค้างโดยลูปเข้าไปดูใน pending request"""
        all = 0
        for v in self.pending_requests.values():
            all += len(v)
        return all
    
    def analyze(self, pkt):
        frame_number = pkt["frame_number"]
        ip_src = pkt["ip_src"]
        ip_dst = pkt["ip_dst"]
        tcp_seq = int(pkt["tcp_seq"])
        tcp_ack = int(pkt["tcp_ack"])
        tcp_len = int(pkt["tcp_len"])
        tcp_dstport = pkt["tcp_dstport"]
        stream_id = pkt["tcp_stream"]
        retransmission = bool(pkt.get("tcp_analysis_retransmission")) or bool(pkt.get("tcp_analysis_fast_retransmission"))
        curr_time = float(pkt["frame_time_epoch"])
        
        
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
        
        # แยกฝั่ง Client และ Server
        if ip_src == ip_dst:
            # กรณี Loopback: ใช้ Port เป็นตัวตัดสินหลัก
            is_from_client = (int(tcp_dstport) in self.ports)
        else:
            # กรณีทั่วไป: ใช้ IP ปลายทางเป็นตัวตัดสิน
            is_from_client = (ip_dst == self.target_ip)
            
        
        # if not is_from_client and tcp_len == 0:
        #     if stream_id in self.pending_requests:
        #         print(f"pkt {frame_number} {Fore.CYAN}server acknowledge")
        #         self.pending_requests[stream_id].insert_ack(tcp_ack)
        #     else:
        #         self.pending_requests[stream_id] = RequestLinkList()
        #         print(f"pkt {frame_number} {Fore.CYAN}{Back.WHITE}server first acknowledge")
        #         self.pending_requests[stream_id].insert_ack(tcp_ack)

        # 1. ถ้ามี Data จาก Client -> Server ตัดสินว่าเป็น Request
        if is_from_client and tcp_len:
                # ตรวจสอบว่ามี packet request ในตารางข้อมูลมี Stream ID เดียวกันมั้ย
            
            if stream_id in self.pending_requests:

                # print(f"packet number {frame_number} have segment in pending requests")
                # ลอง pop โดยใช้ seq number ก่อนถ้าได้ค่ามาแสดงว่าเป็น request เดียวกัน
                
                row_data.type = "request_continue"
                print(f"packet number = {frame_number} stream_id={stream_id}")
                self.pending_requests[stream_id].insert_sorted(frame_number, tcp_seq, tcp_ack, tcp_len, curr_time, row_data)


            else:
                # ถ้าไม่เจอ Request เดิม สร้างข้อมูล Request ใหม่และนับค่าสถิติ
                if not retransmission:    
                    print(f"packet number = {frame_number} stream_id={stream_id}")   
                    self.pending_requests[stream_id] = RequestLinkList()
                    self.pending_requests[stream_id].insert_sorted(frame_number, tcp_seq, tcp_ack, tcp_len, curr_time, row_data)

                    row_data.port = tcp_dstport
                    row_data.endpoint = ip_src
                    row_data.type = "request"
                
        # 2. ถ้ามี Data จาก Server -> Client ตัดสินว่าเป็น Response
        elif not is_from_client:
            
            if stream_id in self.pending_requests:
                
                # เมื่อพบ Response โดยไม่สนว่า Out of Order หรือไม่ 
                if int(tcp_ack) == self.pending_requests[stream_id].tail.nxtseq:
                    
                    link_list = self.pending_requests.pop(stream_id)
                    print(f"{Fore.GREEN}found {tcp_ack} == {link_list.tail.nxtseq}")
                    print(f"{Fore.GREEN}I think {frame_number} is reponse of {link_list.tail.number} and stream id={stream_id}")
                    print(f"{Fore.GREEN}{curr_time} - {link_list.tail.time} response time = {round(curr_time-link_list.start_time,6)*1000}")
                    
                    row_data.response_time = round(curr_time-link_list.start_time,6)*1000
                    row_data.type = "response"
                    row_data.request_size = link_list.total_payload
                    row_data.response_of = link_list.tail.number
                    
            else:
                row_data.type = "continuation response or retransmision response"
                    
                    
        self.result_chunk.append(row_data)