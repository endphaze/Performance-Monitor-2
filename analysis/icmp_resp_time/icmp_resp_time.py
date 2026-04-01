from utility.base_analysis import BaseAnalysis
from dataclasses import dataclass

class ICMPRespTime(BaseAnalysis):
    
    @dataclass(slots=True)
    class RowData:
        # ข้อมูลที่อยากบันทึกผลลัพธ์
        ip_src : str
        ip_dst : str
        resp_time : float
    
    def __init__(self, target_ip, ports, threshold):
        super().__init__(target_ip, ports)
        self.threshold = threshold
        
    def display_filter(self):
        return "icmp"
    
    def fields(self):
        return ["frame.number", "ip.src", "ip.dst", "icmp.resptime"]
    
    def analyze(self, pkt):
        frame_number = pkt.get("frame_number")
        ip_src = pkt.get("ip_src")
        ip_dst = pkt.get("ip_dst")
        resp_time = pkt.get("icmp_resptime")
        
        rowData = self.RowData(
            ip_src=ip_src,
            ip_dst=ip_dst,
            resp_time=0
        )
        
        if resp_time:
            rowData.resp_time = float(resp_time)
        
        print(rowData)
        
        self.result_chunk.append(rowData)