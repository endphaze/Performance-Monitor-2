
from datetime import datetime
from utility.base_analysis import BaseAnalysis
from dataclasses import dataclass
from colorama import Fore

class SynScanDetect(BaseAnalysis):
    
    @dataclass
    class RowData:
        frame_number : int
        time : float
        ip_src : str
        ip_dst : str
        flood_alert : str
        
    
    def __init__(self, target_ip="192.168.1.2", ports=[80], threshold=80):
        super().__init__(target_ip, ports)
        self.first_time = None
        self.syn_count = 0
        self.threshold = int(threshold)
    
    def display_filter(self):
        return f"tcp and tcp.flags.syn == 1 and tcp.flags.ack == 0 and ip.dst == {self.target_ip}"

    def fields(self):
        return ["frame.number", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport", "frame.time_epoch", "tcp.flags.syn"]
    
    def analyze(self, pkt):
        flag_syn = True if pkt.get("tcp_flags_syn") == "True" else False
        flag_ack = False if pkt.get("tcp_flags_ack") == "True" else False
        curr_time = float(pkt.get("frame_time_epoch"))
        frame_number = float(pkt.get("frame_number"))
        ip_src = pkt.get("ip_src")
        ip_dst = pkt.get("ip_dst")
        tcp_srcport = pkt.get("tcp_srcport")
        tcp_dstport = pkt.get("tcp_dstport")
        dt_object = datetime.fromtimestamp(curr_time)
        formatted_time = dt_object.strftime("%m/%d-%H:%M:%S.%f")
        self.syn_count += 1
                
        rowData = self.RowData(
            frame_number = frame_number,
            time = curr_time,
            ip_src = ip_src,
            ip_dst = ip_dst,
            flood_alert = ""
        )

        # print(formatted_time)  
        
        if flag_syn and not flag_ack and ip_dst == self.target_ip:
            
            if self.first_time is None:
                self.first_time = int(curr_time)
            
            if int(curr_time) == self.first_time:
                if self.syn_count > self.threshold:
                    print(self.syn_count, formatted_time,f"{Fore.RED}syn flood detect", f"{ip_src}:{tcp_srcport} > {ip_dst}:{tcp_dstport}")
                    rowData.flood_alert = "flood"
            else:
                self.first_time = int(curr_time)
                self.syn_count=0
            
            self.result_chunk.append(rowData)
            
            
        
        