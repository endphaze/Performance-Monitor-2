import pyshark

import pandas as pd
from core.config import settings
from dataclasses import asdict, dataclass
from utility.outputmodel import StatModel, BaseOutputModel
from utility.base_analysis import BaseAnalysis

class ICMP_RTT_Analysis(BaseAnalysis):
    
    @dataclass
    class RowData:
        timestamp: int
        src_ip: str
        rtt: float
    
    def display_filter(self):
        return f"icmp and ip.addr == {settings.target_ip}"
    
    def analyze(self, pkt):
        rowData = self.RowData(
            timestamp=int(float(pkt.sniff_timestamp)),
            src_ip=pkt.ip.src,
            rtt= float(getattr(pkt.icmp, "resptime", "0"))
        )
        print(rowData)
        self.result_chunk.append(rowData)
            
        

        