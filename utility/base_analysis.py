from abc import ABC, abstractmethod
from dataclasses import dataclass
from core.config import settings
from core.database import db

from pathlib import Path
import os, inspect, sys
import pandas as pd
import time


class BaseAnalysis(ABC):

    def __init__(self, target_ip, ports):
        self.target_ip =  target_ip
        self.ports = ports
        self.result_chunk = [] # หากสืบทอดแล้วให้ append ผลลัพธ์เข้า list นี้ เพื่อบันทึกผลลัพธ์เข้า MongoDB
        self.start_time = time.time()
        self.executed_time = 0
        module_path = self.__class__.__module__
        last_name = module_path.split('.')[-1]
        self.analysis_name = last_name
        self.collection = db[self.analysis_name]
        self.total_packet = 0

    @property
    @abstractmethod 
    def RowData(self):
        pass

    @abstractmethod # จะใช้กับ pcap analyze ได้
    def display_filter(self) -> str:
        pass
    
    @abstractmethod
    def fields(self) -> list:
        pass
    
    @abstractmethod
    def analyze(self, pkt):
        pass

    def end_executed_time(self):
        self.executed_time = time.time() - self.start_time
    
    def start_executed_time(self):
        self.start_time = time.time()
    
    def custom_tshark_options(self):
        pass
    
    def pop_result_chunk(self):
        data = self.result_chunk.copy()
        self.result_chunk.clear()
        return data
    
    def set_total_packet(self, total_packet):
        self.total_packet = total_packet