from pydantic import BaseModel, IPvAnyAddress, Field, computed_field
import statistics
import numpy as np


class BaseOutputModel(BaseModel):
    target_ip : IPvAnyAddress
    exec_time : float
    csv_file: str

class StatModel(BaseModel):
    """กลุ่มข้อมูลสถิติพื้นฐาน Min Max Average"""
    min: float
    max: float
    avg: float
    stddev: float
    
    @classmethod
    def from_list(cls, data: list):
        if not data:
            return cls(min=0, max=0, avg=0, stddev=0)
        
        arr = np.array(data)
        return cls(
            min=arr.min(),
            max=arr.max(),
            avg=arr.mean(),
            stddev=arr.std() if len(data) > 1 else 0
        )
    

class GeneralOutputModel(BaseOutputModel):
    total_packets_count : int
    relevant_packets_count : int
    request_size : StatModel
    response_size : StatModel
    response_time : StatModel
    tshark_filtered_time : float
    top_ports : list[tuple]
    top_endpoints : list[tuple]
    