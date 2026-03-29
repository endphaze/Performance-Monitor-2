from dataclasses import asdict
from fastapi import APIRouter
from concurrent.futures import ThreadPoolExecutor
from pymongo import MongoClient

import pyshark
import asyncio
import importlib
import inspect
import json

from utility.base_report import BaseDashboardGenerator
from core.config import settings
import core.data as data

# สร้าง Executor ไว้จำกัดจำนวน Thread (ป้องกัน CPU พุ่ง)
executor = ThreadPoolExecutor(max_workers=4)

router = APIRouter(
    prefix="/analysis",    # ทุก API ในไฟล์นี้จะขึ้นต้นด้วย /analysis
    tags=["analysis"]      # ช่วยจัดกลุ่มในหน้า /docs
)

@router.get("/run_pcap_analysis")
async def run_pcap_analysis():
    if not data.analysis_module:
        return "active script not set. you need to set first"
    
    if settings.pcap_file == "":
        return "you need to select pcap file"
    
    loop = asyncio.get_event_loop()
    loop.run_in_executor(
        executor, 
        pcap_analysis_task,
        data.analysis_obj, settings.pcap_file, "NetworkAnalysis", data.analysis_name,
        settings.target_ip, settings.ports, settings.chunk_size, settings.db_uri
    )
    
    return {"status": ".pcap Analysis started in background"}


