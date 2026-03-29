from fastapi import APIRouter

import pkgutil, sys
import importlib
import inspect

from utility.base_analysis import BaseAnalysis
from core.config import settings
import core.data as data
import analysis

router = APIRouter(
    prefix="/analysis",    # ทุก API ในไฟล์นี้จะขึ้นต้นด้วย /settings
    tags=["analysis"]      # ช่วยจัดกลุ่มในหน้า /docs
)

@router.get("/get_analysis_scripts_list")
async def get_analysis_scripts():
    
    index = 0
    print("check available analysis script...")
    for loader, sub_dir, is_pkg in pkgutil.iter_modules(analysis.__path__):
        full_module_name = f'analysis.{sub_dir}.{sub_dir}'

        # ลองเช็คว่า module นั้นมี function analysis มั้ย
        module = importlib.import_module(full_module_name)
        # ถ้ามีก็เอาใส่ list ให้ user เลือก
        
        for name, obj in inspect.getmembers(module):
            if inspect.isclass(obj) and issubclass(obj, BaseAnalysis) and obj is not BaseAnalysis:
                
                data.module_list.append({"name" :sub_dir,"class":obj, "index":index})
                index += 1  
            
        del sys.modules[full_module_name] # ลบออกจาก Cache ของ Python
        del module                        # ลบตัวแปรที่เก็บ Object ไว้
          
        
    name_and_indexes = [(item["index"], item["name"]) for item in data.module_list]
    return name_and_indexes

@router.post("/set_active_scripts")
async def set_active_script(active_script_list : list):
    if not data.module_list:
        print("analysis script need to load with /get_analysis_scripts_list")
        return "analysis script need to load with /get_analysis_scripts_list"
    for i in active_script_list:
        data.selected_analysis.append(data.module_list[i]["class"])
    
async def load_parameter()

async def set_argument()

async def run_pcap_analysis(args)
    func(*args)

