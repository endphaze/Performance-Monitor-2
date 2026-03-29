from fastapi import APIRouter
from pydantic import BaseModel
from typing import List
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

class AnalysisSelection(BaseModel):
    selected_analysis_list: List[int] 

@router.get("/get_analysis_scripts_list")
async def get_analysis_scripts():
    data.module_list.clear()
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

@router.post("/select_active_analysises")
async def select_active_analysises(numbers_analysis: str):
    data.selected_analysises.clear()
    if not data.module_list:
        print("analysis script need to load with /get_analysis_scripts_list")
        return "analysis script need to load with /get_analysis_scripts_list"
    for i in numbers_analysis.split(",") :
        data.selected_analysises.append(data.module_list[int(i)])
            
    return numbers_analysis

@router.get("/load_parameter")
async def load_parameter():
    params_dict = {}
    for analysis in data.selected_analysises:
        func_signature = inspect.signature(analysis["class"])
        params_dict[analysis["name"]] = {}
        for name, param in func_signature.parameters.items():
            params_dict[analysis["name"]][name] = type(param.default).__name__
            
    return params_dict

@router.post("/set_arguments")
async def set_arguments(body : dict):
    data.analysis_args.clear()
    
    for key, args in body.items():
        data.analysis_args.append(args)
    
    return data.analysis_args
    

# async def run_pcap_analysis(args)
#     func(*args)

