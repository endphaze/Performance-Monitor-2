import importlib, pkgutil, inspect, sys

from utility.base_analysis import BaseAnalysis
import core.data
import analysis

def list_analysis_scripts():
    for loader, sub_dir, is_pkg in pkgutil.iter_modules(analysis.__path__):
        full_module_name = f'analysis.{sub_dir}.{sub_dir}'

        # ลองเช็คว่า module นั้นมี function analysis มั้ย
        module = importlib.import_module(full_module_name)
        # ถ้ามีก็เอาใส่ list ให้ user เลือก
        
        for name, obj in inspect.getmembers(module):
            if inspect.isclass(obj) and issubclass(obj, BaseAnalysis) and obj is not BaseAnalysis:
                
                core.data.module_list.append({"name" :sub_dir,"class":obj})
            
        del sys.modules[full_module_name] # ลบออกจาก Cache ของ Python
        del module                        # ลบตัวแปรที่เก็บ Object ไว้