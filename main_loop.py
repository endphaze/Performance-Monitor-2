import os
import inspect
from colorama import init


from dataclasses import asdict
from utility.base_analysis import BaseAnalysis
from utility.list_analysis_scripts import list_analysis_scripts
from utility.running_pcap_analysis import pcap_analysis_task
from core.config import settings
from core.database import db, client
import core.data


if __name__ == "__main__":
    
    init(autoreset=True) # ของ colorama
    
    print("initialize folder...")
    os.makedirs(settings.upload_dir, exist_ok=True)
    os.makedirs(settings.result_dir, exist_ok=True)
    
    print("check available analysis script...")
    list_analysis_scripts()
    module_list = core.data.module_list
    for i, module in enumerate(module_list, 1):
        print(f"[{i}] {module["name"]}")
        
    # print("seperate with , (e.g. 1,2)")
    choices = input("choose analysis script : ")
    
    print("choose script complete!")
    for choice in choices.split(","):
        choice = choice.strip() # เอา space ออก
        func_signature = inspect.signature(module_list[int(choice)-1]["class"])
        
        args = []
        # load param
        for name, param in func_signature.parameters.items():
            param_type = type(param.default).__name__
            value = ""
            print(f" - Name: {name}")
            print(f"   Example: {param.default}")
            print(f"   Type:", {param_type})
            print(f"   Kind: {param.kind}") # บอกว่าเป็นตำแหน่งปกติ หรือ keyword-only เป็นต้น
            
            if isinstance(param.default, list):
                print(", to seperate data 10,100,1000")
                value = []
                list_inputs = input("Enter List Parameter Value: ").split(",")
                for inp in list_inputs:
                    if inp == "":
                        break
                    value.append(inp)
            else:
                value = input("Enter Parameter Value: ")
                
            if len(value) > 0:
                args.append(value)
            else:
                args.append(param.default)
            
        
        pcap_analysis_task(int(choice), args)

    client.close()
        
        
        
# for loader, module_name, is_pkg in pkgutil.iter_modules(analysis.__path__):
#         # สร้าง path เต็ม
#     full_module_name = f'analysis.{module_name}'
#     module = importlib.import_module(full_module_name)
#     # ตรวจสอบว่ามีฟังก์ชัน analyze อยู่ในไฟล์นั้นไหม
    
#     if hasattr(module, 'display_filter'):
#         display_filter_func = getattr(module, 'analyze')
#         display_filter = display_filter_func(target_ip, ports)
#     pyshark.FileCapture()
    # if hasattr(module, 'analyze'):
    #     print(f"--- Running {module_name} ---")
    #     analyze_func = getattr(module, 'analyze')
    #     result = analyze_func()
    # else:
    #     print(f"Skipping {module_name} : 'analyze' function not found.")



#     for in icmp
#     cap1 get_display_filtered

# if len(chunk) >= chunk_size:
#     df_chunk = pd.DataFrame(chunk)
#     # append เข้าไปในไฟล์, header เขียนแค่ครั้งแรกที่สร้างไฟล์
#     df_chunk.to_csv(output_file, mode='a', index=False, 
#                 header=not os.path.exists(output_file))
#     chunk = [] # เคลียร์แรม
#     print(f"Saved chunk: {total_packets} packets processed...")