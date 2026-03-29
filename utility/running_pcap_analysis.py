from dataclasses import asdict

import pyshark, importlib, inspect
import pandas as pd
import subprocess, json

from core.database import db
from core.config import settings
import core.data

module_list = core.data.module_list


def stream_tshark_output(display_filter, fields=[]):
    cmd = [
        "tshark", "-r", f"{settings.pcap_file}",
        "-Y", f"{display_filter}",
        "-T", "ek",
        "--disable-protocol", "openflow",
    ]
    
    for field in fields:
        cmd.extend(["-e", field])
    
    # ใช้ Popen เพื่ออ่าน Output ทันทีที่ TShark 
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
    try :
        
        for line in process.stdout:
            line = line.strip()
            if not line or line.startswith('{"index"'):
                continue
                
            pkt_raw = json.loads(line)
            layers = pkt_raw.get("layers", {})
            
            # สร้าง Dictionary ใหม่ที่จะเก็บข้อมูล
            # เริ่มใส่ timestamp ลงไปก่อน
            clean_pkt = {
                "timestamp": pkt_raw.get("timestamp")
            }
            
            # วนลูปเพื่อดึงข้อมูลจาก layers ออกมาวางไว้ที่ระดับบนสุด
            for key, value in layers.items():
                if isinstance(value, list):
                    if len(value) == 1:
                        clean_pkt[key] = value[0] # ยุบเป็นค่าเดี่ยว
                    elif len(value) > 1:
                        clean_pkt[key] = value    # ถ้ามีหลายค่า เก็บเป็น List ไว้
                    else:
                        clean_pkt[key] = None
                else:
                    clean_pkt[key] = value
            
            yield clean_pkt
    finally :
        process.terminate()
        process.wait()


def pcap_analysis_task(choice, args, limit=None):
    # เริ่มต้น analysis object
    analysis_module = module_list[choice-1]
    analysis_obj = analysis_module["class"](*args)
    analysis_name = analysis_obj.analysis_name
    
    path_analysis_module = f"analysis.{analysis_name}"

    print("create analysis obj complete!")
    
    # เช็คว่ามี collection อันเก่ามั้ย ถ้ามี drop collection อันเก่าทิ้ง
    if analysis_name in db.list_collection_names():
            print(f"[{analysis_name}] Found existing collection. Dropping for new start...")
            analysis_obj.collection.drop()
    
    collection = analysis_obj.collection

    # import report ที่เราทำไว้ เอา function generate_report มาใช้
    report_module = importlib.import_module(path_analysis_module+".report")
    generate_report_func = getattr(report_module, "generate_report")
    
    # ใช้ function display_filter ของ analysis_obj เพื่อให้ได้ Filter ที่ต้องการของ Analysis นี้
    display_filter = analysis_obj.display_filter()
    fields = analysis_obj.fields()
    print(display_filter)
    print("delete older collection complete")
    
    cap = None
    print(f"--- Running {analysis_name} ---")
    
    # เริ่มอ่าน .pcap
    
    
    try:
        # ประมวลผลไฟล์ .pcap
        analysis_obj.start_executed_time()
        total_packet = 0
        index = 0
        
        for pkt in stream_tshark_output(display_filter, fields):
            # เรียกฟังก์ชัน analyze เพื่อเริ่มการวิเคราะห์ โดยให้ข้อมูลแพ็กเก็ตไป
            analysis_obj.analyze(pkt)
            
            # นับแพ็กเก็ตรวม และ index ไว้จับว่าวิเคราะห์กี่แพ็กเก็ตแล้ว
            index += 1
            total_packet += 1
            
            # ถ้ามี limit แล้วถึง limit ก็ break
            if limit and total_packet > limit:
                break
            
            # ถ้า index มากกว่า chunk_size ให้เขียนลงฐานข้อมูล
            if index > settings.chunk_size:
                data_to_insert = [asdict(row) for row in analysis_obj.pop_result_chunk()]
                if data_to_insert:    
                    result = collection.insert_many(data_to_insert)
                    print(f"[{analysis_name}] Inserted {len(result.inserted_ids)} docs to MongoDB")
                    index = 0
                
        
        # จบลูปการวิเคราะห์
        analysis_obj.end_executed_time()
        analysis_obj.set_total_packet(total_packet)
        final_chunk = analysis_obj.pop_result_chunk()
        
        # ผลลัพธ์ที่เหลือกใน chunk ให้เขียนลงฐานข้อมูล
        if final_chunk:
            data_to_insert = [asdict(row) for row in final_chunk]
            result = collection.insert_many(data_to_insert)
            print(f"[{analysis_name}] Last Inserted {len(result.inserted_ids)} docs to MongoDB")
        
    # except Exception as e:
    #         print(f"Error while running {analysis_name}: {e}")
    finally:
        print(f"--- Ending {analysis_name} ---")
        
        executed_time = round(analysis_obj.executed_time,3)
        print(f"executed time1 {executed_time} seconds")
        
        #นำ mongodb มาเขียน csv
        cursor = collection.find()
        df = pd.DataFrame(list(cursor))
        df.to_csv(f"{settings.result_dir}/{analysis_name}.csv", index=False, encoding="utf-8")
        print("export to csv complete!")
        
        
        if cap is not None:
            cap.close
        
        # เขียน report pdf เอา analysis_obj pass เข้าไปเพื่อใช้ข้อมูลต่อไป
        generate_report_func(analysis_obj)
        print("generate report complete")