import asyncio
import subprocess
import json
import threading
import time

from fastapi import APIRouter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
import queue

import core.data
from core.config import settings
from core.database import db

router = APIRouter(
    prefix="/live",    # ทุก API ในไฟล์นี้จะขึ้นต้นด้วย /analysis
    tags=["live"]      # ช่วยจัดกลุ่มในหน้า /docs
)

tshark_process = None

main_executor = None
packet_queue = queue.Queue(maxsize=settings.queue_size)

def insert_data(analysis_obj):
    data_to_insert = [asdict(row) for row in analysis_obj.pop_result_chunk()]
    if data_to_insert:    
        analysis_obj.collection.insert_many(data_to_insert)


def tshark_worker(bpf_filter, fields, analysis_obj_list, custom_option_list):
    global tshark_process
    
    cmd = [
        "tshark", "-i", settings.interface,
        "-f", bpf_filter,
        "-T", "ek",
        "-l",
        "--disable-protocol", "openflow",
    ]
    
    for field in fields:
        cmd.extend(["-e", field])
        
    for option in custom_option_list:
        cmd.extend(option)
    
    print("Tshark Command:", cmd)
    # ใช้ Popen เพื่ออ่าน Output ทันทีที่ TShark 
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
    tshark_process = process
    
    try :
        index = 0
        total_packet = 0
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
            
            
            # for analysis_obj in analysis_obj_list:
            #     executor.submit(analysis_obj.analyze, clean_pkt.copy())
            
            packet_queue.put(clean_pkt)
            
            
    finally :
        
        
        packet_queue.put(None)
        
        
            
        # ปิด process ต่างๆ
        tshark_process = None
        process.terminate()
        process.wait()
        


def packet_analyze(analysis_obj_list):
    last_insert_time = time.time()
    index = 0
    total_packet = 0
    
    while True:
        pkt = packet_queue.get()
        if pkt is None: # เจอสัญญาณหยุด
            
            # บันทึกผลลัพธ์ก้อนสุดท้ายลงฐานข้อมูล
            for analysis_obj in analysis_obj_list:
                analysis_obj.end_executed_time()
                analysis_obj.set_total_packet(total_packet)

                insert_data(analysis_obj)
            
            # ออกจาก While Loop        
            packet_queue.task_done()
            break
            
        # วิเคราะห์ข้อมูล
        for analysis_obj in analysis_obj_list:
            analysis_obj.analyze(pkt)
        
        # ตรวจสอบเงื่อนไขเวลาหรือขนาดเพื่อ Insert
        current_time = time.time()
        index += 1
        total_packet += 1    
        if current_time - last_insert_time >= 3.0 or index >= settings.chunk_size:
            for analysis_obj in analysis_obj_list:
                main_executor.submit(insert_data, analysis_obj)
            index = 0
            last_insert_time = current_time
        
        
        packet_queue.task_done()
    


@router.post("/start")
async def start_live_analysis():
    global main_executor
    # check ว่ามี tshark process อยู่มั้ย
    if tshark_process:
        return "Tshark already process"
    
    
    analysis_obj_list= []
    # สร้าง bpf filter ก่อน
    ip_list = []    
    ports_set = set()
    
    for args in core.data.analysis_args:
        ip_list.append(args["target_ip"])
        current_ports = args.get("ports", [])
        print(current_ports)
        if isinstance(current_ports, list):
            for p in current_ports:
                ports_set.add(str(p)) # เก็บเป็น String ไว้เตรียม join
        else:
            ports_set.add(str(current_ports))
        
    # 1. สร้าง IP Filter
    ip_filter = " or ".join([f"host {ip}" for ip in set(ip_list) if ip])

    # 2. สร้าง Port Filter
    port_filter = " or ".join([f"port {p}" for p in ports_set if p])
    
    filters = []
    if ip_filter: 
        filters.append(f"({ip_filter})")
    if port_filter: 
        filters.append(f"({port_filter})")

    bpf_filter = " and ".join(filters)
    print(f"Final BPF Filter: {bpf_filter}")    

    # จบขั้นนี้จะได้ bpf_filter
    
    # สร้าง set fields เพื่อบอกว่าจะเอา fields อะไรบ้าง
    # initialize analysis obj
    # drop mongodb collection ของอันเดิม
    
    fields_set = set()
    custom_option_list = []
    
    for i, analysis in enumerate(core.data.selected_analysises):
        analysis_obj = analysis["class"](**core.data.analysis_args[i])
        analysis_obj_list.append(analysis_obj)
        
        db[analysis["name"]].drop()
        
        for field in analysis_obj.fields():
            fields_set.add(field)
            
        custom_tshark_options = analysis_obj.custom_tshark_options()
        if custom_tshark_options:        
            for option in analysis_obj.custom_tshark_options():
                custom_option_list.append(option)
        
    print(f"Final Fields: {fields_set}")            
        
    # ข้อมูลพร้อมสำหรับรัน Analysis
    
    # clear queue
    while not packet_queue.empty():
        try:
            packet_queue.get_nowait()
        except:
            break
    
    main_executor = ThreadPoolExecutor(max_workers=len(analysis_obj_list) + 5)

    loop = asyncio.get_running_loop()
    
    loop.run_in_executor(
        main_executor, 
        tshark_worker, # tshark ดักจับแพ็กเก็ต
        bpf_filter, 
        fields_set,
        analysis_obj_list,
        custom_option_list
    )
    
    loop.run_in_executor(
        main_executor,
        packet_analyze, # การวิเคราะห์
        analysis_obj_list
    )
    
    return {
            "status": "started",
            "bpf": bpf_filter,
            "fields": list(fields_set)
    }
    
    
    
@router.post("/stop")
async def stop_live_analysis():
    global tshark_process, main_executor
    
    if not tshark_process:
        return "No analysis is running"
    # สั่งหยุด process
    tshark_process.terminate() 
    
    # ลูปใน tshark_worker จะหลุดออกมาเพราะ process.stdout จะปิดลง
    # แล้วมันจะไปทำงานในบล็อก finally เพื่อบันทึกชุดสุดท้ายลง DB
    
    if main_executor:
        main_executor.shutdown(wait=True) # รอจนกว่างานสุดท้ายจะลง DB เสร็จ
        main_executor = None
        
    return {"status": "stopped"}