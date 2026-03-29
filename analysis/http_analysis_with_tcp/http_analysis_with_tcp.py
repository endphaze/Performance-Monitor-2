import pyshark
import time
import os
from utility.outputmodel import StatModel, GeneralOutputModel
import pandas as pd
from dataclasses import asdict, dataclass
from collections import Counter, defaultdict, namedtuple
from datetime import datetime

@dataclass(slots=True)
class PacketRowData:
    number: int
    time: datetime
    payload_len: int
    response_time: int
    pending_req: int
    stream_id: str
    type: str

def get_all_pending_reqs(pending_request: defaultdict):
    """ฟังก์ชันช่วยหา Request ตกค้างโดยลูปเข้าไปดูใน pending request"""
    all = 0
    for v in pending_request.values():
        all += len(v)
    return all


def display_filter(target_ip, ports):
    if ports:
        port_filter = " or ".join([f"tcp.port == {p}" for p in ports])
        display_filter = f"ip.addr == {target_ip} and ({port_filter}) and tcp and tcp.payload > 0"
    else:
        display_filter = f"ip.addr == {target_ip} and tcp.payload > 0 and tcp"
    return display_filter


def analyze(capture_data, target_ip, output_folder = "", ports=[], limit=None, print_summary=True) -> GeneralOutputModel:
    """function analyze traffic that work with http/1.1 by checking behevior of tcp data transfer"""
    
    start_time = time.time()
    
    if output_folder == "":
        output_folder = "result"
    os.makedirs(f'{output_folder}', exist_ok=True)
    
    port_str = "_".join(map(str, ports)) if ports else "all"
    output_file = f"{output_folder}/{target_ip}_{port_str}_analysis.csv"
    
    # ลบไฟล์เก่าทิ้งก่อนเริ่มรันใหม่ (ถ้าต้องการ)
    if os.path.exists(output_file):
        os.remove(output_file)
        
    tshark_filterd_time = time.time() - start_time
    
    # เก็บค่าสถิติต่างๆ
    matched_pair = 0
    total_packets = 0
    total_requests = 0
    total_responses = 0
    chunk = [] # เก็บข้อมูลที่เป็นแถวเอาไปเขียน .csv
    chunk_size = 10000 # ถ้า chunk ถึง chunk_size จะหยุดแล้วเขียน ไม่ให้ใช้แรมเยอะ
    total_retransmission_packets = 0 # ยังอยู่ในขั้นทดสอบ
    endpoints_count = Counter()
    ports_count = Counter()
    resp_times = [] # เก็บ response time ทั้งหมด
    response_sizes = []
    request_sizes = []
    response_times = []

    # เก็บข้อมูลของ Request ล่าสุดแยกตาม Stream ID
    # ในแถวจะมีตารางของ Request ใน Stream ID โดยมี key คือ Expected Sequence
    # { 
    #   Steam ID 1 : {Expected Sequence 1: {ข้อมูลเวลา,index}, Expected Sequence 2: {ข้อมูลเวลา,index}, ...}
    #   Steam ID 2 : {Expected Sequence 3: {ข้อมูลเวลา,index}, Expected Sequence 4: {ข้อมูลเวลา,index}, ...} 
    # }
    pending_requests = defaultdict(dict)
    
    print(f"{'Stream':<8} | {"Req Index":<8} | {"Resp Index":<8} | {'Response Time (ms)':<12}")
    print("-" * 50)

    
    try:
        for pkt in capture_data:            
            if limit and total_packets > limit:
                break
            try:
                
                ip_layer = pkt.ip
                tcp_layer = pkt.tcp
                total_packets +=1
                stream_id = tcp_layer.stream
                curr_time = float(pkt.sniff_timestamp)
                payload_len = int(tcp_layer.len)
                
                row_data = PacketRowData(
                    number=pkt.number,
                    time=int(curr_time),
                    payload_len=payload_len,
                    response_time=0,
                    pending_req=get_all_pending_reqs(pending_requests),
                    stream_id=stream_id,
                    type=""
                )
                
                if len(chunk) >= chunk_size:
                    df_chunk = pd.DataFrame(chunk)
                    # append เข้าไปในไฟล์, header เขียนแค่ครั้งแรกที่สร้างไฟล์
                    df_chunk.to_csv(output_file, mode='a', index=False, 
                                header=not os.path.exists(output_file))
                    chunk = [] # เคลียร์แรม
                    print(f"Saved chunk: {total_packets} packets processed...")
                    
                    
                # แยกฝั่ง Client และ Server
                if ip_layer.src == ip_layer.dst:
                    # กรณี Loopback: ใช้ Port เป็นตัวตัดสินหลัก
                    is_from_client = (int(tcp_layer.dstport) in ports)
                else:
                    # กรณีทั่วไป: ใช้ IP ปลายทางเป็นตัวตัดสิน
                    is_from_client = (ip_layer.dst == target_ip)
                    
                

                # 1. ถ้ามี Data จาก Client -> Server ตัดสินว่านี่คือ Request
                if is_from_client:
                    # ตรวจสอบว่ามี packet request อันเดียวกันมั้ย
                    
                    if stream_id in pending_requests:
                        # print(f"packet number {pkt.number} have segment in pending requests")
                        # ลอง pop โดยใช้ seq number ก่อนถ้าได้ค่ามาแสดงว่าเป็น request เดียวกัน
                        prev_req_segment = pending_requests[stream_id].pop(tcp_layer.seq, None)
                        
                        if prev_req_segment:
                            # update ข้อมูล request เป็น segment ล่าสุด
                                
                            new_req = pending_requests[stream_id][tcp_layer.nxtseq] = {"idx": pkt.number,
                                                                                       "payload_len": prev_req_segment["payload_len"]+payload_len}
                            
                            row_data.type = "continuation"
                            if prev_req_segment.get("retransmission", None):
                                row_data.type = "retransmission of request"
                                total_retransmission_packets += 1
                                new_req["retransmission"] = True
                                print(f"packet number {pkt.number} is continuation of retransmission {prev_req_segment["idx"]}")
                            else: 
                                print(f"packet number {pkt.number} is continuation of {prev_req_segment["idx"]}")
                           
                            
                        else:
                            # หากอยู่ใน Stream เดียวกันแต่ไม่ใช่ Segment ต่อจาก Request ที่แล้ว
                            # คาดว่าอาจเป็น retransmission ให้ mark เอาไว้ และสร้าง Request ใหม่
                            print(f"packet number {pkt.number} is suspected retransmission but create new request")
                            print(f"stream {stream_id}" ,pending_requests[stream_id])
                            # prev_request = pending_requests[stream_id][tcp_layer.nxtseq]
                            pending_requests[stream_id][tcp_layer.nxtseq] = {
                                                                            "idx": pkt.number,
                                                                            "retransmission" : True,
                                                                            "payload_len" : payload_len}
                            total_retransmission_packets += 1

                            row_data.type = "retransmission of request"
                            print(f"stream {stream_id}" ,pending_requests[stream_id])

                    else:
                        # ถ้าไม่เจอ Request เดิม สร้างข้อมูล Request ใหม่และนับค่าสถิติ

                        pending_requests[stream_id] = {"request_idx" : pkt.number,
                                                       "request_time": curr_time}
                        pending_requests[stream_id][tcp_layer.nxtseq] = {"idx": pkt.number,
                                                                         "payload_len": payload_len}
                        
                        print(f"packet number {pkt.number} is first request segment")
                        print(pending_requests[stream_id])
                        ports_count[tcp_layer.dstport] += 1
                        endpoints_count[ip_layer.src] += 1
                        row_data.type = "request"
                        total_requests += 1
                        

                #     #print("request:stream_id", stream_id, payload_len, f"index: {pkt.number}")

                
                # 2. ถ้ามี Data จาก Server -> Client ตัดสินว่านี่คือ Response
                elif not is_from_client:
                    
                    if stream_id in pending_requests:
                        # ลอง pop มาก่อน ถ้าใช่จับคู่ เก็บค่าสถิติ
                        req = pending_requests[stream_id].pop(tcp_layer.ack, None)
                        if req:
                                
                            
                            
                            request_idx = pending_requests[stream_id].pop("request_idx", None)
                            request_time = pending_requests[stream_id].pop("request_time", None)
                            
                            
                            app_res_time = (curr_time - request_time) * 1000
                            request_sizes.append(int(tcp_layer.ack)-1)
                            resp_times.append(round(app_res_time,3))
                            response_sizes.append(req["payload_len"])
                            
                            matched_pair += 1
                            total_responses += 1
                            
                            row_data.type = "response"
                            row_data.response_time = round(app_res_time, 3)
                            
                            # print log
                            print(f"packet number {pkt.number} is response for {request_idx} with Response Time {round(app_res_time,3)} ")
                        else:
                            # อาจเป็นการส่ง Continuation ของ Response
                            # ไม่มี Request รอรับอยู่ คาดว่าเป็น Response Retransmission
                            print(f"packet number {pkt.number} is suspected retransmission or continuation of response")
                            row_data.type = "suspected retransmission or continuation of response"
                        
                # ใส่ลง chunk เตรียมเขียนเป็น csv
                chunk.append(asdict(row_data))
            except Exception as e:
                print(e)
                continue
        
        
        # หาว่ามี request หลงเหลืออยู่เท่าไหร่
        cant_find_response = 0
        for reqs in pending_requests.values():
            cant_find_response += len(reqs)
        exec_time = time.time() - start_time
        # แสดงผลสรุป
        if print_summary:
            print("matched pairs", matched_pair)
            print(StatModel.from_list(resp_times))
            print("display filtered ", display_filter)
            print("total packets from tshark filtered", total_packets)
            print("total requests", total_requests)
            print("total responses", total_responses)
            print("total retransmission", total_retransmission_packets)
            print("requests can't find respone", cant_find_response)
            print("tcp stream connection counts", len(pending_requests))
            
            print("excuted time", exec_time)
            print(request_sizes)
                
    finally:
        capture_data.close()
        
        # บันทึกข้อมูลที่เหลืออยู่ใน chunk สุดท้าย (ถ้ามี)
        if chunk:
            pd.DataFrame(chunk).to_csv(output_file, mode='a', index=False, 
                                     header=not os.path.exists(output_file))
            
        # คำนวณเวลาที่ฟังก์ชันประมวลผล
        
        
        # คืนค่าเป็น Output Model
        return GeneralOutputModel(
        target_ip=target_ip,
        tshark_filtered_time=tshark_filterd_time,
        exec_time=exec_time,
        total_packets_count=total_packets, # ในโหมดนี้จะเป็น count ของ filtered packets
        relevant_packets_count=matched_pair,
        top_endpoints=endpoints_count.most_common(5),
        top_ports=ports_count.most_common(5),
        response_size=StatModel.from_list(response_sizes),
        request_size=StatModel.from_list(request_sizes),
        response_time=StatModel.from_list(response_times),
        csv_file=output_file
    )
