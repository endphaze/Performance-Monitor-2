import pyshark
import time
import os
import tools.utility as utility
import pandas as pd
from dataclasses import asdict
from collections import Counter, deque, defaultdict, namedtuple
from datetime import datetime

RESET = '\033[0m'
GREEN = '\033[32m'
RED = '\033[31m'
CYAN = '\033[96m'
BOLD = '\033[1m'
BLUE = '\033[94m'
YELLOW = '\033[93m'

def tcp_analyze(pcap_file, target_ip,output_folder="", ports=None) -> utility.TCPOutputModel:
    
    print(f"Reading {pcap_file} with PyShark...")
    

    
    # เริ่มจับเวลา
    start_time = time.time()
    
    
    if output_folder == "":
        output_folder = "result"
    
    port_str = "_".join(map(str, ports)) if ports else "all"
    output_file = f"{output_folder}/{target_ip}_{port_str}_analysis.csv"
    
    # ลบไฟล์เก่าทิ้งก่อนเริ่มรันใหม่
    if os.path.exists(output_file):
        os.remove(output_file)
        
    # สร้าง Display Filter ให้ TShark กรองข้อมูลตั้งแต่ระดับล่าง
    if ports:
        port_filter = " or ".join([f"tcp.port == {p}" for p in ports])
        display_filter = f"ip.addr == {target_ip} and ({port_filter}) and tcp and tcp.payload > 0"
    else:
        display_filter = f"ip.addr == {target_ip} and tcp.payload > 0 and tcp"
    
    cap = pyshark.FileCapture(
        pcap_file,
        display_filter=display_filter,
        keep_packets=False,
        use_json=False
    )
    
    tshark_filtered_time = time.time() - start_time

    # เตรียมตัวแปรสำหรับเก็บสถิติ
    total_packets = 0
    relevant_packets = 0
    
    chunk = []
    chunk_size = 10000
    resp_times = []
    
    response_times = []
    request_sizes = []
    response_sizes = []
    data_points = []
    
    ports_count = Counter()
    endpoints_count = Counter()
    print(f"{'No.':<8} | {'Source':<15} | {'Dest':<15} | {'RTT (ms)':<10}")
    print("-" * 60)

    try:
        for pkt in cap:
            total_packets += 1 # หมายเหตุ: total ในที่นี้จะเป็น total ที่ผ่าน display filter
            
            
            try:                
                if not hasattr(pkt,"ip") and not hasattr(pkt,"tcp") :
                    continue
                ip_layer = pkt.ip
                tcp_layer = pkt.tcp
                total_packets +=1
                stream_id = tcp_layer.stream
                curr_time = float(pkt.sniff_timestamp)
                payload_len = int(tcp_layer.len)

                
                metrics = utility.PacketMetrics(
                    time=curr_time,
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
                
                
                relevant_packets += 1
                pkt_size = int(pkt.length)
                
                # แยกแยะ Request / Response
                if ip_layer.dst == target_ip and tcp_layer.dstport == "8080":
                    # Case: Request (ส่งหา Target)
                    request_sizes.append(pkt_size)
                    ports_count[int(tcp_layer.dstport)] += 1
                    endpoints_count[ip_layer.src] += 1
                    
                    # print(ip_layer.src, tcp_layer.srcport, ip_layer.dst, tcp_layer.dstport)
                    
                elif ip_layer.src == target_ip and tcp_layer.srcport == "8080":
                    # Case: Response (ส่งจาก Target)
                    response_sizes.append(pkt_size)
                    
                    # ดึงค่า RTT ที่ Wireshark คำนวณไว้ 
                    if hasattr(tcp_layer.analysis, "ack_rtt"):
                        rtt_val = float(tcp_layer.analysis.ack_rtt)
                        response_times.append(rtt_val)
                        data_points.append((float(pkt.sniff_time.timestamp()), rtt_val))
                        
                        print(f"{pkt.number:<8} | {ip_layer.src:<15} | {ip_layer.dst:<15} | {rtt_val*1000:.2f} ms")

            except AttributeError:
                # ข้ามแพ็กเก็ตที่โครงสร้างไม่ครบ
                continue

    finally:
        cap.close()

    exec_time = time.time() - start_time

    return utility.TCPOutputModel(
        target_ip=target_ip,
        exec_time=exec_time,
        tshark_filtered_time=tshark_filtered_time,
        total_packets_count=total_packets, # ในโหมดนี้จะเป็น count ของ filtered packets
        relevant_packets_count=relevant_packets,
        top_endpoints=endpoints_count.most_common(5),
        top_ports=ports_count.most_common(5),
        response_size=utility.get_MinMaxAvg(response_sizes),
        request_size=utility.get_MinMaxAvg(request_sizes),
        response_time=utility.get_MinMaxAvg(response_times),
        csv_file=output_file
    )
    

def get_all_pending_reqs(pending_request: defaultdict):
    all = 0
    for v in pending_request.values():
        all += len(v)
    return all

def tcp_analyze_http1(pcap_file, target_ip, output_folder = "", ports=[], limit=None) -> utility.TCPOutputModel:
    
    if output_folder == "":
        output_folder = "result"
    
    port_str = "_".join(map(str, ports)) if ports else "all"
    output_file = f"{output_folder}/{target_ip}_{port_str}_analysis.csv"
    
    # ลบไฟล์เก่าทิ้งก่อนเริ่มรันใหม่ (ถ้าต้องการ)
    if os.path.exists(output_file):
        os.remove(output_file)
    
    chunk = []
    chunk_size = 10000
    start_time = time.time()
    resp_times = []
    # port_filter = " ".join(map(str, ports))
    # display_filter = f"ip.addr == {target_ip} and tcp.port in {{{port_filter}}}"
    
    
    if ports:
        port_filter = " or ".join([f"tcp.port == {p}" for p in ports])
        display_filter = f"ip.addr == {target_ip} and ({port_filter}) and tcp and tcp.payload > 0"
    else:
        display_filter = f"ip.addr == {target_ip} and tcp.payload > 0 and tcp"
    
    cap = pyshark.FileCapture(
        pcap_file,
        display_filter=display_filter,
        keep_packets=False,
        use_json=False
    )
    
    unknown_packet=[]
    
    tshark_filterd_time = time.time() - start_time
    
    # เก็บค่าสถิติต่างๆ
    relevant_packets = 0
    total_packets = 0
    total_requests = 0
    total_responses = 0
    endpoints_count = Counter()
    ports_count = Counter()
    response_sizes = []
    request_sizes = []
    response_times = []
    active_streams = set()
    
    
    graph_data_lst = []
    
    cap = pyshark.FileCapture(
        pcap_file,
        display_filter=display_filter,
        keep_packets=False,
        use_json=True,
        custom_parameters=["-2"]
    )

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
        for pkt in cap:            
            if limit and total_packets > limit:
                break
            try:
                
                ip_layer = pkt.ip
                tcp_layer = pkt.tcp
                total_packets +=1
                stream_id = tcp_layer.stream
                curr_time = float(pkt.sniff_timestamp)
                payload_len = int(tcp_layer.len)
                
                
                # # --- 1. ตรวจสอบการเริ่มต้น/ทำงาน ---
                # # ถ้ามีข้อมูลวิ่งอยู่ ให้ถือว่า stream นี้ยัง active
                # # active_streams.add(stream_id)

                # # --- 2. ตรวจสอบการจบการเชื่อมต่อ (FIN หรือ RST) ---
                # # เช็ค Flag เพื่อดูว่าการเชื่อมต่อสิ้นสุดลงหรือไม่
                # # flags = int(tcp_layer.flags, 16)
                # # FIN = 0x01
                # # RST = 0x04
                
                # # if flags & FIN or flags & RST:
                # #     # ถ้าเจอแพ็กเก็ตปิดการเชื่อมต่อ ให้เอาออกจาก set
                # #     if stream_id in active_streams:
                # #         active_streams.remove(stream_id)
                
                # #ทำไมต้องใช้ data class จาก pandas แทนที่จะใช้ BaseModel
                
                metrics = utility.PacketMetrics(
                    number=pkt.number,
                    time=curr_time,
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
                                
                            pending_requests[stream_id][tcp_layer.nxtseq] = {"idx": pkt.number}
                            
                            metrics.type = "continuation"    
                            request_sizes.append(payload_len)
                            print(f"packet number {pkt.number} is {YELLOW}continuation of {prev_req_segment["idx"]}{RESET}")
                        else:
                            # หากอยู่ใน Stream เดียวกันแต่ไม่ใช่ Segment ต่อจาก Request ที่แล้ว
                            # คาดว่าอาจเป็น retransmission ให้ mark เอาไว้ และสร้าง Request ใหม่
                            print(f"packet number {pkt.number} {RED}is suspected retransmission but create new request{RESET}")
                            # print(f"stream {stream_id}" ,pending_requests[stream_id])
                            # prev_request = pending_requests[stream_id][tcp_layer.nxtseq]
                            pending_requests[stream_id][tcp_layer.nxtseq] = {
                                                                            "idx": pkt.number}
                                                                            # "request_idx": prev_request["request_idx"],
                                                                            # }
                            metrics.type = "retransmission"   
                            # print(f"stream {stream_id}" ,pending_requests[stream_id])

                    else:
                        # ถ้าไม่เจอ Request เดิม สร้างข้อมูล Request ใหม่และนับค่าสถิติ

                        pending_requests[stream_id][tcp_layer.nxtseq] = {"idx": pkt.number}
                        
                        pending_requests[stream_id] = {"request_idx" : pkt.number,
                                                       "request_time": curr_time}
                    
                        print(f"packet number {pkt.number} {BOLD}{BLUE}is first request segment{RESET}")
                        ports_count[tcp_layer.dstport] += 1
                        endpoints_count[ip_layer.src] += 1
                        metrics.type = "request"
                        request_sizes.append(payload_len)
                        total_requests += 1
                        

                #     #print("request:stream_id", stream_id, payload_len, f"index: {pkt.number}")
                #     # "seq": tcp_layer.seq}
                
                # 2. ถ้ามี Data จาก Server -> Client ตัดสินว่านี่คือ Response
                
                elif not is_from_client:
                    if stream_id in pending_requests:
                        # คำนวณเวลาที่ห่างกัน
                        
                        req = pending_requests[stream_id].pop(tcp_layer.ack, None)
                        if req:    
                            relevant_packets += 1
                            request_idx = pending_requests[stream_id].pop("request_idx", None)
                            request_time = pending_requests[stream_id].pop("request_time", None)
                            app_res_time = (curr_time - request_time) * 1000
                            resp_times.append(round(app_res_time,3))
                            total_responses += 1
                            metrics.type = "response"
                            metrics.response_time = round(app_res_time, 3)
                            print(f"packet number {pkt.number} is {GREEN}response for {request_idx} with Response Time {round(app_res_time,3)} {RESET}")
                        # print(f"{stream_id:<8} | {req["idx"]:<9} | {pkt.number:<10} | {app_res_time:>10.3f} ms")
                        
                
                
                chunk.append(asdict(metrics))
            except Exception as e:
                print(e)
                input()
                continue
        
        
        
        cant_find_response = 0
        for reqs in pending_requests.values():
            cant_find_response += len(reqs)
        
        print("matched pairs", relevant_packets)
        print(utility.get_StatModel(resp_times))
        print("display filtered ", display_filter)
        print("total packets from tshark filtered", total_packets)
        print("total requests", total_requests)
        print("total responses", total_responses)
        print("requests can't find respone", cant_find_response)
        print("tcp stream connection counts", len(pending_requests))
        
        
        # print(f"{cant_find_response} requests cant find response.")
        # print("unknown packets")
        # print(unknown_packet)
        
    finally:
        cap.close()
        
        # บันทึกข้อมูลที่เหลืออยู่ใน chunk สุดท้าย (ถ้ามี)
        if chunk:
            pd.DataFrame(chunk).to_csv(output_file, mode='a', index=False, 
                                     header=not os.path.exists(output_file))
            
        
        exec_time = time.time() - start_time
        
        return utility.TCPOutputModel(
        target_ip=target_ip,
        tshark_filtered_time=tshark_filterd_time,
        exec_time=exec_time,
        total_packets_count=total_packets, # ในโหมดนี้จะเป็น count ของ filtered packets
        relevant_packets_count=relevant_packets,
        top_endpoints=endpoints_count.most_common(5),
        top_ports=ports_count.most_common(5),
        response_size=utility.get_StatModel(response_sizes),
        request_size=utility.get_StatModel(request_sizes),
        response_time=utility.get_StatModel(response_times),
        csv_file=output_file
    )


# def get_https_app_response_time2(pcap_file, target_ip, ports=[], limit=None) -> utility.TCPOutputModel:
#     start_time = time.time()
    
#     # สถิติพื้นฐาน
#     total_packets = 0
#     relevant_packets = 0
#     endpoints_count = Counter()
#     ports_count = Counter()
    
#     # ข้อมูลสำหรับ Model
#     request_sizes = []
#     response_sizes = []
#     response_times = []
#     data_points = []

#     # โครงสร้างสำหรับ Matching (FIFO)
#     # { stream_id: deque([ {'expect_ack': 123, 'time': 1.1, 'idx': 10}, ... ]) }
#     pending_requests = {}
    
#     # สำหรับสะสมขนาด Response (Multi-packet)
#     # { (stream_id, ack): total_payload_size }
#     active_responses_size = {}

#     # ปรับปรุง: ถ้า ports ว่าง ให้กรองแค่ target_ip อย่างเดียว
#     if ports:
#         port_filter = " or ".join([f"tcp.port == {p}" for p in ports])
#         display_filter = f"ip.addr == {target_ip} and ({port_filter})"
#     else:
#         display_filter = f"ip.addr == {target_ip}"
    
#     cap = pyshark.FileCapture(
#         pcap_file,
#         display_filter=display_filter,
#         keep_packets=False,
#         use_json=True
#     )

#     print(f"{'No.':<8} | {'Stream':<8} | {'Event':<15} | {'Latency':<10}")
#     print("-" * 50)

#     try:
#         for pkt in cap:
#             if limit and total_packets >= limit:
#                 break
#             total_packets += 1
            
#             try:
#                 tcp = pkt.tcp
#                 ip = pkt.ip
#                 stream_id = tcp.stream
#                 curr_time = float(pkt.sniff_timestamp)
#                 payload_len = int(tcp.len)
                
#                 # เก็บข้อมูล Endpoints/Ports
#                 endpoints_count[ip.src if ip.dst == target_ip else ip.dst] += 1
#                 ports_count[tcp.srcport if ip.dst == target_ip else tcp.dstport] += 1

#                 # แยกฝั่ง Client (ส่งหา Target) และ Server (Target ส่งออกมา)
#                 if ip.src == ip.dst:
#                     # กรณี Loopback: ใช้ Port เป็นตัวตัดสินหลัก
#                     is_from_client = (int(tcp.dstport) in ports)
#                 else:
#                     # กรณีทั่วไป: ใช้ IP ปลายทางเป็นตัวตัดสิน
#                     is_from_client = (ip.dst == target_ip)

#                 # 1. จัดการ Request (Client -> Server)
#                 if is_from_client and payload_len > 0:
                    
#                     request_sizes.append(payload_len)
                    
#                     # คำนวณ Ack ที่คาดหวังจาก Server
#                     expect_ack = int(tcp.seq) + payload_len
                    
#                     if stream_id not in pending_requests:
#                         pending_requests[stream_id] = deque()
                    
#                     pending_requests[stream_id].append({
#                         "expect_ack": expect_ack,
#                         "time": curr_time,
#                         "idx": pkt.number
#                     })
#                     print(f"{pkt.number:<8} | {stream_id:<8} | REQUEST | {payload_len}")

#                 # 2. จัดการ Response (Server -> Client)
#                 elif not is_from_client and payload_len > 0:
                    
#                     # print(ip.src, tcp.srcport, ip.dst, tcp.dstport)
#                     server_ack = int(tcp.ack)
                    
#                     # กรณี A: เป็นแพ็กเก็ตแรกของ Response (TTFB)
#                     if stream_id in pending_requests and pending_requests[stream_id]:
#                         first_req = pending_requests[stream_id][0]
                        
#                         if server_ack == first_req["expect_ack"]:
#                             req = pending_requests[stream_id].popleft()
#                             latency = (curr_time - req["time"]) * 1000
                            
#                             if latency > 0:
#                                 response_times.append(latency)
#                                 data_points.append((curr_time, latency))
#                                 # เริ่มสะสมขนาด Response สำหรับ Ack นี้
#                                 active_responses_size[(stream_id, server_ack)] = payload_len
                                
#                                 print(f"{pkt.number:<8} | {stream_id:<8} | RESPONSE | {latency:.2f} ms (Match Req {req['idx']})")
                    
#                     # กรณี B: เป็นแพ็กเก็ตต่อเนื่องของ Response เดิม (Multi-packet)
#                     elif (stream_id, server_ack) in active_responses_size:
#                         active_responses_size[(stream_id, server_ack)] += payload_len

#             except AttributeError:
#                 continue

#         # นำขนาด Response ทั้งหมดที่สะสมเสร็จแล้วใส่ลง list
#         response_sizes = list(active_responses_size.values())
#         print("matched packet", relevant_packets)
#     finally:
#         cap.close()
#         exec_time = time.time() - start_time
        
#         return utility.TCPOutputModel(
#             target_ip=target_ip,
#             exec_time=exec_time,
#             total_packets_count=total_packets,
#             relevant_packets_count=relevant_packets,
#             top_endpoints=endpoints_count.most_common(5),
#             top_ports=ports_count.most_common(5),
#             response_size=utility.get_MinMaxAvg(response_sizes),
#             request_size=utility.get_MinMaxAvg(request_sizes),
#             response_time=utility.get_MinMaxAvg(response_times),
#             graph_response_time=data_points
#         )



# def get_https_app_response_time3(pcap_file, target_ip, ports=[443], limit=None) -> utility.TCPOutputModel:
#     start_time = time.time()
    
#     response_times = []
#     request_sizes = []
#     response_sizes = [] 
#     data_points = []
    
#     endpoints_count = Counter()
#     ports_count = Counter()
#     total_packets = 0
#     relevant_packets = 0

#     pending_requests = {} 
#     active_responses = {}

#     port_filter = " or ".join([f"tcp.port == {p}" for p in ports])
#     display_filter = f"ip.addr == {target_ip} and ({port_filter})"
    
#     print(f"\n{'='*95}")
#     print(f"📡 Analyzing: {pcap_file} | Target IP: {target_ip} | Limit: {limit if limit else 'Full File'}")
#     print(f"{'='*95}\n")
#     print(f"{'No.':<8} | {'Stream':<8} | {'Event':<15} | {'Size (B)':<10} | {'Info/Latency'}")
#     print(f"{'-'*95}")

#     cap = pyshark.FileCapture(
#         pcap_file,
#         display_filter=display_filter,
#         keep_packets=False,
#         use_json=True
#     )

#     try:
#         for pkt in cap:
#             # ตรวจสอบ Limit
#             if limit and total_packets >= limit:
#                 print(f"\n[!] Reached limit of {limit} packets. Stopping analysis...")
#                 break
                
#             total_packets += 1
#             try:
#                 tcp_layer = pkt.tcp
#                 stream_id = tcp_layer.stream
#                 curr_time = float(pkt.sniff_timestamp)
#                 payload_len = int(tcp_layer.len)
                
#                 endpoints_count[pkt.ip.src if pkt.ip.dst == target_ip else pkt.ip.dst] += 1
#                 ports_count[tcp_layer.srcport if pkt.ip.dst == target_ip else tcp_layer.dstport] += 1

#                 is_from_client = (pkt.ip.dst == target_ip)

#                 # --- [1] ฝั่ง REQUEST (Client -> Server) ---
#                 if is_from_client and payload_len > 0:
#                     relevant_packets += 1
#                     expect_ack = int(tcp_layer.seq) + payload_len
                    
#                     if stream_id not in pending_requests:
#                         pending_requests[stream_id] = deque()
                    
#                     pending_requests[stream_id].append({
#                         "expect_ack": expect_ack,
#                         "time": curr_time,
#                         "idx": pkt.number
#                     })
#                     request_sizes.append(payload_len)
                    
#                     print(f"{pkt.number:<8} | {stream_id:<8} | REQUEST         | {payload_len:<10} | ExpAck: {expect_ack}")

#                 # --- [2] ฝั่ง RESPONSE (Server -> Client) ---
#                 elif not is_from_client and payload_len > 0:
#                     relevant_packets += 1
#                     server_ack = int(tcp_layer.ack)
#                     res_key = (stream_id, server_ack)

#                     # กรณี A: เป็นแพ็กเก็ตต่อเนื่อง (Multi-packet Response)
#                     if res_key in active_responses:
#                         active_responses[res_key]['total_size'] += payload_len
#                         # พิมพ์แจ้งเตือนเบาๆ ว่ากำลังสะสมข้อมูล
#                         print(f"{pkt.number:<8} | {stream_id:<8} | RESP_CONT       | {payload_len:<10} | (Accumulating for Req#{active_responses[res_key]['req_idx']})")
                    
#                     # กรณี B: เป็นแพ็กเก็ตแรกของ Response ใหม่ (TTFB)
#                     elif stream_id in pending_requests and pending_requests[stream_id]:
#                         # หา Request ที่มีค่า ExpectAck ตรงกับ Ack ของ Server
#                         # ปกติควรจะเป็นอันแรกใน Queue (FIFO)
#                         first_req = pending_requests[stream_id][0]
                        
#                         if server_ack == first_req["expect_ack"]:
#                             req = pending_requests[stream_id].popleft()
#                             app_res_time = (curr_time - req["time"]) * 1000 
                            
#                             if app_res_time > 0:
#                                 response_times.append(app_res_time)
#                                 data_points.append((curr_time, app_res_time))
                                
#                                 active_responses[res_key] = {
#                                     'total_size': payload_len,
#                                     'req_idx': req['idx']
#                                 }
                                
#                                 print(f"{pkt.number:<8} | {stream_id:<8} | RESPONSE_START  | {payload_len:<10} | Match Req#{req['idx']} -> {app_res_time:.2f} ms")

#             except AttributeError:
#                 continue

#         # สรุปผลลัพธ์ในส่วนท้าย
#         print(f"\n{'-'*95}")
#         print(f"📊 Summary of Analysis:")
#         for res in active_responses.values():
#             response_sizes.append(res['total_size'])
        
#         pending_total = sum(len(q) for q in pending_requests.values())
#         print(f"Total Filtered Packets: {total_packets}")
#         print(f"Relevant Data Packets: {relevant_packets}")
#         print(f"Pending Requests (No response found): {pending_total}")

#     finally:
#         cap.close()
        
#     exec_time = time.time() - start_time
#     print(f"Execution Time: {exec_time:.2f}s")
#     print(f"{'='*95}\n")
    
#     return utility.TCPOutputModel(
#         target_ip=target_ip,
#         tshark
#         exec_time=exec_time,
#         total_packets_count=total_packets,
#         relevant_packets_count=relevant_packets,
#         top_endpoints=endpoints_count.most_common(5),
#         top_ports=ports_count.most_common(5),
#         response_size=utility.get_MinMaxAvg(response_sizes),
#         request_size=utility.get_MinMaxAvg(request_sizes),
#         response_time=utility.get_MinMaxAvg(response_times),
#         graph_response_time=data_points
#     ) 
    
    
# def tcp_analyze_http1_optimized(pcap_file, target_ip, ports=[], limit=None) -> utility.TCPOutputModel:
#     start_time = time.time()
    
    
#     port_str = "_".join(map(str, ports)) if ports else "all"
#     output_file = f"result/{target_ip}_{port_str}_analysis.csv"
    
#     # ลบไฟล์เก่าทิ้งก่อนเริ่มรันใหม่ (ถ้าต้องการ)
#     if os.path.exists(output_file):
#         os.remove(output_file)
    
#     chunk = []
#     chunk_size = 10000
        
#     # 1. ปรับ Display Filter ให้ดักเฉพาะแพ็กเก็ตที่มี Data (tcp.len > 0)
#     # วิธีนี้จะลดจำนวนแพ็กเก็ตที่เข้า Loop ไปได้มากกว่า 50% (ข้ามพวก ACK เปล่าๆ)
#     port_filter = ""
#     if ports:
#         port_list = " ".join(map(str, ports))
#         port_filter = f" and tcp.port in {{{port_list}}}"

#     # เพิ่ม 'tcp.len > 0' ใน filter เพื่อความเร็วสูงสุด
#     display_filter = f"ip.addr == {target_ip} and tcp.len > 0{port_filter}"
    
#     # 2. ปรับ Parameter ของ TShark เพื่อความเร็ว
#     # -n: ปิด Name Resolution
#     # -o tcp.desegment_tcp_streams:FALSE: ปิดการรวมข้อมูลที่แยกส่วนกันเพื่อลดการใช้ RAM
#     custom_params = ['-n', '-o', 'tcp.desegment_tcp_streams:FALSE']

#     cap = pyshark.FileCapture(
#         pcap_file,
#         display_filter=display_filter,
#         keep_packets=False,
#         use_json=True,
#         custom_parameters=custom_params
#     )

#     relevant_packets = 0
#     total_packets = 0
#     resp_times = []
#     data_points = []
    
#     # ใช้ dict ปกติแทน defaultdict เพื่อความเร็วที่เพิ่มขึ้นเล็กน้อยใน loop ใหญ่
#     pending_requests = {} 

#     print(f"Analyzing {pcap_file} (Optimized)...")

#     try:
#         for pkt in cap:
#             total_packets += 1
#             if limit and total_packets > limit:
#                 break
                
#             try:
#                 tcp = pkt.tcp
#                 ip = pkt.ip
#                 stream_id = tcp.stream
#                 curr_time = float(pkt.sniff_timestamp)
                
#                 # แยกฝั่ง Client/Server (ใช้วิธีเช็ค IP ปลายทาง)
#                 is_from_client = (ip.dst == target_ip)
                
#                 # 1. Request (Client -> Server)
#                 if is_from_client:
#                     if stream_id not in pending_requests:
#                         pending_requests[stream_id] = {}
                    
#                     # จดบันทึกเวลาที่ nxtseq นี้ควรจะได้รับการ ACK กลับมา
#                     pending_requests[stream_id][tcp.nxtseq] = curr_time
                
#                 # 2. Response (Server -> Client)
#                 else:
#                     # เช็คว่า ACK นี้ตรงกับ Request ตัวไหนใน Stream นี้
#                     if stream_id in pending_requests:
#                         req_time = pending_requests[stream_id].pop(tcp.ack, None)
                        
#                         if req_time:
#                             app_res_time = (curr_time - req_time) * 1000
                            
#                             if app_res_time > 0:
#                                 relevant_packets += 1
#                                 resp_times.append(round(app_res_time, 2))
#                                 data_points.append((curr_time, app_res_time))

#             except AttributeError:
#                 continue

#     finally:
#         cap.close()

#     exec_time = time.time() - start_time
    
#     # คำนวณสถิติส่งกลับ (ใช้ utility ที่คุณมี)
#     return utility.TCPOutputModel(
#         target_ip=target_ip,
#         exec_time=exec_time,
#         total_packets_count=total_packets,
#         relevant_packets_count=relevant_packets,
#         top_endpoints=[], # เพิ่ม Counter เองตามต้องการ
#         top_ports=[],
#         response_size=utility.get_MinMaxAvg([]),
#         request_size=utility.get_MinMaxAvg([]),
#         response_time=utility.get_MinMaxAvg(resp_times),
#         csv_file=output_file
#     )
    
    