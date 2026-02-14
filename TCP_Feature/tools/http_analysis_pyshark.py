import pyshark
import time
from collections import Counter

import tools.utility as utility

def http_analyze(pcap_file, target_ip, ports=[], limit=None) -> utility.TCPOutputModel:
    start_time = time.time()
    
    # สถิติพื้นฐาน
    total_packets = 0
    relevant_packets = 0
    endpoints_count = Counter()
    ports_count = Counter()
    
    request_sizes = []
    response_sizes = []
    response_times = []
    data_points = []
    
    # Filter: เน้นเฉพาะแพ็กเก็ตที่มีการคำนวณ HTTP Response Time มาให้แล้ว
    if ports:
        port_filter = " or ".join([f"tcp.port == {p}" for p in ports])
        display_filter = f"ip.addr == {target_ip} and ({port_filter}) and http.time"
    else:
        display_filter = f"ip.addr == {target_ip} and http.time"
    
    cap = pyshark.FileCapture(
        pcap_file,
        display_filter=display_filter,
        keep_packets=False,
        use_json=True
    )

    print(f"{'Request No.':<8} | {'Response No.':<8} | {'Stream':<8} | {'HTTP Time (ms)':<20}")
    print("-" * 50)

    try:
        for pkt in cap:
            if limit and total_packets >= limit:
                break
            total_packets += 1
            
            try:
                # ใน HTTPS/TLS ที่ถอดรหัสไม่ได้ http.time อาจจะไม่ปรากฏ
                # แต่ถ้าเป็น HTTP ปกติหรือมีการใส่ Key จะใช้ฟิลด์นี้ได้โดยตรง
                if hasattr(pkt.http, 'time'):
                    res_time_sec = float(pkt.http.time)
                    res_time_ms = res_time_sec * 1000
                    
                    curr_time = float(pkt.sniff_timestamp)
                    stream_id = pkt.tcp.stream
                    
                    response_times.append(res_time_ms)
                    data_points.append((curr_time, res_time_ms))
                    relevant_packets += 1
                    
                    # เก็บขนาด Payload ของ Response
                    if hasattr(pkt.tcp, 'len'):
                        response_sizes.append(int(pkt.tcp.len))

                    print(f"{pkt.number:<8} | {stream_id:<8} | {res_time_ms:.2f} ms")

            except AttributeError:
                continue

    finally:
        cap.close()
        exec_time = time.time() - start_time
        
        return utility.TCPOutputModel(
            target_ip=target_ip,
            exec_time=exec_time,
            total_packets_count=total_packets,
            relevant_packets_count=relevant_packets,
            top_endpoints=endpoints_count.most_common(5),
            top_ports=ports_count.most_common(5),
            response_size=utility.get_MinMaxAvg(response_sizes),
            request_size=utility.get_MinMaxAvg(request_sizes), # ส่วนนี้อาจว่างถ้ากรองแค่ http.time
            response_time=utility.get_MinMaxAvg(response_times),
            graph_response_time=data_points
        )