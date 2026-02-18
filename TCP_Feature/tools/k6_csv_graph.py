import pandas as pd
import matplotlib.pyplot as plt
import os # เพิ่มเพื่อจัดการชื่อไฟล์

def k6_gen_graph(csv_file : str):
    # 1. โหลดข้อมูลจาก CSV
    df = pd.read_csv(csv_file)
    
    # ดึงชื่อไฟล์ออกมา (เช่น apache_0.5_100)
    base_name = os.path.splitext(os.path.basename(csv_file))[0]

    # 2. แปลงหน่วยเวลา (timestamp) ให้เป็นวินาที เพื่อให้อ่านง่าย
    df['timestamp'] = df['timestamp'] - df['timestamp'].min()

    # --- กราฟที่ 1: Response Time (Latency) ---
    latency_data = df[df['metric_name'] == 'http_req_duration']

    plt.figure(figsize=(12, 6))
    plt.plot(latency_data['timestamp'], latency_data['metric_value'], 
            label='Response Time (ms)', color='#2ecc71', alpha=0.6)

    plt.plot(latency_data['timestamp'], latency_data['metric_value'].rolling(window=10).mean(), 
            label='Trend (MA-10)', color='#e74c3c', linewidth=2)

    # ปรับ Title ให้มีชื่อไฟล์
    plt.title(f'k6 Load Test: HTTP Request Duration - {base_name}')
    plt.xlabel('Time (seconds)')
    plt.ylabel('Duration (ms)')
    plt.legend()
    plt.grid(True, linestyle='--', alpha=0.7)
    
    # ปรับชื่อไฟล์ตอน Save
    plt.savefig(f"result/graph/{base_name}_k6_latency.png")

    # --- กราฟที่ 2: Throughput (Requests Per Second) ---
    throughput_data = df[df['metric_name'] == 'http_reqs'].copy()
    throughput_data['timestamp_sec'] = throughput_data['timestamp'].astype(int)
    rps = throughput_data.groupby('timestamp_sec').size()

    plt.figure(figsize=(12, 6))
    plt.bar(rps.index, rps.values, color='#3498db', alpha=0.8)
    
    # ปรับ Title ให้มีชื่อไฟล์
    plt.title(f'k6 Load Test: Throughput (RPS) - {base_name}')
    plt.xlabel('Time (seconds)')
    plt.ylabel('Requests')
    plt.grid(axis='y', linestyle='--', alpha=0.5)
    
    # ปรับชื่อไฟล์ตอน Save
    plt.savefig(f"result/graph/{base_name}_k6_throughput.png")
    print(f"บันทึกกราฟ k6 เรียบร้อย: {base_name}_k6_latency.png และ {base_name}_k6_throughput.png")