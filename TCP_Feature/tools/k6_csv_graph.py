import pandas as pd
import matplotlib.pyplot as plt


def gen_graph(csv_file : str):
# 1. โหลดข้อมูลจาก CSV
    df = pd.read_csv(csv_file)

    # 2. แปลงหน่วยเวลา (timestamp) ให้เป็นวินาที เพื่อให้อ่านง่าย
    # k6 มักจะให้ timestamp มาเป็นแบบ Unix Epoch
    df['timestamp'] = df['timestamp'] - df['timestamp'].min()

    # --- กราฟที่ 1: Response Time (Latency) ---
    # เราจะเลือกเฉพาะ metric 'http_req_duration' (หน่วยเป็น ms)
    latency_data = df[df['metric_name'] == 'http_req_duration']

    plt.figure(figsize=(12, 6))
    plt.plot(latency_data['timestamp'], latency_data['metric_value'], 
            label='Response Time (ms)', color='#2ecc71', alpha=0.6)

    # คำนวณค่าเฉลี่ย (Moving Average) เพื่อให้เห็น Trend ชัดขึ้น
    plt.plot(latency_data['timestamp'], latency_data['metric_value'].rolling(window=10).mean(), 
            label='Trend (MA-10)', color='#e74c3c', linewidth=2)

    plt.title('k6 Load Test: HTTP Request Duration Over Time')
    plt.xlabel('Time (seconds)')
    plt.ylabel('Duration (ms)')
    plt.legend()
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.savefig("result/graph/k6_graph.png")

    # --- กราฟที่ 2: Throughput (Requests Per Second) ---
    # นับจำนวนครั้งที่เกิด 'http_reqs' ในแต่ละวินาที
    throughput_data = df[df['metric_name'] == 'http_reqs'].copy()
    throughput_data['timestamp_sec'] = throughput_data['timestamp'].astype(int)
    rps = throughput_data.groupby('timestamp_sec').size()

    plt.figure(figsize=(12, 6))
    plt.bar(rps.index, rps.values, color='#3498db', alpha=0.8)
    plt.title('k6 Load Test: Throughput (Requests Per Second)')
    plt.xlabel('Time (seconds)')
    plt.ylabel('Requests')
    plt.grid(axis='y', linestyle='--', alpha=0.5)
    plt.savefig("result/graph/k6_graph2.png")