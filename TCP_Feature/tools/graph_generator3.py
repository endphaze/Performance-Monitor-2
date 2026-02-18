import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import os

def plot_graph(csv_file):
    # 1. โหลดข้อมูล
    df = pd.read_csv(csv_file)
    
    # ดึงชื่อไฟล์ออกมา (เช่น apache_0.5_100)
    base_name = os.path.splitext(os.path.basename(csv_file))[0]
    
    # 2. แปลงเวลา Unix Epoch เป็น Datetime object
    df['dt'] = pd.to_datetime(df['time'], unit='s')
    df.set_index('dt', inplace=True)
    
    # 3. แยกนับจำนวน Request และ Response ต่อวินาที
    req_per_sec = df[df['role'] == 'request'].resample('1s').size()
    resp_per_sec = df[df['role'] == 'response'].resample('1s').size()
    
    # สร้าง DataFrame รวม
    stats = pd.DataFrame({
        'req_sec': req_per_sec,
        'resp_sec': resp_per_sec
    }).fillna(0)

    # 4. สร้าง Subplot
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 10), sharex=True)
    
    # กราฟที่ 1: Requests per Second
    ax1.bar(stats.index, stats['req_sec'], color='skyblue', width=0.00001)
    ax1.set_title(f'Requests per Second - {base_name}') # ชื่อไฟล์ใน Title
    ax1.set_ylabel('Request Count')
    ax1.grid(axis='y', linestyle='--', alpha=0.7)
    
    # กราฟที่ 2: Responses per Second
    ax2.bar(stats.index, stats['resp_sec'], color='salmon', width=0.00001)
    ax2.set_title(f'Responses per Second - {base_name}') # ชื่อไฟล์ใน Title
    ax2.set_xlabel('Timestamp (HH:MM:SS)')
    ax2.set_ylabel('Response Count')
    ax2.grid(axis='y', linestyle='--', alpha=0.7)

    xfmt = mdates.DateFormatter('%H:%M:%S')
    ax2.xaxis.set_major_formatter(xfmt)
    plt.xticks(rotation=45)

    plt.tight_layout()
    
    # 5. บันทึกรูปภาพ (ชื่อไฟล์ตาม csv_file + ชนิดกราฟ)
    save_path = f'result/graph/{base_name}_split_graph.png'
    plt.savefig(save_path, dpi=300)
    print(f"บันทึกกราฟแยกเรียบร้อยที่: {save_path}")


def plot_graph_overlay(csv_file):
    # 1. โหลดข้อมูล
    df = pd.read_csv(csv_file)
    
    # ดึงชื่อไฟล์ออกมา
    base_name = os.path.splitext(os.path.basename(csv_file))[0]
    
    # 2. แปลงเวลา Unix Epoch เป็น Datetime object
    df['dt'] = pd.to_datetime(df['time'], unit='s')
    df.set_index('dt', inplace=True)
    
    # 3. แยกนับจำนวน Request และ Response ต่อวินาที
    req_per_sec = df[df['role'] == 'request'].resample('1s').size()
    resp_per_sec = df[df['role'] == 'response'].resample('1s').size()
    
    # สร้าง DataFrame รวม
    stats = pd.DataFrame({
        'req_sec': req_per_sec,
        'resp_sec': resp_per_sec
    }).fillna(0)

    # 4. สร้างกราฟแบบซ้อนกัน
    fig, ax = plt.subplots(figsize=(12, 7))
    
    ax.plot(stats.index, stats['req_sec'], label='Requests per Second', 
            color='skyblue', linewidth=2, marker='o', markersize=4, alpha=0.8)
    
    ax.plot(stats.index, stats['resp_sec'], label='Responses per Second', 
            color='salmon', linewidth=2, marker='x', markersize=4, alpha=0.8)

    # ชื่อไฟล์ใน Title
    ax.set_title(f'Network Throughput (Overlay) - {base_name}')
    ax.set_xlabel('Timestamp (HH:MM:SS)')
    ax.set_ylabel('Count per Second')
    ax.grid(True, linestyle='--', alpha=0.6)
    ax.legend()

    xfmt = mdates.DateFormatter('%H:%M:%S')
    ax.xaxis.set_major_formatter(xfmt)
    plt.xticks(rotation=45)

    plt.tight_layout()
    
    # 5. บันทึกรูปภาพ (ชื่อไฟล์ตาม csv_file + ชนิดกราฟ)
    save_path = f'result/graph/{base_name}_overlay_graph.png'
    plt.savefig(save_path, dpi=300)
    print(f"บันทึกกราฟซ้อนเรียบร้อยที่: {save_path}")