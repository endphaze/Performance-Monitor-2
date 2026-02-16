import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.dates as mdates

def plot_graph(csv_file):
    # 1. โหลดข้อมูล
    df = pd.read_csv(csv_file)
    
    # 2. แปลงเวลา Unix Epoch เป็น Datetime object
    df['dt'] = pd.to_datetime(df['time'], unit='s')
    df.set_index('dt', inplace=True)
    
    # 3. แยกนับจำนวน Request และ Response ต่อวินาที
    req_per_sec = df[df['role'] == 'request'].resample('1s').size()
    resp_per_sec = df[df['role'] == 'response'].resample('1s').size()
    
    # สร้าง DataFrame รวม (จัดการค่าที่เป็น NaN เป็น 0)
    stats = pd.DataFrame({
        'req_sec': req_per_sec,
        'resp_sec': resp_per_sec
    }).fillna(0)

    # 4. สร้าง Subplot (2 แถว 1 คอลัมน์)
    # sharex=True เพื่อให้แกน X (เวลา) เชื่อมต่อกันทั้งสองกราฟ
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 10), sharex=True)
    
    # กราฟที่ 1: Requests per Second (แกน X คือ index/timestamp, แกน Y คือค่า req_sec)
    ax1.bar(stats.index, stats['req_sec'], color='skyblue', width=0.00001) # ปรับ width ตามความเหมาะสมของช่วงเวลา
    ax1.set_title('Requests per Second')
    ax1.set_ylabel('Request Count')
    ax1.grid(axis='y', linestyle='--', alpha=0.7)
    
    # กราฟที่ 2: Responses per Second (แกน X คือ index/timestamp, แกน Y คือค่า resp_sec)
    ax2.bar(stats.index, stats['resp_sec'], color='salmon', width=0.00001)
    ax2.set_title('Responses per Second')
    ax2.set_xlabel('Timestamp (HH:MM:SS)')
    ax2.set_ylabel('Response Count')
    ax2.grid(axis='y', linestyle='--', alpha=0.7)

    # จัดรูปแบบการแสดงผลของเวลาบนแกน X
    xfmt = mdates.DateFormatter('%H:%M:%S')
    ax2.xaxis.set_major_formatter(xfmt)
    plt.xticks(rotation=45) # หมุนตัวอักษร 45 องศาเพื่อให้ไม่อัดแน่นจนเกินไป

    plt.tight_layout()
    
    # 5. บันทึกรูปภาพ (ตรวจสอบให้แน่ใจว่ามีโฟลเดอร์ตาม path หรือเซฟลงที่ปัจจุบัน)
    plt.savefig('result/graph/result_graph.png', dpi=300)


# เรียกใช้งาน
# plot_graph('your_data.csv')