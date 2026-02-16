import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

def gen_graph(data, graph_name):
    
    
    if not data:
        print("No data to plot")
        return

    data.sort(key=lambda x: x[0])
    start_time = data[0][0]
    x_data = np.array([float(x[0]) - float(start_time) for x in data])
    y_data = np.array([float(x[1]) for x in data])

    # ปรับ Window Size ให้ใหญ่ขึ้นเพื่อความสมูท (เช่น 10-20 จุด)
    window_size = 10 if len(y_data) > 30 else 3
    if len(y_data) >= window_size:
        moving_avg = np.convolve(y_data, np.ones(window_size)/window_size, mode='valid')
        x_moving = x_data[window_size-1:]
    else:
        moving_avg = y_data
        x_moving = x_data

    plt.figure(figsize=(12, 5), facecolor='white') # พื้นหลังขาวสะอาด

    # 1. วาดเส้นพื้นหลัง (Raw Data) ให้จางลงมากๆ เพื่อไม่ให้กวนสายตา
    plt.plot(x_data, y_data, color='#2c7bb6', linewidth=0.8, alpha=0.3, label='Raw Latency', zorder=1)
    
    # 2. วาดเส้น Moving Average ให้เด่น (เป็นเส้นทึบที่ดูง่าย)
    plt.plot(x_moving, moving_avg, color='#d7191c', linewidth=2, label=f'Trend (Avg {window_size} pts)', zorder=3)

    # 3. ใส่ Shaded Area เฉพาะช่วงที่ Response Time สูงเกินเกณฑ์ (Highlight เฉพาะปัญหา)
    threshold = 1000.0
    plt.fill_between(x_data, y_data, threshold, where=(y_data > threshold), 
                     color='#d7191c', alpha=0.2, label='Above Threshold', zorder=2)

    # 4. วาด Threshold Line แบบบางๆ
    plt.axhline(y=threshold, color='black', linestyle='--', linewidth=1, alpha=0.5, zorder=2)
    plt.text(x_data[-1], threshold, f'  Target {int(threshold)}ms', va='center', color='black', alpha=0.7)

    # ปรับแต่ง Spine (กรอบกราฟ) ให้ดูทันสมัย
    ax = plt.gca()
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    
    plt.title("Network Performance: HTTPS Response Time", fontsize=14, loc='left', pad=20)
    plt.xlabel("Time Elapsed (seconds)", fontsize=10)
    plt.ylabel("Latency (ms)", fontsize=10)
    
    plt.grid(axis='y', linestyle=':', alpha=0.5) # โชว์เฉพาะเส้นแนวนอนเพื่อให้ดูไม่อึดอัด
    plt.legend(frameon=False, loc='upper right', fontsize=9)
    
    plt.ylim(0, max(y_data) * 1.1 if len(y_data) > 0 else 1200)
    plt.tight_layout()
    
    plt.savefig(f"{graph_name}", dpi=200)
    plt.close()
    print(f"Clean graph saved: {graph_name}")
    
    
    
def gen_pandas_graph(df : pd, graph_name, metrics=['response_time', 'conn_count', 'pending_requests']):
    num_plots = len(metrics)
    fig, axes = plt.subplots(num_plots, 1, figsize=(12, 3 * num_plots), sharex=True)
    
    if num_plots == 1: axes = [axes]

    for i, col in enumerate(metrics):
        ax = axes[i]
        if col in df.columns:
            # พล็อตข้อมูลดิบแบบจางๆ
            ax.plot(df.index, df[col], alpha=0.3, color='gray')
            
            # ถ้าเป็นค่าต่อเนื่อง ให้ทำ Smoothing ให้ด้วย
            if 'time' in col:
                smooth_data = df[col].rolling(window=5, min_periods=1).mean()
                ax.plot(df.index, smooth_data, color='#2c7bb6', linewidth=2, label='Smoothed')
            else:
                # ถ้าเป็นพวก Count ให้ใช้ Step plot
                ax.step(df.index, df[col], where='post', color='#d7191c', linewidth=1.5)
            
            ax.set_ylabel(col.replace('_', ' ').title(), fontweight='bold')
            ax.grid(True, linestyle=':', alpha=0.6)
        
    plt.xlabel("Time (Timeline)")
    plt.tight_layout()
    plt.savefig(graph_name)
    
    
    
    
    
    
    
    