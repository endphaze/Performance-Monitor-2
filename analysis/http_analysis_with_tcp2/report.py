from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

import pandas as pd
import os

from utility.base_analysis import BaseAnalysis
from .graph_generator import plot_graph_rps, plot_graph_response_time_threshold
from core.config import settings


def generate_report(analysis_obj : BaseAnalysis):
    
    target_ip = analysis_obj.target_ip
    cursor = analysis_obj.collection.find()
    df = pd.DataFrame(list(cursor))
    # อ่านรูปแบบของหัวตาราง
    header_list = df.columns.to_list()
    
    df['dt'] = pd.to_datetime(df['time'], unit='s')
    df.set_index('dt', inplace=True)
    
    # 2. คำนวณจำนวนต่อวินาที (Per Second)
    # ใช้ .size() เพื่อนับจำนวนแถวที่เกิดขึ้นในแต่ละ 1 วินาที
    req_per_sec = df[df['type'] == 'request'].resample('1s').size()
    resp_per_sec = df[df['type'] == 'response'].resample('1s').size()
    
    # นับจำนวนแถวที่คอลัมน์ type เป็น 'request'
    total_requests = len(df[df['type'] == 'request'])

    # นับจำนวนแถวที่คอลัมน์ type เป็น 'response'
    total_responses = len(df[df['type'] == 'response'])
    
    title = f"TCP Analysis Report for {target_ip}"
    output_pdf = f"{settings.result_dir}/report_tcp_{target_ip}.pdf"
    
    base_name = os.path.splitext(os.path.basename(analysis_obj.analysis_name))[0]
    
    # check ว่า header เป็น pattern ไหน

    # plot graph ก่อนและกำหนด path ของ report
    rps_graph = plot_graph_rps(df, base_name, settings.result_dir)     
    rt_graph = plot_graph_response_time_threshold(df, base_name, settings.result_dir)
    doc = SimpleDocTemplate(output_pdf, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph(title, styles['Title']))
    elements.append(Spacer(1, 12))
    img_rps_graph = Image(rps_graph, width=350, height=300)
    elements.append(img_rps_graph)
    img_rt_graph = Image(rt_graph, width=300, height=200)
    elements.append(img_rt_graph)
    elements.append(Spacer(1, 12))
    

    req_size = df[df['request_size'] > 0]['request_size']
    res_time = df[df['response_time'] > 0]['response_time']
    
    stats_req = {
        "Min": req_size.min(),
        "Max": req_size.max(),
        "Avg": req_size.mean(),
        "Std": req_size.std()
    }

    # 4. คำนวณค่าทางสถิติของ Response Time
    stats_rt = {
        "Min": res_time.min(),
        "Max": res_time.max(),
        "Avg": res_time.mean(),
        "Std": res_time.std()
    }
    # ตารางสถิติ
    filtered_endpoints = df[ (df['endpoint'].notna()) & (df['endpoint'] != "") ]['endpoint']
    top_ports = df['port'].dropna().value_counts().head(5)
    top_endpoints = filtered_endpoints.value_counts().head(5)
    exec_time = analysis_obj.executed_time
    
    

    # Table 1: Requests and Responses Per Second Stats
    data_rps = [
    ['Metric', 'Min', 'Max', 'Average', 'Std Dev'],
    ['Requests Per Second', f"{req_per_sec.min():.3f}",
    f"{req_per_sec.max():.3f}",
    f"{req_per_sec.mean():.3f}",
    f"{req_per_sec.std():.3f}"],
    ['Response Per Second', f"{resp_per_sec.min():.3f}",
    f"{resp_per_sec.max():.3f}",
    f"{resp_per_sec.mean():.3f}",
    f"{resp_per_sec.std():.3f}"]
    ]
    t1 = Table(data_rps)

    elements.append(Paragraph("Requests / Responses Per Second Statistics", styles['Heading2']))
    elements.append(t1)
    elements.append(Spacer(1, 12))
    
    
    # Table 2: Request Size Stats
    data_size = [
    ['Type', 'Min Size (bytes)', 'Max Size (bytes)', 'Average Size (bytes)', 'Std Dev'],
    ['Request', f"{stats_req["Min"]}", f"{stats_req["Max"]}", f"{stats_req["Avg"]:.2f}", f"{stats_req["Std"]:.2f}"],
    ]
    t2 = Table(data_size)

    elements.append(Paragraph("Request Size Statistics", styles['Heading2']))
    elements.append(t2)
    elements.append(Spacer(1, 12))
    
    
    # Table 3: Response Time Stats
    data_rt = [
    ['Metric', 'Min', 'Max', 'Average', 'Std Dev'],
    ['Response Time (ms)', f"{stats_rt["Min"]:.3f}",
    f"{stats_rt["Max"]:.3f}",
    f"{stats_rt["Avg"]:.3f}",f"{stats_rt['Std']:.2f}"]
    ]
    t3 = Table(data_rt)

    elements.append(Paragraph("Response Time Statistics", styles['Heading2']))
    elements.append(t3)
    elements.append(Spacer(1, 12))
    
    
    # Table 4 : Top Endpoints
    data_endpoints = [['Endpoint', 'Requests Count']]
    for endpoint, frequency in top_endpoints.items():
        data_endpoints.append([endpoint, frequency])
    
    t4 = Table(data_endpoints)
    elements.append(Paragraph("Top Endpoints", styles['Heading2']))
    elements.append(t4)
    elements.append(Spacer(1, 12))
    
    # Table 5 : Top Ports
    data_ports = [['Port', 'Requests Count']]
    for port, frequency in top_ports.items():
        data_ports.append([port, frequency])
    
    t5 = Table(data_ports)
    elements.append(Paragraph("Top Ports", styles['Heading2']))
    elements.append(t5)
    elements.append(Spacer(1, 12))

    data_exec = [
        ['Metric', 'Time (seconds)'],
        ['Program Execution Time', f"{exec_time:.4f}"]
    ]
    t6 = Table(data_exec)

    elements.append(Paragraph("Program Performance", styles['Heading2']))
    elements.append(t6)
    doc.build(elements)
    
    
    print("PDF generation complete.")

    print()
    print(f"Analysis Results for {target_ip}")
    print("="*50)
    
    print(f"\nFiltered Packet {analysis_obj.total_packet} From TShark")
    print("\n[Total Request] =", total_requests)
    print("[Total Response] =", total_responses)
    
    print("\n[Response Time Statistics (s)]")
    print(f"  Min: {stats_rt["Min"]:.6f}")
    print(f"  Max: {stats_rt["Max"]:.6f}")
    print(f"  Avg: {stats_rt["Avg"]:.6f}")
    print(f"  Std: {stats_rt["Std"]:.6f}")
    
    print("\n[Top Ports]")
    print(f"{"Ports":<7}{"Count":<7}")
    for port, count in top_ports.items():
        print(f"{port:<7}{count:<7}")
    
    print("\n[Top Endpoints]")
    print(f"{"Endpoints":<12}{"Count":<12}")
    for endpoint, count in top_endpoints.items():
        print(f"{endpoint:<12}{count:<12}")
    
        
    print("\n[Request Size Statistics (bytes)]")
    print(f"  Request  - Min: {stats_req["Min"]:<10} Max: {stats_req["Max"]:<10} Avg: {stats_req["Avg"]:.2f}")

    print("executed time = ", round(exec_time, 3), "sec")
                
    