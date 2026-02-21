from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

from tools.graph_generator3 import plot_graph_rps, plot_graph_response_time

import tools.utility as utility
import pandas as pd
import os



def report_gen(target_ip, result : utility.TCPOutputModel):
    
    csv_file = result.csv_file
    df = pd.read_csv(csv_file)
    # อ่านรูปแบบของหัวตาราง
    header_list = df.columns.to_list()
    
    df['dt'] = pd.to_datetime(df['time'], unit='s')
    df.set_index('dt', inplace=True)
    
    # 2. คำนวณจำนวนต่อวินาที (Per Second)
    # ใช้ .size() เพื่อนับจำนวนแถวที่เกิดขึ้นในแต่ละ 1 วินาที
    req_per_sec = df[df['type'] == 'request'].resample('1s').size()
    resp_per_sec = df[df['type'] == 'response'].resample('1s').size()
    
    title = f"TCP Analysis Report for {target_ip}"
    output_pdf = f"result/report_tcp_{target_ip}.pdf"
    
    base_name = os.path.splitext(os.path.basename(csv_file))[0]
    
    # check ว่า header เป็น pattern ไหน
    if header_list == ['time', 'response_time', 'pending_req', 'stream_id', 'type']:
        # plot graph ก่อนและกำหนด path ของ report
        
        rps_graph = plot_graph_rps(df, base_name)     
        rt_graph = plot_graph_response_time(df, base_name)
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
        

        # ตารางสถิติ
        min_req, max_req, avg_req, stddev_req = result.request_size.model_dump().values()
        min_res, max_res, avg_res, stddev_res = result.response_size.model_dump().values()
        min_rt, max_rt, avg_rt, stddev_rt = result.response_time.model_dump().values()
        top_ports = result.top_ports
        top_endpoints = result.top_endpoints
        exec_time = result.exec_time
        
        

        # Table 1: Requests and Responses Per Second Stats
        data_rps = [
        ['Metric', 'Min', 'Max', 'Average', 'Std Dev'],
        ['Requests Per Second', f"{req_per_sec.min():.3f}",
        f"{req_per_sec.max():.3f}",
        f"{req_per_sec.mean():.3f}",
        f"{req_per_sec.std():.3f}"],
        ['Requests Per Second', f"{resp_per_sec.min():.3f}",
        f"{resp_per_sec.max():.3f}",
        f"{resp_per_sec.mean():.3f}",
        f"{resp_per_sec.std():.3f}"]
        ]
        t1 = Table(data_rps)

        elements.append(Paragraph("Requests / Responses Per Second Statistics", styles['Heading2']))
        elements.append(t1)
        elements.append(Spacer(1, 12))
        
        
        # Table 2: Request/Response Size Stats
        data_size = [
        ['Type', 'Min Size (bytes)', 'Max Size (bytes)', 'Average Size (bytes)', 'Std Dev'],
        ['Request', f"{min_req}", f"{max_req}", f"{avg_req:.2f}", f"{stddev_req:.2f}"],
        ['Response', f"{min_res}", f"{max_res}", f"{avg_res:.2f}", f"{stddev_res:.2f}"]
        ]
        t2 = Table(data_size)

        elements.append(Paragraph("Request / Response Size Statistics", styles['Heading2']))
        elements.append(t2)
        elements.append(Spacer(1, 12))
        
        
        # Table 3: Response Time Stats
        data_rt = [
        ['Metric', 'Min', 'Max', 'Average', 'Std Dev'],
        ['Response Time (ms)', f"{min_rt:.3f}",
        f"{max_rt:.3f}",
        f"{avg_rt:.3f}",f"{stddev_rt:.2f}"]
        ]
        t3 = Table(data_rt)

        elements.append(Paragraph("Response Time Statistics", styles['Heading2']))
        elements.append(t3)
        elements.append(Spacer(1, 12))
        
        
        # Table 4 : Top Endpoints
        data_endpoints = [['Endpoint', 'Requests Count']]
        for endpoint, frequency in top_endpoints:
            data_endpoints.append([endpoint, frequency])
        
        t4 = Table(data_endpoints)
        elements.append(Paragraph("Top Endpoints", styles['Heading2']))
        elements.append(t4)
        elements.append(Spacer(1, 12))
        
        # Table 5 : Top Ports
        data_ports = [['Port', 'Requests Count']]
        for port, frequency in top_ports:
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

        print("\n[Response Time Statistics (s)]")
        print(f"  Min: {min_rt:.6f}")
        print(f"  Max: {max_rt:.6f}")
        print(f"  Avg: {avg_rt:.6f}")

        print("\nTop Ports")
        for port in top_ports:
            print(f"{port}")
            
        print("\nTop Endpoints")
        for endpoint in top_endpoints:
            print(f"{endpoint}")
            
            
        print("\n[Request/Response Size Statistics (bytes)]")
        print(f"  Request  - Min: {min_req:<10} Max: {max_req:<10} Avg: {avg_req:.2f}")
        print(f"  Response - Min: {min_res:<10} Max: {max_res:<10} Avg: {avg_res:.2f}")
        

        print("excuted time = ", round(exec_time, 3), "sec")
                
    