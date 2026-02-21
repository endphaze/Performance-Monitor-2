from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

from tools.utility import save_data_to_csv
import tools.graph_generator as graph_generator
from tools.tcp_analysis_pyshark import tcp_analyze


pcap_file = "pcap/TCP Test 5.pcap"
target_ip = "216.198.79.67"
output_graph = f"result/graph/graph_resp-t_{target_ip}.png"
output_pdf = f"result/report_tcp_{target_ip}.pdf"
title = f"TCP Analysis Report for {target_ip}"

output = tcp_analyze(pcap_file, target_ip, [])
for field in output:
    print(field)

min_req, max_req, avg_req = output.request_size.model_dump().values()
min_res, max_res, avg_res = output.response_size.model_dump().values()
min_rt, max_rt, avg_rt = output.response_time.model_dump().values()
top_ports = output.top_ports
top_endpoints = output.top_endpoints
exec_time = output.exec_time

graph_generator.gen_graph(output.graph_response_time, output_graph)

# สร้างรายงาน pdf
doc = SimpleDocTemplate(output_pdf, pagesize=letter)
styles = getSampleStyleSheet()
elements = []

elements.append(Paragraph(title, styles['Title']))
elements.append(Spacer(1, 12))
img = Image(output_graph, width=450, height=225)
elements.append(img)
elements.append(Spacer(1, 12))

# ตารางสถิติ

# Table 1: Response Time Stats
data_rt = [
['Metric', 'Min', 'Max', 'Average'],
['Response Time (s)', f"{min_rt:.6f}",
 f"{max_rt:.6f}",
 f"{avg_rt:.6f}"]
]
t1 = Table(data_rt)

elements.append(Paragraph("Response Time Statistics", styles['Heading2']))
elements.append(t1)
elements.append(Spacer(1, 12))

# Table 2: Request/Response Size Stats
data_size = [
['Type', 'Min Size (bytes)', 'Max Size (bytes)', 'Avg Size (bytes)'],
['Request', f"{min_req}", f"{max_req}", f"{avg_req:.2f}"],
['Response', f"{min_res}", f"{max_res}", f"{avg_res:.2f}"]
]
t2 = Table(data_size)

elements.append(Paragraph("Request / Response Size Statistics", styles['Heading2']))
elements.append(t2)
elements.append(Spacer(1, 12))

data_exec = [
    ['Metric', 'Time (seconds)'],
    ['Program Execution Time', f"{exec_time:.4f}"]
]
t4 = Table(data_exec)

elements.append(Paragraph("Program Performance", styles['Heading2']))
elements.append(t4)
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