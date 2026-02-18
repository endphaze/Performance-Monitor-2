import sys
import argparse
import time
from collections import defaultdict
import statistics
import os

from scapy.all import *
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

import matplotlib.pyplot as plt

def analyze_and_generate_report(pcap_file, target_ip, output_pdf="tcp_analysis_report.pdf"):
    start_time = time.time()
    
    print(f"Reading {pcap_file}...")
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"Error reading pcap file: {e}")
        return

    # Data collections
    all_packet_sizes = []
    tcp_packet_sizes = []
    
    # Connection tracking for Target IP
    connections = defaultdict(list)
    
    # Initial pass: Collect global stats and group connections
    for i, pkt in enumerate(packets):
        # Filter IPv6
        if IPv6 in pkt:
            continue
            
        pkt_len = len(pkt)
        all_packet_sizes.append(pkt_len)
        
        if TCP in pkt:
            tcp_packet_sizes.append(pkt_len)
            
            if IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
                
                # Check if this packet involves the target IP
                if src == target_ip or dst == target_ip:
                    sport = pkt[TCP].sport
                    dport = pkt[TCP].dport
                    
                    # Canonical key for the connection
                    if src < dst:
                        key = (src, sport, dst, dport)
                    else:
                        key = (dst, dport, src, sport)
                        
                    connections[key].append((i, pkt))

    # Analyze Connections for Request/Response
    response_times = []      
    request_sizes = []
    response_sizes = []
    
    print(f"Analyzing {len(connections)} connections for {target_ip}...")
    
    rtt_data_points = [] # list of (timestamp, rtt)
    
    # Find start time of the capture for relative time calculation
    first_packet_time = 0
    if len(packets) > 0:
        first_packet_time = packets[0].time

    for key, conn_pkts in connections.items():
        pending_requests = {} 
        
        for idx, pkt in conn_pkts:
            if not isinstance(pkt.payload, IP) and not isinstance(pkt, IP):
                  if IP not in pkt: continue
            
            ip_layer = pkt[IP]
            tcp_layer = pkt[TCP]
            payload_len = len(tcp_layer.payload)
            wire_len = len(pkt)
            
            if ip_layer.dst == target_ip: # Request
                if payload_len > 0:
                    expected_ack = tcp_layer.seq + payload_len
                    if expected_ack not in pending_requests:
                        pending_requests[expected_ack] = {
                            'time': pkt.time,
                            'wire_len': wire_len,
                            'idx': idx
                        }
            
            elif ip_layer.src == target_ip: # Response
                ack_num = tcp_layer.ack
                if ack_num in pending_requests:
                    req = pending_requests.pop(ack_num)
                    
                    rtt = float(pkt.time - req['time'])
                    
                    response_times.append(rtt)
                    request_sizes.append(req['wire_len'])
                    response_sizes.append(wire_len)
                    
                    # Use Request time or Response time?
                    # Usually "Response Time" vs "Time of Occurrence".
                    # Let's use Request Timestamp for the X-axis (when the request matched happened)
                    # Normalized to start of capture
                    rel_time = float(req['time'] - first_packet_time)
                    rtt_data_points.append((rel_time, rtt))
    
    
    
    
    end_time = time.time()
    exec_time = end_time - start_time
    
    # helper for stats
    def get_stats(data):
        if not data:
            return 0, 0, 0
        return min(data), max(data), statistics.mean(data)

    # --- Console Output ---
    min_rt, max_rt, avg_rt = get_stats(response_times)
    min_req, max_req, avg_req = get_stats(request_sizes)
    min_res, max_res, avg_res = get_stats(response_sizes)
    min_all, max_all, avg_all = get_stats(all_packet_sizes)
    min_tcp, max_tcp, avg_tcp = get_stats(tcp_packet_sizes)

    print("\n" + "="*50)
    print(f"Analysis Results for {target_ip}")
    print("="*50)
    
    print("\n[Response Time Statistics (s)]")
    print(f"  Min: {min_rt:.6f}")
    print(f"  Max: {max_rt:.6f}")
    print(f"  Avg: {avg_rt:.6f}")
    
    print("\n[Request/Response Size Statistics (bytes)]")
    print(f"  Request  - Min: {min_req:<10} Max: {max_req:<10} Avg: {avg_req:.2f}")
    print(f"  Response - Min: {min_res:<10} Max: {max_res:<10} Avg: {avg_res:.2f}")
    
    print("\n[Global Packet Statistics (bytes)]")
    print(f"  All Packets (No IPv6) - Count: {len(all_packet_sizes):<6} Min: {min_all:<6} Max: {max_all:<6} Avg: {avg_all:.2f}")
    print(f"  Total TCP Packets     - Count: {len(tcp_packet_sizes):<6} Min: {min_tcp:<6} Max: {max_tcp:<6} Avg: {avg_tcp:.2f}")
    
    print(f"\n[Performance]")
    print(f"  Execution Time: {exec_time:.4f} seconds")
    print("="*50 + "\n")

    # --- Generate PDF ---
    print(f"Generating PDF: {output_pdf}")
    doc = SimpleDocTemplate(output_pdf, pagesize=letter)
    elements = []
    styles = getSampleStyleSheet()
    
    # Title
    elements.append(Paragraph(f"TCP Analysis Report for {target_ip}", styles['Title']))
    elements.append(Spacer(1, 12))
    
    # helper for stats
    def get_stats(data):
        if not data:
            return 0, 0, 0
        return min(data), max(data), statistics.mean(data)

    # 1. Graph (Response Time) with Matplotlib
    if rtt_data_points:
        # Sort by timestamp
        rtt_data_points.sort(key=lambda x: x[0])
        x_data = [x[0] for x in rtt_data_points]
        y_data = [x[1] for x in rtt_data_points]
        
        # Generate Plot using Matplotlib
        plt.figure(figsize=(8, 4))
        plt.plot(x_data, y_data, marker='o', linestyle='-', color='b', markersize=4)
        plt.title(f"Response Time vs Packet Timestamp")
        plt.xlabel("Time (s) from start of capture")
        plt.ylabel("Response Time (seconds)")
        plt.grid(True)
        plt.tight_layout()
        
        temp_img = "temp_plot.png"
        plt.savefig(temp_img)
        plt.close()
        
        # Embed in PDF
        elements.append(Paragraph("Response Time Graph (X=Time, Y=RTT)", styles['Heading2']))
        
        # Check aspect ratio
        img = Image(temp_img, width=450, height=225)
        elements.append(img)
        elements.append(Spacer(1, 12))
        
        # We will remove temp_img later or just leave it
    else:
        elements.append(Paragraph("No matched Request/Response pairs found for graph.", styles['Normal']))
        elements.append(Spacer(1, 12))

    # 2. Statistics Tables
    
    # Style for tables
    tbl_style = TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ])

    # Table 1: Response Time Stats
    min_rt, max_rt, avg_rt = get_stats(response_times)
    data_rt = [
        ['Metric', 'Min', 'Max', 'Average'],
        ['Response Time (s)', f"{min_rt:.6f}", f"{max_rt:.6f}", f"{avg_rt:.6f}"]
    ]
    t1 = Table(data_rt)
    t1.setStyle(tbl_style)
    
    elements.append(Paragraph("Response Time Statistics", styles['Heading2']))
    elements.append(t1)
    elements.append(Spacer(1, 12))
    
    # Table 2: Request/Response Size Stats
    min_req, max_req, avg_req = get_stats(request_sizes)
    min_res, max_res, avg_res = get_stats(response_sizes)
    
    data_size = [
        ['Type', 'Min Size (bytes)', 'Max Size (bytes)', 'Avg Size (bytes)'],
        ['Request', f"{min_req}", f"{max_req}", f"{avg_req:.2f}"],
        ['Response', f"{min_res}", f"{max_res}", f"{avg_res:.2f}"]
    ]
    t2 = Table(data_size)
    t2.setStyle(tbl_style)
    
    elements.append(Paragraph("Request / Response Size Statistics", styles['Heading2']))
    elements.append(t2)
    elements.append(Spacer(1, 12))
    
    # Table 3: Total Packet Stats (All & TCP)
    min_all, max_all, avg_all = get_stats(all_packet_sizes)
    min_tcp, max_tcp, avg_tcp = get_stats(tcp_packet_sizes)
    
    data_global = [
        ['Category', 'Count', 'Min Size', 'Max Size', 'Avg Size'],
        ['All Packets (No IPv6)', f"{len(all_packet_sizes)}", f"{min_all}", f"{max_all}", f"{avg_all:.2f}"],
        ['Total TCP Packets', f"{len(tcp_packet_sizes)}", f"{min_tcp}", f"{max_tcp}", f"{avg_tcp:.2f}"]
    ]
    t3 = Table(data_global)
    t3.setStyle(tbl_style)
    
    elements.append(Paragraph("Global Packet Statistics", styles['Heading2']))
    elements.append(t3)
    elements.append(Spacer(1, 12))
    
    # Table 4: Execution Time
    data_exec = [
        ['Metric', 'Time (seconds)'],
        ['Program Execution Time', f"{exec_time:.4f}"]
    ]
    t4 = Table(data_exec)
    t4.setStyle(tbl_style)
    
    elements.append(Paragraph("Performance", styles['Heading2']))
    elements.append(t4)
    
    # Build
    doc.build(elements)
    print("PDF generation complete.")
    
    # Cleanup temp image
    if os.path.exists("temp_plot.png"):
        os.remove("temp_plot.png")

if __name__ == "__main__":
    # parser = argparse.ArgumentParser(description="TCP Analysis with PDF Report")
    # parser.add_argument("pcap_file", help="Path to .pcap file")
    # parser.add_argument("target_ip", help="Target IP Address")
    # parser.add_argument("--output", help="Output PDF filename", default="tcp_analysis_report.pdf")
    
    # args = parser.parse_args()
    analyze_and_generate_report("test_pcap/TCP Test 5.pcap", target_ip="64.29.17.131", output_pdf="analysis_report.pdf")
