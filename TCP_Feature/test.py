

from tools.tcp_analysis_pyshark import tcp_analyze_http1
from tools.k6_csv_graph import k6_gen_graph
from tools.report_generator import report_gen
import pandas as pd

pcap_file="pcap/mininet_test3.pcap"
target_ip = "192.168.1.11"
ports = [8080]

if __name__ == "__main__":
    
    result1 = tcp_analyze_http1(pcap_file=pcap_file, target_ip=target_ip, ports=[8080])
    
    # print("tshark filterd time =", round(result1.tshark_filterd_time,3), "seconds")
    print("executed time =", round(result1.exec_time,3), "seconds")
    
    report_gen(result=result1, target_ip=target_ip)
    
    # plot_graph_overlay(result1.csv_file)
    # k6_gen_graph(csv_file="data/apache_0.5_5000_2.csv")
    
    