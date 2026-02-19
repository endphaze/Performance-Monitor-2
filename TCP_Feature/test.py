

from tools.tcp_analysis_pyshark import tcp_analyze_http1
from tools.graph_generator3 import plot_graph_overlay, plot_graph
from tools.k6_csv_graph import k6_gen_graph
import pyshark
import pandas as pd

pcap_file="pcap/k6_apache_vus5000.pcap"
target_ip = "127.0.0.1"
ports = [8080]

if __name__ == "__main__":
    
    result1 = tcp_analyze_http1(pcap_file=pcap_file, target_ip="127.0.0.1", ports=[8080])
    print("tshark filterd time =", round(result1.tshark_filterd_time,3), "seconds")
    print("executed time =", round(result1.exec_time,3), "seconds")
    # plot_graph(result1.csv_file)
    # plot_graph_overlay(result1.csv_file)
    # k6_gen_graph(csv_file="data/apache_0.5_5000_2.csv")
    