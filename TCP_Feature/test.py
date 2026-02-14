from tools.tcp_analysis_pyshark import get_https_app_response_time2, tcp_analyze_http1, tcp_analyze_http1_optimized
from tools.http_analysis_pyshark import http_analyze
from tools.utility import save_data_to_csv
#result1 = get_https_app_response_time(pcap_file="pcap/TCP Test 5.pcap",target_ip="127.0.0.1", ports=[], limit=1000)

result1 = tcp_analyze_http1(pcap_file="pcap/TCP Test 3.pcap",target_ip="127.0.0.1", ports=[8080, 443], limit=65)
result2 = http_analyze(pcap_file="pcap/TCP Test 3.pcap",target_ip="127.0.0.1", ports=[8080], limit=32)
result3 = tcp_analyze_http1_optimized(pcap_file="pcap/TCP Test 3.pcap",target_ip="127.0.0.1", ports=[8080], limit=200)
#print(f"len1 = {len(result1.graph_response_time)}")

save_data_to_csv(result1.graph_response_time, "result/tcp_analysis.csv")
save_data_to_csv(result2.graph_response_time, "result/http_time.csv")
save_data_to_csv(result3.graph_response_time, "result/tcp_analysis_optimized.csv")

print("result1 = len ", len(result1.graph_response_time), result1.exec_time)
print("result2 = len ", len(result2.graph_response_time), result2.exec_time)
print("result3 = len ", len(result3.graph_response_time), result3.exec_time)
# Find Difference Response Time
# for (ts1, rt1),(ts2, rt2) in zip(result1.graph_response_time, result2.graph_response_time):
#     print(round(rt1,2), round(rt2,2))