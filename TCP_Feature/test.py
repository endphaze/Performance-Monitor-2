from tools.tcp_analysis_pyshark import get_https_app_response_time2, get_https_app_response_time
from tools.utility import save_data_to_csv
#result1 = get_https_app_response_time(pcap_file="pcap/TCP Test 5.pcap",target_ip="127.0.0.1", ports=[], limit=1000)

result1 = get_https_app_response_time(pcap_file="pcap/TCP Test 3.pcap",target_ip="127.0.0.1", ports=[8080], limit=100)
result2 = 
#print(f"len1 = {len(result1.graph_response_time)}")
print(f"len1 = {len(result2.graph_response_time)}")
save_data_to_csv()
# Find Difference Response Time
# for (ts1, rt1),(ts2, rt2) in zip(result1.graph_response_time, result2.graph_response_time):
#     print(round(rt1,2), round(rt2,2))