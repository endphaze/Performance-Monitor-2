from scapy.all import *
import time
from collections import defaultdict
import sys
import argparse

def analyze_tcp(pcap_file, target_ip):
    start_time = time.time()
    
    print(f"Reading {pcap_file}...")
    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        print(f"Error: File {pcap_file} not found.")
        return
    except Exception as e:
        print(f"Error reading file: {e}")
        return

    connections = defaultdict(list)
    
    # We will use the packet's index in the pcap as ID
    # rdpcap returns a list, so we can use enumerate
    
    tcp_packets_count = 0
    relevant_packets_count = 0
    
    for idx, pkt in enumerate(packets):
        if TCP not in pkt:
            continue
            
        tcp_packets_count += 1
            
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
        else:
            continue
            
        # Filter by Target IP
        if src != target_ip and dst != target_ip:
            continue
            
        relevant_packets_count += 1
            
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        
        # Canonical tuple
        if src < dst:
            key = (src, sport, dst, dport)
        else:
            key = (dst, dport, src, sport)
            
        connections[key].append((idx + 1, pkt)) # 1-based index

    print(f"Total TCP Packets: {tcp_packets_count}")
    print(f"Packets involving {target_ip}: {relevant_packets_count}")
    
    response_times = []
    request_sizes = []
    response_sizes = []
    pairs = [] # List of (req_idx, res_idx, rtt)
    
    print(f"Found {len(connections)} TCP connections involving {target_ip}.\n")

    for conn_key, indexed_pkts in connections.items():
        if not indexed_pkts:
            continue
            
        # Helper to identify direction
        # Assume first packet initiator is client
        p0 = indexed_pkts[0][1]
        
        # We need to correctly identify if target_ip is client or server in this specific flow
        # But for pairing "Request" and "Response", the logic remains:
        # Client -> Server (Data) = Request
        # Server -> Client (ACK) = Response
        
        if IP in p0:
            client_ip = p0[IP].src
        else:
            continue
            
        # Pending requests: expected_ack -> {time, size, idx}
        pending_requests = {}
        
        for idx, p in indexed_pkts:
            if IP in p:
                p_src = p[IP].src
            else:
                continue
                
            payload_len = len(p[TCP].payload)
            
            if p_src == client_ip: # Client -> Server (Request)
                if payload_len > 0:
                    seq = p[TCP].seq
                    expected_ack = seq + payload_len
                    if expected_ack not in pending_requests:
                        pending_requests[expected_ack] = {
                            'time': p.time, 
                            'size': payload_len, 
                            'idx': idx,
                            'matched': False
                        }
            else: # Server -> Client (Response)
                ack = p[TCP].ack
                
                # Check if this matches a pending request
                # We prefer Data responses.
                if ack in pending_requests:
                    req = pending_requests[ack]
                    if not req['matched']:
                        # Found a match!
                        
                        rrt = float(p.time - req['time'])
                        response_times.append(rrt)
                        request_sizes.append(req['size'])
                        req['matched'] = True
                        
                        pairs.append((req['idx'], idx, rrt))
                        
                        if payload_len > 0:
                            response_sizes.append(payload_len)

    if pairs:
        print("Request/Response Pairs:")
        print(f"{'Ord':<5} | {'Req Pkt':<10} | {'Res Pkt':<10} | {'RTT (s)':<15}")
        print("-" * 50)
        for i, (req_idx, res_idx, rtt) in enumerate(pairs):
            print(f"{i+1:<5} | {req_idx:<10} | {res_idx:<10} | {rtt:.6f}")
        print("-" * 50)
        print()

    if not response_times:
        print(f"No paired request/responses found for {target_ip}.")
    else:
        print(f"Stats Summary for Target IP {target_ip}:")
        print(f"- Pairs Found: {len(response_times)}")
        print(f"- Response Time: Min={min(response_times):.6f}s, Max={max(response_times):.6f}s, Avg={sum(response_times)/len(response_times):.6f}s")
        print(f"- Request Size: Min={min(request_sizes)}, Max={max(request_sizes)}, Avg={sum(request_sizes)/len(request_sizes):.2f}")
        
        if response_sizes:
             print(f"- Response Size: Min={min(response_sizes)}, Max={max(response_sizes)}, Avg={sum(response_sizes)/len(response_sizes):.2f}")
        else:
             print("- Response Size: N/A (No Data matching ACKs)")

    end_time = time.time()
    print(f"\nTotal Execution Time: {end_time - start_time:.4f} seconds")

if __name__ == "__main__":
    # parser = argparse.ArgumentParser(description="Analyze TCP packets for a specific target IP.")
    # parser.add_argument("pcap_file", help="Path to the .pcap file")
    # parser.add_argument("target_ip", help="Target IP address to filter")
    
    # args = parser.parse_args()
    analyze_tcp(pcap_file="test_pcap/TCP Test 5.pcap", target_ip="64.29.17.131")
