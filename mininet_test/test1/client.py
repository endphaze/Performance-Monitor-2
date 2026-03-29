import requests
import time


# จำลองข้อมูลขนาดใหญ่ (เช่น 2000 bytes) เพื่อให้เกิน MTU 1500
large_data = "A" * 2000 
headers = {"X-Large-Header": "B" * 2000}

def send_request(server_url):
    try:
        # ส่ง POST พร้อมข้อมูลขนาดใหญ่
        response = requests.post(server_url, data=large_data, headers=headers)
        print(f"Sent to {server_url}: Status {response.status_code}")
    except Exception as e:
        print(f"Error: {e}")

# รายชื่อ Server หลายเครื่อง
servers = ["http://10.0.0.1:80", "http://10.0.0.2:80"]

try:
    while True:
        for sv in servers:
            send_request(sv)
        
        # หน่วงเวลา 0.1 วินาที ให้ Wireshark ได้จับลำดับแพ็กเก็ตได้ชัดเจน
        time.sleep(0.5) 
except KeyboardInterrupt:
    print("\nTest stopped by user.")
    
    
    
# ใช้ Threading เพื่อจำลอง Client หลายเครื่องพร้อมกัน
# for i in range(10): # จำลอง 10 clients
#     for url in servers:
#         threading.Thread(target=send_request, args=(url,)).start()