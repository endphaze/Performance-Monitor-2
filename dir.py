import pyshark
import subprocess
import json

# cap = pyshark.FileCapture(
#     "pcap/tcp/mininet_test2.pcap",
#     display_filter="tcp.analysis.fast_retransmission",use_json=True
# )



# print(cap[0].tcp.get("analysis.fast_retransmission"))

# obtain all the field names within the ETH packets

def get_field(pkt, field):
    return pkt["_source"]["layers"].get(field, [None])[0]

# cmd = [
#     "tshark",
#     "-r", "pcap/tcp/mininet_test2.pcap",
#     "-Y", "tcp.analysis.fast_retransmission",
#     "-T", "fields",
#     "-e", "frame.number",
#     "-e", "tcp.analysis.fast_retransmission"
# ]


# process = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)

# for line in process.stdout:
#     if line == "\n":
#         continue
#     print(line)


def flatten_layers(layers_dict):
    flattened = {}
    for key, value in layers_dict.items():
        if isinstance(value, list):
            if len(value) == 1:
                # ถ้ามีตัวเดียว ให้ยุบเป็นค่าเดี่ยว (Common case)
                flattened[key] = value[0]
            elif len(value) > 1:
                # ถ้ามีหลายตัว ให้เป็น List ไว้ 
                flattened[key] = value 
            else:
                flattened[key] = None
        else:
            flattened[key] = value
    return flattened


def stream_tshark_output(display_filter, fields=[], count=None):
    
    pcap_path = "pcap/tcp/carbon_test.pcap"
    
    cmd = [
        "tshark", 
        "-r", pcap_path,
        "-2",                                      # วิเคราะห์ 2 รอบเพื่อความแม่นยำ
        "-o", "tcp.analyze_sequence_numbers:TRUE",  # บังคับวิเคราะห์ Seq Number
        "-o", "tcp.relative_sequence_numbers:TRUE", # ใช้ Relative Seq เหมือน Wireshark
        "-o", "tcp.check_checksum:FALSE",           # ป้องกันการข้ามแพ็กเก็ตที่ checksum ผิด
        "-Y", str(display_filter),
        "-T", "ek"                                 # ใช้ EK format เพื่อความยืดหยุ่น
    ]
    
    if count:
        cmd.extend(["-c", str(count)])
    
    for field in fields:
        cmd.extend(["-e", field])
    
    
    # ใช้ Popen เพื่ออ่าน Output ทันทีที่ TShark พ่นออกมา (ไม่ต้องรอจบไฟล์)
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
    try :
        
        for line in process.stdout:
            line = line.strip()
            if not line or line.startswith('{"index"'):
                continue
                
            pkt_raw = json.loads(line)
            layers = pkt_raw.get("layers", {})
            
            # สร้าง Dictionary ใหม่ที่จะเก็บข้อมูล
            # เริ่มใส่ timestamp ลงไปก่อน
            clean_pkt = {
                "timestamp": pkt_raw.get("timestamp")
            }
            
            # วนลูปเพื่อดึงข้อมูลจาก layers ออกมาวางไว้ที่ระดับบนสุด
            for key, value in layers.items():
                if isinstance(value, list):
                    if len(value) == 1:
                        clean_pkt[key] = value[0] # ยุบเป็นค่าเดี่ยว
                    elif len(value) > 1:
                        clean_pkt[key] = value    # ถ้ามีหลายค่า เก็บเป็น List ไว้
                    else:
                        clean_pkt[key] = None
                else:
                    clean_pkt[key] = value
            
            yield clean_pkt
    finally :
        process.terminate()
        process.wait()

  
        
fields = ["frame.number","ip.src", "ip.dst", "tls.handshake", "tls.change_cipher_spec", "tls.alert_message"]

display_filter = 'ip.src == 161.246.72.218 and (tls.change_cipher_spec or tls.handshake or tls.alert_message)'

i = 0
limit = 80
for pkt in stream_tshark_output(display_filter, fields):
    if limit and i > limit:
        break
    num = pkt.get("frame_number")
    # print(num, bool(pkt.get("tls_handshake")), bool(pkt.get("tls_change_cipher_spec")), bool(pkt.get("tls_alert_message")))
    print(pkt)
    i += 1




# for frame, seq in stream_tshark_output():
#     print(frame, seq)
# layers = packets[0]["_source"]["layers"]
# print(layers)
    
# for attr in dir(cap[0].tcp):
#     print(attr)
# field_names = packet.icmp._all_fields

# # obtain all the field values
# field_values = packet.icmp._all_fields.values()

# # enumerate the field names and field values
# for field_name, field_value in zip(field_names, field_values):
#     print(f"{field_name}:  {field_value}")

