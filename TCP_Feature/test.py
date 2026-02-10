import struct
from hashlittlebyte import hashlittle

def get_flow_key(src_ip, dst_ip, src_port, dst_port, proto):
        # 1. Canonical Sort: บังคับให้ข้อมูลที่น้อยกว่าอยู่หน้าเสมอ
        # เพื่อให้ทั้งสองทิศทาง (A->B และ B->A) ได้ลำดับข้อมูลเหมือนกันเป๊ะ
        if (src_ip, src_port) < (dst_ip, dst_port):
            s_ip, d_ip, s_p, d_p = src_ip, dst_ip, src_port, dst_port
        else:
            s_ip, d_ip, s_p, d_p = dst_ip, src_ip, dst_port, src_port
        
        # 2. นำตัวแปรที่ "จัดลำดับใหม่แล้ว" มา Pack เป็น Bytes
        # (เปลี่ยนจาก 'e' เป็น 'B' เพื่อความถูกต้องของ Protocol ID 1 byte)
        raw_data = struct.pack("!4s4sHHB", 
                               bytes(map(int, s_ip.split('.'))),
                               bytes(map(int, d_ip.split('.'))),
                               s_p, d_p, proto)
        print(raw_data)
        # แปลง Bytes เป็น Str แบบ 1 ต่อ 1 ด้วย latin-1
        # str_data = raw_data.decode('latin-1')
        # 3. คำนวณ Jenkins Hash จากก้อนข้อมูลที่ "นิ่ง" แล้ว
        return hashlittle(raw_data)
    
flow_id = get_flow_key(src_ip="64.29.17.131", src_port=51970, dst_ip="64.29.17.131", dst_port=443, proto=6)
    
print(flow_id)