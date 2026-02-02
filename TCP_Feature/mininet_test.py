from mininet.link import TCLink
from mininet.net import Mininet

net = Mininet(link=TCLink)
h1 = net.addHost("h1", ip="10.0.0.1")
server = net.addHost("server", ip="10.0.0.2")

# ตั้งค่า Link ให้มีความหน่วง 15ms (iRTT ควรจะได้ 30ms)
net.addLink(h1, server, delay="15ms")

net.start()

# 1. รัน Web Server บน host 'server'
print("กำลังเปิด Web Server...")
server.cmd("python3 -m http.server 80 &")

# 2. เริ่มดักจับ Packet ด้วย dumpcap (ทำเบื้องหลัง)
h1.cmd("dumpcap -i h1-eth0 -w test_web.pcap -a duration:10 &")

# 3. h1 ทำการ "รีเฟรชหน้าเว็บ" (ส่ง HTTP Request)
print("h1 กำลังเข้าเว็บ...")
h1.cmd("curl http://10.0.0.2")

net.stop()
print("จบการเทส บันทึกไฟล์ test_web.pcap แล้ว")
