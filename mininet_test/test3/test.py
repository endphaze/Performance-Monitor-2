from mininet.net import Mininet
from mininet.node import Controller
from mininet.nodelib import NAT
from mininet.cli import CLI
from mininet.link import TCLink
import os

def myNetwork():
    # ใช้ NAT=True เพื่อเปิดฟังก์ชัน NAT ของ Mininet (เหมือน sudo mn --nat)
    net = Mininet(controller=Controller, link=TCLink)
    net.addController('c0')

    
    


    
    # defaultRoute='via 192.168.1.254'
    # จำลอง Client และ Server พร้อมตั้ง Default Route ไปที่ NAT
    
    # สร้าง Switch
    s1 = net.addSwitch('s1')
    net.addNAT().configDefault()

    # จำลอง Client และ Server
    clients = [net.addHost(f'h{i}', ip=f'192.168.1.{i}/24') for i in range(1, 4)]
    servers = [net.addHost(f'srv{i}', ip=f'192.168.1.1{i}/24' ) for i in range(1, 3)]
    
    # เชื่อมต่อเข้า Switch
    for h in clients + servers:
        net.addLink(h, s1, delay='10ms', mtu=1500)

    net.start()

    # --- ส่วนการทำ Port Mirror สำหรับ Live Analysis ---
    print("*** Setting up Mirror Port for Live Analysis...")
    s1_node = net.get('s1')
    
    
    # 1. สร้าง Interface ชื่อ 'vmirror0' บน Switch s1
    s1_node.cmd('ovs-vsctl add-port s1 vmirror0 -- set interface vmirror0 type=internal')
    s1_node.cmd('ip link set vmirror0 up')

    # 2. ดึง UUID ของพอร์ต vmirror0 มาเก็บในตัวแปร (ตัดช่องว่างและ \n ออก)
    vmirror_uuid = s1_node.cmd('ovs-vsctl get port vmirror0 _uuid').strip()

    # 3. ตั้งค่า Mirror โดยใช้ UUID ที่ดึงมาได้
    # ใช้ f-string เพื่อใส่ค่า vmirror_uuid ลงในคำสั่ง
    s1_node.cmd(f'ovs-vsctl -- set Bridge s1 mirrors=@m '
                f'-- --id=@m create Mirror name=live-mirror '
                f'select_all=1 output_port={vmirror_uuid}')

    # (Optional) ถ้าต้องการให้ข้อมูลไหลไปที่ eth0 ของ WSL จริงๆ
    # s1_node.cmd('tc qdisc add dev vmirror0 ingress')
    # s1_node.cmd('tc filter add dev vmirror0 ingress protocol all u32 match u32 0 0 action mirred egress mirror dev eth0')

    # --- เริ่มรัน Server / Client  ---
    srv1 = net.get('srv1')
    srv2 = net.get("srv2")
    h1 = net.get("h1")
    h2 = net.get("h2")
    h3 = net.get("h3")
    target_ip = "192.168.1.12"

    print("*** Running Background Tasks...")
    srv1.cmd('./.venv/bin/python3 mininet_test/test3/server.py &')
    srv2.cmd('./.venv/bin/python3 mininet_test/test3/server.py &')
    
    h1.cmd('./.venv/bin/python3 mininet_test/test3/client.py &')
    # ยิง hping3 ทดสอบระบบ 
    # h1.cmd(f'hping3 -S -p 8888 --rand-source -i u1000 {target_ip} &')
    
    h2.cmd('./.venv/bin/python3 mininet_test/test3/client.py &')
    h3.cmd('./.venv/bin/python3 mininet_test/test3/client.py &')
    
    # --- แจ้งเตือนเรื่องการดักจับ ---
    print(f"\n[INFO] Mirror is active on interface: vmirror0")
    print(f"[INFO] You can run your analysis script using: sudo python3 analysis.py --iface vmirror0\n")

    CLI(net)
    
    # Cleanup Mirror
    print("*** Cleaning up Mirror...")
    s1_node.cmd('ovs-vsctl clear Bridge s1 mirrors')
    net.stop()

if __name__ == '__main__':
    myNetwork()