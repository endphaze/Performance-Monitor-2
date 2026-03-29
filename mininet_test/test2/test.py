from mininet.net import Mininet
from mininet.node import Controller
from mininet.cli import CLI
from mininet.link import TCLink

import time

def myNetwork():
    net = Mininet(controller=Controller, link=TCLink)
    net.addController('c0')

    # สร้าง Switch
    s1 = net.addSwitch('s1')

    # จำลอง Client 3 เครื่อง
    clients = [net.addHost(f'h{i}', ip=f'192.168.1.{i}') for i in range(1, 4)]
    
    # จำลอง Server 2 เครื่อง
    servers = [net.addHost(f'srv{i}', ip=f'192.168.1.1{i}') for i in range(1, 3)]
    
    # เชื่อมต่อและตั้งค่า MTU (เช่น ตั้งค่าที่ Link ให้ต่ำกว่าข้อมูลที่จะส่ง)
    for h in clients + servers:
        # jitter='10ms' และ reorder='25%' หมายถึงมีโอกาส 25% ที่แพ็กเก็ตจะถูกส่งสลับลำดับกัน
        net.addLink(h, s1, delay='10ms', jitter="10ms", mtu=1500)
    

    net.start()
    
    # ทดสอบเปลี่ยน MTU ของ Interface เฉพาะเจาะจงให้เล็กลงเพื่อบังคับ Fragment
    # net.get('h1').cmd('ifconfig h1-eth0 mtu 1400') 
    

    # ดักจับ Traffic ทั้งหมดที่ผ่าน Switch s1
    print("*** Capturing all traffic on s1...")
    s1 = net.get('s1')
    s1.cmd('tcpdump -i any -w all_traffic.pcap &')
    
    # --- เพื่อรัน Server อัตโนมัติ ---
    print("*** Starting Server on srv1 and srv2")
    srv1 = net.get('srv1')
    srv2 = net.get("srv2")
    

    
    # และใช้ & เพื่อให้รันเป็น background ไม่ขวางการเปิด CLI
    srv1.cmd('./venv_mininet/bin/python3 test1/server.py &')
    srv2.cmd('./venv_mininet/bin/python3 test1/server.py &')
    
    # print("*** Starting Host on h1 h2 and h3")
    # h1 = net.get('h1')
    # h2 = net.get("h2")
    # h3 = net.get("h3")
    
    # print("*** Turn off TSO on h1 h2 and h3")
    # h1.cmd('ethtool -K h1-eth0 tso off')
    # h2.cmd('ethtool -K h2-eth0 tso off')
    # h3.cmd('ethtool -K h3-eth0 tso off')
    
    # h1.cmd('./venv_mininet/bin/python3 test1/client.py &')
    # h2.cmd('./venv_mininet/bin/python3 test1/client.py &')
    # h3.cmd('./venv_mininet/bin/python3 test1/client.py &')
    
    
    # for i in range(1,11): # ปรับจำนวนวินาทีได้
    #     time.sleep(1)
    #     print(i, "sec")
    
        
    CLI(net)
    
    print("*** Cleaning up processes...")
    s1.cmd('pkill tcpdump')
    srv1.cmd('pkill -f server.py')
    srv2.cmd('pkill -f server.py')
    # h1.cmd('pkill -f client.py')
    # h2.cmd('pkill -f client.py')
    # h3.cmd('pkill -f client.py')
    
    net.stop()

if __name__ == '__main__':
    myNetwork()