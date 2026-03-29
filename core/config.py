import json
import os
from pathlib import Path

class Settings:
    def __init__(self):
        # 1. กำหนดค่า Default ไว้ก่อน เผื่อไฟล์ config.json หาย
        self.database_name = "NetworkAnalysis"
        self.db_uri = "mongodb://localhost:27017"
        self.upload_dir = "uploads"
        self.result_dir = "results"
        self.queue_size = 100000
        self.chunk_size = 10000
        self.interface = "eth0"
        self.pcap_file = "pcap/icmp/ICMP Test 2.pcap"
        
        # 2. ระบุ Path ของไฟล์ config.json อ้างอิงจากตำแหน่งไฟล์นี้
        config_path = Path(__file__).parent.parent / "config.json"

        # 3. โหลดข้อมูลจาก config.json ถ้ามีไฟล์อยู่จริง
        if config_path.exists():
            with open(config_path, "r", encoding="utf-8") as f:
                config_data = json.load(f)
                # อัปเดตค่าใน Class ตามข้อมูลใน config.json
                for key, value in config_data.items():
                    if hasattr(self, key):
                        setattr(self, key, value)
            print(f"Loaded config from {config_path}")
        else:
            print("Config file not found, using default settings.")

# สร้าง Instance ครั้งเดียว
settings = Settings()

