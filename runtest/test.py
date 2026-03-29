import requests
import json
import time
import server

# กำหนด Base URL ของ API
BASE_URL = "http://127.0.0.1:8000"

def run_analysis_workflow():
    try:
        # 1. ดึงรายการ Script ทั้งหมด (GET /analysis/get_analysis_scripts_list)
        print("--- Step 1: Getting Analysis Scripts List ---")
        response_list = requests.get(f"{BASE_URL}/analysis/get_analysis_scripts_list")
        response_list.raise_for_status()
        print("Scripts List:", response_list.json())

        # 2. เลือก Script ที่ต้องการใช้งาน (GET /analysis/select_active_analysises)
        # ตัวอย่างตามคำสั่ง: query numbers_analysis="1"
        print("\n--- Step 2: Selecting Active Analysis ---")
        params = {"numbers_analysis": "1"}
        response_select = requests.post(f"{BASE_URL}/analysis/select_active_analysises", params=params)
        response_select.raise_for_status()
        print("Selection Status:", response_select.json())

        # 3. ตั้งค่า Arguments สำหรับการวิเคราะห์ (POST /analysis/set_arguments)
        print("\n--- Step 3: Setting Arguments ---")
        payload = {
            "http_analysis_with_tcp3": {
                "target_ip": "127.0.0.1",
                "ports": [8888]
            }
        }
        
        # ส่งแบบ JSON Body
        response_args = requests.post(
            f"{BASE_URL}/analysis/set_arguments",
            json=payload
        )
        response_args.raise_for_status()
        print("Arguments Status:", response_args.json())
        
        print("\nWorkflow Completed Successfully!")

    except requests.exceptions.RequestException as e:
        print(f"\nAn error occurred: {e}")

if __name__ == "__main__":
    
    import uvicorn
    
    run_analysis_workflow()
    
    uvicorn.run(server.app, host="0.0.0.0", port=8888)
    
    
    

    
        
        