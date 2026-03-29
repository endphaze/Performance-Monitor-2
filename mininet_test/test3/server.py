from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import asyncio
import time

app = FastAPI()

origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,            # อนุญาตทุก Domain
    allow_credentials=True,
    allow_methods=["*"],              # อนุญาตทุก Method (GET, POST, etc.)
    allow_headers=["*"],              # อนุญาตทุก Header
)

@app.get("/test")
async def simulate_delay():
    """
    Endpoint ที่จะรอตามจำนวนวินาทีที่กำหนดก่อนส่ง Response
    """
    start_time = time.time()
    seconds = 3
    # ใช้ asyncio.sleep แทน time.sleep เพื่อไม่ให้ Server หยุดทำงานทั้งระบบ
    await asyncio.sleep(seconds)
    
    end_time = time.time()
    duration = end_time - start_time
    
    return {
        "status": "success",
        "requested_delay": seconds,
        "actual_duration": round(duration, 4),
        "message": f"Delayed response for {seconds} seconds"
    }

if __name__ == "__main__":
    import uvicorn
    # รัน server ที่ port 8000
    uvicorn.run(app, host="0.0.0.0", port=8888)