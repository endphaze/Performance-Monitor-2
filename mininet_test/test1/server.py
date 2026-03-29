from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse
import uvicorn

app = FastAPI()

@app.post("/")
async def root(request: Request):
    # อ่านข้อมูลที่ Client ส่งมา (ตรวจสอบขนาด Request)
    body = await request.body()
    print(f"Received Request size: {len(body)} bytes")
    
    # ตอบกลับด้วยข้อมูลขนาด 3000 bytes (เพื่อให้ Reply เกิน MTU 1500)
    return PlainTextResponse("R" * 3000)

if __name__ == "__main__":
    # กำหนดพอร์ต 8080 และให้ยอมรับการเชื่อมต่อจากทุก IP ใน Mininet
    uvicorn.run(app, host="0.0.0.0", port=80)