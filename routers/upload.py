from fastapi import APIRouter, UploadFile, File, HTTPException
import shutil
import os

from core.config import settings

router = APIRouter()

@router.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    # 1. ตรวจสอบนามสกุลไฟล์เบื้องต้น
    if not file.filename.endswith(('.pcap', '.pcapng')):
        raise HTTPException(status_code=400, detail="Invalid file type. Only .pcap or .pcapng are allowed.")

    # 2. กำหนด Path
    file_path = os.path.join(settings.upload_dir, file.filename)
    
    # มั่นใจว่าโฟลเดอร์สำหรับ upload มีอยู่จริง
    os.makedirs(settings.upload_dir, exist_ok=True)

    try:
        # Stream ข้อมูลจาก Network ลง Disk ตรงๆ
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Could not save file: {str(e)}")
    finally:
        file.file.close() # ปิดไฟล์หลังจากทำงานเสร็จ

    # 4. อัปเดต Path 
    settings.pcap_file = file_path
            
    return {
        "status": "success",
        "filename": file.filename,
        "saved_at": file_path
    }
    
# @router.get("/list_pcap")
# async def list_pcap_files():
#     # 1. ระบุโฟลเดอร์ที่เก็บไฟล์ (ดึงมาจาก settings ที่เราทำไว้)
#     upload_dir = settings.upload_dir
    
#     # 2. ตรวจสอบว่ามีโฟลเดอร์อยู่จริงไหม
#     if not os.path.exists(upload_dir):
#         return {"files": [], "message": "Upload directory not found"}
    
#     # 3. ลิสต์ไฟล์เฉพาะที่มีนามสกุล .pcap หรือ .pcapng
#     files = [] 
#     for f in os.listdir(upload_dir):
#         # เช็คว่าไฟล์ลงท้ายด้วย .pcap หรือ .pcapng ไหม
#         if f.endswith('.pcap') or f.endswith('.pcapng'):
#             files.append(f)
    
#     # 4. (Optional) ถ้าอยากได้ข้อมูลเพิ่ม เช่น ขนาดไฟล์ หรือเวลาที่อัปโหลด
#     file_details = []
#     for f in files:
#         file_path = os.path.join(upload_dir, f)
#         stats = os.stat(file_path)
#         file_details.append({
#             "name": f,
#             "size_mb": round(stats.st_size / (1024 * 1024), 2),
#             "modified": stats.st_mtime
#         })
    
#     return {"files": file_details}