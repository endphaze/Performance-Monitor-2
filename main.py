from fastapi import FastAPI, Request, File, UploadFile, APIRouter
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import IPvAnyAddress
from dataclasses import asdict

import importlib, inspect, pkgutil, os, sys
import pyshark

import asyncio

from routers import analysisManager, pcapAnalysis, setConfig, upload, liveAnalysis, exportManager
from core.config import settings
import core.data as data
import analysis

app = FastAPI()
origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,            # อนุญาตทุก Domain
    allow_credentials=True,
    allow_methods=["*"],              # อนุญาตทุก Method (GET, POST, etc.)
    allow_headers=["*"],              # อนุญาตทุก Header
)


v1_router = APIRouter(prefix="/v1")
v1_router.include_router(analysisManager.router)
v1_router.include_router(setConfig.router)
v1_router.include_router(upload.router)
v1_router.include_router(liveAnalysis.router)
v1_router.include_router(exportManager.router)
v1_router.include_router(pcapAnalysis.router)

api_router = APIRouter(prefix="/api")
api_router.include_router(v1_router)

app.include_router(api_router)

dist_path = os.path.join(os.getcwd(), "dist")

if os.path.exists(dist_path):
    # 1. ให้ FastAPI รู้จักโฟลเดอร์ assets (เก็บ js, css)
    app.mount("/assets", StaticFiles(directory=os.path.join(dist_path, "assets")), name="assets")

    # 2. ดักทุก Path ที่เหลือให้ไปลงที่ index.html
    @app.get("/{full_path:path}")
    async def serve_frontend(full_path: str):
        return FileResponse(os.path.join(dist_path, "index.html"))
    
else:
    print(f"Not Found {dist_path}")
    


if __name__ == "__main__":
    # กำหนดพอร์ต 8080 และให้ยอมรับการเชื่อมต่อจากทุก IP ใน Mininet
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
    