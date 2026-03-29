from fastapi import APIRouter
from pydantic import IPvAnyAddress
from core.config import settings

router = APIRouter(
    prefix="/settings",    # ทุก API ในไฟล์นี้จะขึ้นต้นด้วย /settings
    tags=["settings"]      # ช่วยจัดกลุ่มในหน้า /docs
)


@router.post("/set_interface")
async def set_interface(interface : str):
    settings.interface = interface
    return settings.interface
