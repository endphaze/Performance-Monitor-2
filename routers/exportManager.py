import io
import zipfile
import pandas as pd
from fastapi import APIRouter
from fastapi.responses import StreamingResponse

import core.data 
from core.database import db
from core.config import settings

router = APIRouter(
    prefix="/export",    # ทุก API ในไฟล์นี้จะขึ้นต้นด้วย /settings
    tags=["export"]      # ช่วยจัดกลุ่มในหน้า /docs
)


@router.get("/csv/{analysis_name}")
async def export_single_csv(analysis_name: str):
    collection = db[analysis_name]
    df = pd.DataFrame(list(collection.find()))
    
    if "_id" in df.columns: df = df.drop(columns=["_id"])
    
    stream = io.StringIO()
    df.to_csv(stream, index=False)
    
    return StreamingResponse(
        iter([stream.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={analysis_name}.csv"}
    )