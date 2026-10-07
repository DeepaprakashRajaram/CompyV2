import os
import hashlib
import uuid
import json
import asyncio
from datetime import datetime, timezone
from fastapi import FastAPI, BackgroundTasks, Request, HTTPException
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from fmd.v2.application.use_cases import AnalyzeMemoryUseCase, AnalyzeMemoryRequest
from fmd.v2.adapters.cli.compy_cli import build_v2_app
from fmd.v2.adapters.web.report import generate_forensic_report

app = FastAPI(title="Compy Web - Cyber Forensic Engine")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

# In-memory database for local execution
REPORTS_DB = {}
JOBS_DB = {}

class AnalyzeRequest(BaseModel):
    file_path: str

def get_human_readable_size(size_bytes):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0

def process_memory_dump_task(job_id: str, file_path: str):
    try:
        JOBS_DB[job_id]["status"] = "processing"
        JOBS_DB[job_id]["message"] = "Hashing file (SHA-256)..."
        
        # 1. Verify file exists and calculate hash
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found on local disk: {file_path}")
            
        file_size_bytes = os.path.getsize(file_path)
        human_size = get_human_readable_size(file_size_bytes)
        
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(8192 * 1024):
                sha256_hash.update(chunk)
        hash_hex = sha256_hash.hexdigest()
        
        JOBS_DB[job_id]["message"] = "Executing Fileless Forensic Engine..."
        
        # 2. Run Forensic Analysis
        use_case = build_v2_app()
        req = AnalyzeMemoryRequest(
            target_path=file_path,
            session_timestamp=datetime.now(timezone.utc)
        )
        dossier = use_case.execute(req)
        
        JOBS_DB[job_id]["message"] = "Generating Reports (PDF & JSON)..."
        
        # 3. Generate Reports
        from pathlib import Path
        import tempfile
        file_name = Path(file_path).name
        
        report_filename = f"Report_{dossier.investigation_id}.pdf"
        report_path = os.path.join(tempfile.gettempdir(), report_filename)
        
        generate_forensic_report(
            dossier=dossier,
            file_name=file_name,
            file_hash=hash_hex,
            file_size=human_size,
            output_path=report_path
        )
        
        # 4. Save JSON Report Data
        json_data = {
            "investigation_id": dossier.investigation_id,
            "created_at": dossier.created_at.isoformat(),
            "target_file": file_name,
            "sha256": hash_hex,
            "system_status": dossier.system_status.value,
            "candidates_found": len(dossier.candidates),
            "engine_version": dossier.schema_version
        }
        
        REPORTS_DB[dossier.investigation_id] = {
            "pdf_path": report_path,
            "json_data": json_data,
            "finding": dossier.system_status.value
        }
        
        JOBS_DB[job_id]["status"] = "completed"
        JOBS_DB[job_id]["investigation_id"] = dossier.investigation_id
        
    except Exception as e:
        JOBS_DB[job_id]["status"] = "failed"
        JOBS_DB[job_id]["message"] = str(e)


@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")

@app.post("/api/analyze")
async def start_analysis(req: AnalyzeRequest, background_tasks: BackgroundTasks):
    job_id = str(uuid.uuid4())
    JOBS_DB[job_id] = {
        "status": "queued",
        "message": "Initializing...",
        "investigation_id": None
    }
    
    # Run the heavy process in the background
    background_tasks.add_task(process_memory_dump_task, job_id, req.file_path)
    
    return {"job_id": job_id}

@app.get("/api/status/{job_id}")
async def get_status(job_id: str):
    if job_id not in JOBS_DB:
        raise HTTPException(status_code=404, detail="Job not found")
        
    job = JOBS_DB[job_id]
    if job["status"] == "completed":
        job["finding"] = REPORTS_DB[job["investigation_id"]]["finding"]
        
    return job

@app.get("/report/download/pdf/{investigation_id}")
async def download_pdf(investigation_id: str):
    if investigation_id not in REPORTS_DB:
        raise HTTPException(status_code=404, detail="Report not found")
    report_info = REPORTS_DB[investigation_id]
    return FileResponse(
        path=report_info["pdf_path"], 
        filename=f"Compy_Report_{investigation_id}.pdf",
        media_type='application/pdf'
    )

@app.get("/report/download/json/{investigation_id}")
async def download_json(investigation_id: str):
    if investigation_id not in REPORTS_DB:
        raise HTTPException(status_code=404, detail="Report not found")
    report_info = REPORTS_DB[investigation_id]
    return JSONResponse(
        content=report_info["json_data"],
        headers={"Content-Disposition": f"attachment; filename=Compy_Data_{investigation_id}.json"}
    )

