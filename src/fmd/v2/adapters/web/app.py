import os
import hashlib
import uuid
import json
import asyncio
from pathlib import Path
from datetime import datetime, timezone
from fastapi import FastAPI, BackgroundTasks, Request, HTTPException
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from fmd.v2.application.use_cases import AnalyzeMemoryUseCase, AnalyzeMemoryRequest
from fmd.v2.bootstrap import (
    create_demo_app, 
    create_real_app, 
    is_supported_memory_image, 
    classify_artifact,
    SUPPORTED_MEMORY_EXTENSIONS,
    ALL_SUPPORTED_EXTENSIONS
)
from fmd.v2.domain.contracts import CapabilityStatus, TriState
from fmd.v2.adapters.web.report import generate_forensic_report
from fmd.v2.adapters.reporting.html_to_pdf_renderer import HtmlToPdfRenderer
from fmd.v2.adapters.reporting.mapper import dossier_to_report_dict

app = FastAPI(title="Compy Web - Cyber Forensic Engine")
app.state.custom_collector = None

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

# In-memory database for local execution
REPORTS_DB = {}
JOBS_DB = {}

class AnalyzeRequest(BaseModel):
    file_path: str

class DemoAnalyzeRequest(BaseModel):
    scenario: str = "synthetic_fileless_malware_demo"

def get_human_readable_size(size_bytes):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0

def process_demo_analysis_task(job_id: str):
    try:
        JOBS_DB[job_id]["status"] = "processing"
        JOBS_DB[job_id]["message"] = "Generating synthetic demonstration fixtures..."
        
        file_name = "synthetic_demo_image.raw"
        hash_hex = "0000000000000000000000000000000000000000000000000000000000000000"
        human_size = "16.00 GB (Synthetic Demo)"
        
        use_case = create_demo_app()
        req = AnalyzeMemoryRequest(
            target_path=file_name,
            session_timestamp=datetime.now(timezone.utc)
        )
        dossier = use_case.execute(req)
        
        JOBS_DB[job_id]["message"] = "Compiling synthetic demonstration report..."
        
        from pathlib import Path
        import tempfile
        
        report_filename = f"Report_DEMO_{dossier.investigation_id}.pdf"
        report_html_name = f"Report_DEMO_{dossier.investigation_id}.html"
        report_path = os.path.join(tempfile.gettempdir(), report_filename)
        report_html_path = os.path.join(tempfile.gettempdir(), report_html_name)
        
        report_dict = dossier_to_report_dict(
            dossier=dossier,
            file_name=file_name,
            file_hash=hash_hex,
            file_size=human_size,
            examiner_name="Synthetic Demo Examiner",
            agency_name="Demonstration Testing Environment",
            is_synthetic_demo=True
        )

        try:
            renderer = HtmlToPdfRenderer()
            renderer.render(
                report_data=report_dict,
                output_pdf_path=report_path,
                output_html_path=report_html_path
            )
        except Exception:
            generate_forensic_report(
                dossier=dossier,
                file_name=file_name,
                file_hash=hash_hex,
                file_size=human_size,
                output_path=report_path
            )
        
        ppid_anomalies_list = [
            {
                "pid": getattr(o, "process_pid", None),
                "process_name": getattr(o, "process_name", None),
                "ppid": getattr(o, "ppid", None),
                "actual_parent": getattr(o, "actual_parent", None),
                "expected_parent": getattr(o, "expected_parent", None),
                "category": getattr(o, "anomaly_category", None),
                "confidence": getattr(o, "confidence", 1.0),
                "description": getattr(o, "description", "")
            }
            for o in dossier.process_tree_anomalies
        ]

        hidden_rootkit_list = [
            {
                "pid": getattr(o, "process_pid", None),
                "process_name": getattr(o, "process_name", None),
                "ppid": getattr(o, "ppid", None),
                "thread_count": getattr(o, "thread_count", 0),
                "category": getattr(o, "anomaly_category", "ROOTKIT_DKOM"),
                "confidence": getattr(o, "confidence", 1.0),
                "description": getattr(o, "description", "")
            }
            for o in dossier.hidden_process_anomalies
        ]

        injected_code_list = [
            {
                "pid": getattr(o, "process_pid", None),
                "process_name": getattr(o, "process_name", None),
                "start_address": getattr(o, "start_address", 0),
                "end_address": getattr(o, "end_address", 0),
                "protection": getattr(o, "protection", ""),
                "category": getattr(o, "anomaly_category", "CODE_INJECTION"),
                "confidence": getattr(o, "confidence", 0.90),
                "description": getattr(o, "description", "")
            }
            for o in getattr(dossier, "injected_code_anomalies", [])
        ]

        yara_matches_list = [
            {
                "rule": getattr(o, "rule_name", "UNKNOWN"),
                "target": str(getattr(o, "target_identifier", "TARGET")),
                "target_type": getattr(o, "target_type", "PROCESS_MEMORY"),
                "matched_count": len(getattr(o, "matched_strings", ())),
                "severity": (getattr(o, "meta", {}) or {}).get("severity", "HIGH"),
                "description": getattr(o, "description", "")
            }
            for o in getattr(dossier, "yara_anomalies", [])
        ]

        mitigation_list = [
            rec.to_dict() if hasattr(rec, "to_dict") else dict(rec)
            for rec in getattr(dossier, "mitigation_recommendations", [])
        ]

        demo_verdict = report_dict.get("summary", {}).get("verdict", "DETECTED")
        demo_risk_score = report_dict.get("summary", {}).get("risk_score", 92)

        json_data = dict(report_dict)
        json_data["investigation_id"] = dossier.investigation_id
        json_data["created_at"] = dossier.created_at.isoformat()
        json_data["mode"] = "DEMO"
        json_data["is_synthetic_demo"] = True
        json_data["disclaimer"] = "SYNTHETIC DEMONSTRATION — NOT REAL FORENSIC EVIDENCE"
        json_data["target_file"] = file_name
        json_data["sha256"] = hash_hex
        json_data["system_status"] = dossier.system_status.value
        json_data["execution_summary"] = {
            "executed_detectors": [
                "process_tree_anomaly_v1",
                "hidden_process_rootkit_v1",
                "injected_code_malfind_v1",
                "yara_signature_detector_v1"
            ],
            "unexecuted_checks": [
                "SSDT_HOOK_AUDIT",
                "IDT_HOOK_AUDIT",
                "IRP_HOOK_AUDIT"
            ]
        }
        json_data["metrics"] = {
            "ppid_anomalies_count": len(ppid_anomalies_list),
            "hidden_rootkits_count": len(hidden_rootkit_list),
            "injected_code_count": len(injected_code_list),
            "yara_matches_count": len(yara_matches_list),
            "mitigation_count": len(mitigation_list)
        }
        json_data["findings"] = {
            "process_tree_anomalies": ppid_anomalies_list,
            "hidden_rootkits": hidden_rootkit_list,
            "injected_code": injected_code_list,
            "yara_matches": yara_matches_list,
            "detailed_findings": report_dict.get("findings", [])
        }
        json_data["detailed_findings"] = report_dict.get("findings", [])

        report_json_name = f"Report_DEMO_{dossier.investigation_id}.json"
        report_json_path = os.path.join(tempfile.gettempdir(), report_json_name)
        with open(report_json_path, "w", encoding="utf-8") as f:
            json.dump(json_data, f, indent=2)

        REPORTS_DB[dossier.investigation_id] = {
            "mode": "DEMO",
            "is_synthetic_demo": True,
            "pdf_path": report_path,
            "html_path": report_html_path if os.path.exists(report_html_path) else None,
            "json_path": report_json_path,
            "json_data": json_data,
            "dfir_data": report_dict,
            "finding": dossier.system_status.value,
            "verdict": demo_verdict,
            "risk_score": demo_risk_score,
            "ppid_count": len(ppid_anomalies_list),
            "rootkit_count": len(hidden_rootkit_list),
            "injected_count": len(injected_code_list),
            "yara_count": len(yara_matches_list),
            "mitigation_count": len(mitigation_list)
        }
        
        JOBS_DB[job_id]["status"] = "completed"
        JOBS_DB[job_id]["mode"] = "DEMO"
        JOBS_DB[job_id]["is_synthetic_demo"] = True
        JOBS_DB[job_id]["investigation_id"] = dossier.investigation_id
        JOBS_DB[job_id]["finding"] = dossier.system_status.value
        JOBS_DB[job_id]["verdict"] = demo_verdict
        JOBS_DB[job_id]["risk_score"] = demo_risk_score
        JOBS_DB[job_id]["ppid_count"] = len(ppid_anomalies_list)
        JOBS_DB[job_id]["rootkit_count"] = len(hidden_rootkit_list)
        JOBS_DB[job_id]["injected_count"] = len(injected_code_list)
        JOBS_DB[job_id]["yara_count"] = len(yara_matches_list)
        JOBS_DB[job_id]["mitigation_count"] = len(mitigation_list)
        JOBS_DB[job_id]["indicators"] = {
            "ppid_status": "PPID Spoofing (Synthetic Demo)",
            "ppid_badge": f"{len(ppid_anomalies_list)} Anomalies",
            "rootkit_status": "Unlinked DKOM (Synthetic Demo)",
            "rootkit_badge": f"{len(hidden_rootkit_list)} Hidden PIDs",
            "injected_status": "Executable Injections (Demo)",
            "injected_badge": f"{len(injected_code_list)} Injected Regions",
            "yara_status": "YARA Signature Matching",
            "yara_badge": f"{len(yara_matches_list)} Matches",
            "mitigation_status": f"{len(mitigation_list)} Actions Recommended",
            "mitigation_badge": f"{len(mitigation_list)} Recommendations"
        }
    except Exception as e:
        JOBS_DB[job_id]["status"] = "failed"
        JOBS_DB[job_id]["message"] = f"Demo error: {str(e)}"

def process_real_memory_dump_task(job_id: str, file_path: str):
    try:
        JOBS_DB[job_id]["status"] = "processing"
        JOBS_DB[job_id]["message"] = "Validating input memory image..."
        
        # 1. Validate file existence and format
        if not os.path.exists(file_path):
            JOBS_DB[job_id]["status"] = "failed"
            JOBS_DB[job_id]["message"] = f"File not found on local disk: {file_path}"
            return

        artifact_type = classify_artifact(file_path)
        if artifact_type == "UNSUPPORTED":
            JOBS_DB[job_id]["status"] = "unsupported"
            JOBS_DB[job_id]["message"] = (
                f"Unsupported format for '{Path(file_path).name}'. "
                f"Supported extensions: {', '.join(sorted(ALL_SUPPORTED_EXTENSIONS))}"
            )
            return
            
        file_size_bytes = os.path.getsize(file_path)
        human_size = get_human_readable_size(file_size_bytes)
        
        JOBS_DB[job_id]["message"] = "Calculating SHA-256 evidence integrity hash..."
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(8192 * 1024):
                sha256_hash.update(chunk)
        hash_hex = sha256_hash.hexdigest()
        
        JOBS_DB[job_id]["message"] = "Initializing Compy Real Forensic Engine..."
        
        # 2. Resolve real provider (FAIL_IF_MISSING policy - NO SILENT FALLBACK TO MOCK)
        custom_collector = getattr(app.state, "custom_collector", None)
        use_case, failure_reason = create_real_app(
            memory_image_path=file_path,
            artifact_hash=hash_hex,
            custom_collector=custom_collector,
            yara_rules_dir="rules/yara"
        )
        
        if use_case is None:
            JOBS_DB[job_id]["status"] = "unavailable"
            JOBS_DB[job_id]["message"] = f"Real forensic capability unavailable: {failure_reason}"
            JOBS_DB[job_id]["detail"] = failure_reason
            return
            
        req = AnalyzeMemoryRequest(
            target_path=file_path,
            session_timestamp=datetime.now(timezone.utc)
        )
        dossier = use_case.execute(req)
        
        JOBS_DB[job_id]["message"] = "Compiling authentic forensic report..."
        
        from pathlib import Path
        import tempfile
        file_name = Path(file_path).name
        
        report_filename = f"Report_{dossier.investigation_id}.pdf"
        report_html_name = f"Report_{dossier.investigation_id}.html"
        report_path = os.path.join(tempfile.gettempdir(), report_filename)
        report_html_path = os.path.join(tempfile.gettempdir(), report_html_name)
        
        # Real mode strictly uses is_synthetic_demo=False
        report_dict = dossier_to_report_dict(
            dossier=dossier,
            file_name=file_name,
            file_hash=hash_hex,
            file_size=human_size,
            is_synthetic_demo=False
        )

        try:
            renderer = HtmlToPdfRenderer()
            renderer.render(
                report_data=report_dict,
                output_pdf_path=report_path,
                output_html_path=report_html_path
            )
        except Exception:
            generate_forensic_report(
                dossier=dossier,
                file_name=file_name,
                file_hash=hash_hex,
                file_size=human_size,
                output_path=report_path
            )
        
        ppid_anomalies_list = [
            {
                "pid": getattr(o, "process_pid", None),
                "process_name": getattr(o, "process_name", None),
                "ppid": getattr(o, "ppid", None),
                "actual_parent": getattr(o, "actual_parent", None),
                "expected_parent": getattr(o, "expected_parent", None),
                "category": getattr(o, "anomaly_category", None),
                "confidence": getattr(o, "confidence", 1.0),
                "description": getattr(o, "description", "")
            }
            for o in dossier.process_tree_anomalies
        ]

        hidden_rootkit_list = [
            {
                "pid": getattr(o, "process_pid", None),
                "process_name": getattr(o, "process_name", None),
                "ppid": getattr(o, "ppid", None),
                "thread_count": getattr(o, "thread_count", 0),
                "category": getattr(o, "anomaly_category", "ROOTKIT_DKOM"),
                "confidence": getattr(o, "confidence", 1.0),
                "description": getattr(o, "description", "")
            }
            for o in dossier.hidden_process_anomalies
        ]

        injected_code_list = [
            {
                "pid": getattr(o, "process_pid", None),
                "process_name": getattr(o, "process_name", None),
                "start_address": getattr(o, "start_address", 0),
                "end_address": getattr(o, "end_address", 0),
                "protection": getattr(o, "protection", ""),
                "category": getattr(o, "anomaly_category", "CODE_INJECTION"),
                "confidence": getattr(o, "confidence", 0.90),
                "description": getattr(o, "description", "")
            }
            for o in getattr(dossier, "injected_code_anomalies", [])
        ]

        yara_matches_list = [
            {
                "rule": getattr(o, "rule_name", "UNKNOWN"),
                "target": str(getattr(o, "target_identifier", "TARGET")),
                "target_type": getattr(o, "target_type", "PROCESS_MEMORY"),
                "matched_count": len(getattr(o, "matched_strings", ())),
                "severity": (getattr(o, "meta", {}) or {}).get("severity", "HIGH"),
                "description": getattr(o, "description", "")
            }
            for o in getattr(dossier, "yara_anomalies", [])
        ]

        mitigation_list = [
            rec.to_dict() if hasattr(rec, "to_dict") else dict(rec)
            for rec in getattr(dossier, "mitigation_recommendations", [])
        ]

        def _check_failed(detector_id: str) -> bool:
            for cf in getattr(dossier, "capability_failures", []):
                pid = getattr(cf, "provider_id", "")
                reason = getattr(cf, "failure_reason", "") or ""
                if (pid == detector_id or detector_id in reason) and getattr(cf, "status", None) in (CapabilityStatus.UNAVAILABLE, CapabilityStatus.FAILED):
                    return True
            return False

        ppid_failed = _check_failed("process_tree_anomaly_v1")
        rootkit_failed = _check_failed("hidden_process_rootkit_v1")
        injected_failed = _check_failed("injected_code_malfind_v1")
        yara_failed = _check_failed("yara_signature_detector_v1") or _check_failed("yara_scanner_provider_v1")

        overall_finding = dossier.system_status.value
        if dossier.system_status == TriState.UNKNOWN:
            if ppid_failed and rootkit_failed and injected_failed and yara_failed:
                overall_finding = "UNAVAILABLE"
            elif (ppid_failed or rootkit_failed or injected_failed or yara_failed) and (ppid_anomalies_list or hidden_rootkit_list or injected_code_list or yara_matches_list):
                overall_finding = "PARTIAL"

        verdict = report_dict.get("summary", {}).get("verdict", overall_finding)
        risk_score = report_dict.get("summary", {}).get("risk_score", 0)

        # Align overall_finding with authoritative TriState verdict
        if verdict == "DETECTED":
            overall_finding = "TRUE"
        elif verdict == "NOT DETECTED":
            overall_finding = "FALSE"
        elif verdict in ("PARTIAL", "UNAVAILABLE"):
            overall_finding = verdict

        executed_detectors = ["process_tree_anomaly_v1", "hidden_process_rootkit_v1"]
        if not injected_failed:
            executed_detectors.append("injected_code_malfind_v1")
        if not yara_failed:
            executed_detectors.append("yara_signature_detector_v1")

        unexecuted_checks = ["SSDT_HOOK_AUDIT", "IDT_HOOK_AUDIT", "IRP_HOOK_AUDIT"]
        if injected_failed:
            unexecuted_checks.append("VAD_INJECTION_SCAN")
        if yara_failed:
            unexecuted_checks.append("YARA_SIGNATURE_SCAN")

        json_data = dict(report_dict)
        json_data["investigation_id"] = dossier.investigation_id
        json_data["created_at"] = dossier.created_at.isoformat()
        json_data["mode"] = "REAL"
        json_data["is_synthetic_demo"] = False
        json_data["target_file"] = file_name
        json_data["sha256"] = hash_hex
        json_data["system_status"] = overall_finding
        json_data["execution_summary"] = {
            "executed_detectors": executed_detectors,
            "unexecuted_checks": unexecuted_checks
        }
        json_data["metrics"] = {
            "ppid_anomalies_count": len(ppid_anomalies_list),
            "hidden_rootkits_count": len(hidden_rootkit_list),
            "injected_code_count": len(injected_code_list),
            "yara_matches_count": len(yara_matches_list),
            "mitigation_count": len(mitigation_list)
        }
        json_data["findings"] = {
            "process_tree_anomalies": ppid_anomalies_list,
            "hidden_rootkits": hidden_rootkit_list,
            "injected_code": injected_code_list,
            "yara_matches": yara_matches_list,
            "detailed_findings": report_dict.get("findings", [])
        }
        json_data["detailed_findings"] = report_dict.get("findings", [])
        
        report_json_name = f"Report_{dossier.investigation_id}.json"
        report_json_path = os.path.join(tempfile.gettempdir(), report_json_name)
        with open(report_json_path, "w", encoding="utf-8") as f:
            json.dump(json_data, f, indent=2)

        REPORTS_DB[dossier.investigation_id] = {
            "mode": "REAL",
            "is_synthetic_demo": False,
            "pdf_path": report_path,
            "html_path": report_html_path if os.path.exists(report_html_path) else None,
            "json_path": report_json_path,
            "json_data": json_data,
            "dfir_data": report_dict,
            "finding": overall_finding,
            "verdict": verdict,
            "risk_score": risk_score,
            "ppid_count": len(ppid_anomalies_list),
            "rootkit_count": len(hidden_rootkit_list),
            "injected_count": len(injected_code_list),
            "yara_count": len(yara_matches_list),
            "mitigation_count": len(mitigation_list)
        }
        
        JOBS_DB[job_id]["status"] = "completed"
        JOBS_DB[job_id]["mode"] = "REAL"
        JOBS_DB[job_id]["is_synthetic_demo"] = False
        JOBS_DB[job_id]["investigation_id"] = dossier.investigation_id
        JOBS_DB[job_id]["finding"] = overall_finding
        JOBS_DB[job_id]["verdict"] = verdict
        JOBS_DB[job_id]["risk_score"] = risk_score
        JOBS_DB[job_id]["ppid_count"] = len(ppid_anomalies_list)
        JOBS_DB[job_id]["rootkit_count"] = len(hidden_rootkit_list)
        JOBS_DB[job_id]["injected_count"] = len(injected_code_list)
        JOBS_DB[job_id]["yara_count"] = len(yara_matches_list)
        JOBS_DB[job_id]["mitigation_count"] = len(mitigation_list)
        JOBS_DB[job_id]["indicators"] = {
            "ppid_status": "PPID Spoofing Detected" if ppid_anomalies_list else ("Analysis Unavailable / Incomplete" if ppid_failed else "Baseline Verified (Executed)"),
            "ppid_badge": f"{len(ppid_anomalies_list)} Anomalies" if not ppid_failed else "Unavailable",
            "rootkit_status": "Unlinked DKOM Detected" if hidden_rootkit_list else ("Analysis Unavailable / Incomplete" if rootkit_failed else "Zero Unlinked PIDs (Executed)"),
            "rootkit_badge": f"{len(hidden_rootkit_list)} Hidden PIDs" if not rootkit_failed else "Unavailable",
            "injected_status": "Executable Injections Detected" if injected_code_list else ("Analysis Unavailable / Incomplete" if injected_failed else "Zero Injected VADs (Executed)"),
            "injected_badge": f"{len(injected_code_list)} Injected Regions" if not injected_failed else "Unavailable",
            "yara_status": "YARA Matches Detected" if yara_matches_list else ("Analysis Unavailable / Incomplete" if yara_failed else "Zero Matches (Executed)"),
            "yara_badge": f"{len(yara_matches_list)} Matches" if not yara_failed else "Unavailable",
            "mitigation_status": f"{len(mitigation_list)} Actions Recommended" if mitigation_list else "Monitoring Baseline",
            "mitigation_badge": f"{len(mitigation_list)} Recommendations"
        }
    except Exception as e:
        JOBS_DB[job_id]["status"] = "failed"
        JOBS_DB[job_id]["message"] = str(e)


@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")

@app.post("/api/analyze/demo")
async def start_demo_analysis(req: DemoAnalyzeRequest, background_tasks: BackgroundTasks):
    job_id = str(uuid.uuid4())
    JOBS_DB[job_id] = {
        "status": "queued",
        "mode": "DEMO",
        "is_synthetic_demo": True,
        "message": "Initializing Synthetic Demonstration Job...",
        "investigation_id": None
    }
    background_tasks.add_task(process_demo_analysis_task, job_id)
    return {"job_id": job_id, "mode": "DEMO", "is_synthetic_demo": True}

@app.post("/api/analyze")
async def start_analysis(req: AnalyzeRequest, background_tasks: BackgroundTasks):
    if not req.file_path or not req.file_path.strip():
        raise HTTPException(status_code=400, detail="Missing target file_path parameter.")
        
    cleaned_path = req.file_path.strip()
    if not os.path.exists(cleaned_path):
        raise HTTPException(status_code=404, detail=f"Target file not found on local disk: {cleaned_path}")
        
    artifact_type = classify_artifact(cleaned_path)
    if artifact_type == "UNSUPPORTED":
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported format for '{Path(cleaned_path).name}'. Supported: Memory dumps, PE executables, and scripts."
        )

    job_id = str(uuid.uuid4())
    JOBS_DB[job_id] = {
        "status": "queued",
        "mode": "REAL",
        "is_synthetic_demo": False,
        "message": "Queued for real forensic analysis...",
        "investigation_id": None
    }
    background_tasks.add_task(process_real_memory_dump_task, job_id, cleaned_path)
    return {"job_id": job_id, "mode": "REAL", "is_synthetic_demo": False}

@app.get("/api/status/{job_id}")
async def get_status(job_id: str):
    if job_id not in JOBS_DB:
        raise HTTPException(status_code=404, detail="Job not found")
        
    job = JOBS_DB[job_id]
    if job["status"] == "completed" and job.get("investigation_id") in REPORTS_DB:
        r_info = REPORTS_DB[job["investigation_id"]]
        job["finding"] = r_info["finding"]
        job["verdict"] = r_info.get("verdict", job.get("verdict"))
        job["risk_score"] = r_info.get("risk_score", job.get("risk_score", 0))
        job["is_synthetic_demo"] = r_info.get("is_synthetic_demo", False)
        
    return job

@app.get("/api/posture")
async def get_posture():
    total_jobs = len(JOBS_DB)
    completed_runs = len(REPORTS_DB)
    latest_inv_id = None
    latest_verdict = None
    total_findings = 0
    if REPORTS_DB:
        latest_inv_id = list(REPORTS_DB.keys())[-1]
        latest_report = REPORTS_DB[latest_inv_id]
        latest_verdict = latest_report.get("verdict") or latest_report.get("finding")
        total_findings = (
            latest_report.get("ppid_count", 0)
            + latest_report.get("rootkit_count", 0)
            + latest_report.get("yara_count", 0)
            + latest_report.get("injected_count", 0)
        )
    return {
        "targets_analyzed": total_jobs,
        "completed_runs": completed_runs,
        "latest_investigation_id": latest_inv_id,
        "latest_verdict": latest_verdict,
        "latest_findings_count": total_findings
    }

def _resolve_investigation_id(target_id: str) -> str:
    """Resolves a job_id (UUID) to its associated investigation_id, or returns target_id."""
    if not target_id:
        return target_id
    if target_id in JOBS_DB:
        inv_id = JOBS_DB[target_id].get("investigation_id")
        if inv_id:
            return inv_id
    for j_id, j_data in JOBS_DB.items():
        if j_data.get("investigation_id") == target_id:
            return target_id
    return target_id

def _resolve_report_files(target_id: str):
    import tempfile
    inv_id = _resolve_investigation_id(target_id)
    td = tempfile.gettempdir()
    dirs_to_check = [td, os.path.abspath("."), os.path.abspath("output")]
    
    candidates_pdf = []
    candidates_html = []
    candidates_json = []
    for d in dirs_to_check:
        candidates_pdf.extend([
            os.path.join(d, f"Report_{inv_id}.pdf"),
            os.path.join(d, f"Report_DEMO_{inv_id}.pdf"),
            os.path.join(d, f"COMPY_{inv_id}_Analysis_Report.pdf"),
            os.path.join(d, f"COMPY_DEMO_{inv_id}_Analysis_Report.pdf"),
        ])
        candidates_html.extend([
            os.path.join(d, f"Report_{inv_id}.html"),
            os.path.join(d, f"Report_DEMO_{inv_id}.html"),
            os.path.join(d, f"COMPY_{inv_id}_Analysis_Report.html"),
            os.path.join(d, f"COMPY_DEMO_{inv_id}_Analysis_Report.html"),
        ])
        candidates_json.extend([
            os.path.join(d, f"Report_{inv_id}.json"),
            os.path.join(d, f"Report_DEMO_{inv_id}.json"),
            os.path.join(d, f"COMPY_{inv_id}_Analysis_Report.json"),
            os.path.join(d, f"COMPY_DEMO_{inv_id}_Analysis_Report.json"),
        ])
        
    pdf_path = next((p for p in candidates_pdf if os.path.exists(p)), None)
    html_path = next((p for p in candidates_html if os.path.exists(p)), None)
    json_path = next((p for p in candidates_json if os.path.exists(p)), None)
    
    is_demo = False
    if inv_id in REPORTS_DB:
        is_demo = REPORTS_DB[inv_id].get("is_synthetic_demo", False)
    elif target_id in JOBS_DB:
        is_demo = JOBS_DB[target_id].get("is_synthetic_demo", False)
    elif any("DEMO_" in p for p in [pdf_path, html_path, json_path] if p):
        is_demo = True
        
    return pdf_path, html_path, json_path, is_demo, inv_id

@app.get("/report/download/pdf/{investigation_id}")
async def download_pdf(investigation_id: str):
    pdf_path, _, _, is_demo, inv_id = _resolve_report_files(investigation_id)
    if not pdf_path or not os.path.exists(pdf_path):
        raise HTTPException(
            status_code=404, 
            detail=f"PDF report artifact not found for investigation ID '{investigation_id}'."
        )
    prefix = "DEMO_" if is_demo else ""
    filename = f"COMPY_{prefix}{inv_id}_Analysis_Report.pdf"
    return FileResponse(
        path=pdf_path, 
        filename=filename,
        media_type='application/pdf',
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

@app.get("/report/download/json/{investigation_id}")
async def download_json(investigation_id: str):
    _, _, json_path, is_demo, inv_id = _resolve_report_files(investigation_id)
    prefix = "DEMO_" if is_demo else ""
    filename = f"COMPY_{prefix}{inv_id}_Analysis_Report.json"
    
    if inv_id in REPORTS_DB and "json_data" in REPORTS_DB[inv_id]:
        return JSONResponse(
            content=REPORTS_DB[inv_id]["json_data"],
            media_type='application/json',
            headers={"Content-Disposition": f'attachment; filename="{filename}"'}
        )
    if json_path and os.path.exists(json_path):
        return FileResponse(
            path=json_path,
            filename=filename,
            media_type='application/json',
            headers={"Content-Disposition": f'attachment; filename="{filename}"'}
        )
    raise HTTPException(
        status_code=404, 
        detail=f"JSON evidence artifact not found for investigation ID '{investigation_id}'."
    )

@app.get("/report/view/html/{investigation_id}", response_class=HTMLResponse)
async def view_report_html(investigation_id: str):
    _, html_path, _, _, _ = _resolve_report_files(investigation_id)
    if not html_path or not os.path.exists(html_path):
        raise HTTPException(
            status_code=404, 
            detail=f"HTML report artifact not found for investigation ID '{investigation_id}'."
        )
    with open(html_path, "r", encoding="utf-8") as f:
        content = f.read()
    return HTMLResponse(content=content, media_type="text/html; charset=utf-8")

@app.get("/report/download/html/{investigation_id}")
async def download_report_html(investigation_id: str):
    _, html_path, _, is_demo, inv_id = _resolve_report_files(investigation_id)
    if not html_path or not os.path.exists(html_path):
        raise HTTPException(
            status_code=404, 
            detail=f"HTML report artifact not found for investigation ID '{investigation_id}'."
        )
    prefix = "DEMO_" if is_demo else ""
    filename = f"COMPY_{prefix}{inv_id}_Analysis_Report.html"
    return FileResponse(
        path=html_path,
        filename=filename,
        media_type="text/html; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

@app.get("/report/sample", response_class=HTMLResponse)
async def view_sample_report():
    sample_html = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(BASE_DIR))), "sample_report.html")
    if not os.path.exists(sample_html):
        sample_html = os.path.abspath("sample_report.html")
    if not os.path.exists(sample_html):
        raise HTTPException(status_code=404, detail="sample_report.html not found on disk")
    with open(sample_html, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


