"""
AI Secure Data Intelligence Platform — Main FastAPI Server
Provides /analyze and /upload endpoints for multi-source data analysis.
"""

import os
import sys
import traceback
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables early
load_dotenv()

from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional, Any

# Ensure backend dir is on path
sys.path.insert(0, str(Path(__file__).parent))

from detection import detect_in_content
from log_analyzer import analyze_log
from risk_engine import evaluate_risk
from policy_engine import apply_policy
from ai_insights import generate_insights
from file_parser import parse_file, detect_input_type


# ─── App Setup ──────────────────────────────────────────────────────

app = FastAPI(
    title="AI Secure Data Intelligence Platform",
    description="AI Gateway + Scanner + Log Analyzer + Risk Engine",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Serve Frontend ─────────────────────────────────────────────────
FRONTEND_DIR = Path(__file__).parent.parent / "frontend"

@app.get("/app")
async def serve_frontend():
    """Serve the frontend HTML."""
    return FileResponse(str(FRONTEND_DIR / "index.html"))

if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


# ─── Request / Response Models ──────────────────────────────────────

class AnalyzeOptions(BaseModel):
    mask: bool = False
    block_high_risk: bool = False
    log_analysis: bool = True

class AnalyzeRequest(BaseModel):
    input_type: str = "text"          # text | file | sql | chat | log
    content: str = ""                 # raw content or base64 for files
    filename: Optional[str] = None    # original filename (for file type)
    options: AnalyzeOptions = AnalyzeOptions()

class PlaybookRequest(BaseModel):
    content: str
    findings: list[dict]
    anomalies: Optional[list[dict]] = None


# ─── Core Analysis Pipeline ────────────────────────────────────────

def run_pipeline(content: str, input_type: str, options: dict) -> dict:
    """
    End-to-end processing pipeline:
    Content → Detection → Log Analysis → Risk → Policy → AI Insights → Response
    """

    content_type = "text"
    anomalies = []
    metadata = None
    sensitive_lines = []

    # ── Step 1: Detection Engine ────────────────────────────────
    findings = detect_in_content(content)

    # ── Step 2: Log Analysis (if applicable) ────────────────────
    if input_type == "log" or options.get("log_analysis", False):
        log_result = analyze_log(content)
        # Merge log-specific findings (avoid duplicates by checking type+line)
        existing_keys = {(f["type"], f.get("line")) for f in findings}
        for lf in log_result["findings"]:
            key = (lf["type"], lf.get("line"))
            if key not in existing_keys:
                findings.append(lf)
                existing_keys.add(key)
        anomalies = log_result.get("anomalies", [])
        metadata = log_result.get("metadata")
        sensitive_lines = log_result.get("sensitive_lines", [])
        content_type = "logs"
    elif input_type == "sql":
        content_type = "sql"
    elif input_type == "chat":
        content_type = "chat"
    elif input_type == "file":
        content_type = "document"

    # ── Step 3: Risk Engine ─────────────────────────────────────
    risk_result = evaluate_risk(findings, anomalies)

    # ── Step 4: Policy Engine ───────────────────────────────────
    policy_result = apply_policy(
        content, findings, risk_result["risk_level"], options
    )

    # ── Step 5: AI Insights ─────────────────────────────────────
    insight_result = generate_insights(
        content, findings, anomalies, use_ai=True
    )

    return {
        "summary": insight_result.get("summary", "Analysis complete."),
        "content_type": content_type,
        "findings": findings,
        "anomalies": anomalies,
        "risk_score": risk_result["risk_score"],
        "risk_level": risk_result["risk_level"],
        "risk_breakdown": risk_result["risk_breakdown"],
        "type_breakdown": risk_result["type_breakdown"],
        "action": policy_result["action"],
        "masked_content": policy_result["content"] if policy_result["action"] == "masked" else None,
        "insights": insight_result.get("insights", []),
        "recommendations": insight_result.get("recommendations", []),
        "metadata": metadata,
        "sensitive_lines": sensitive_lines,
    }


# ─── API Endpoints ─────────────────────────────────────────────────

@app.post("/analyze")
async def analyze(request: AnalyzeRequest):
    """Analyze text, SQL, chat, or log content."""
    try:
        content = request.content
        if not content.strip():
            raise HTTPException(status_code=400, detail="Content cannot be empty")

        options = request.options.model_dump()
        result = run_pipeline(content, request.input_type, options)
        return result
    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@app.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    mask: bool = Form(False),
    block_high_risk: bool = Form(False),
    log_analysis: bool = Form(True),
):
    """Upload and analyze a file (PDF, DOC, DOCX, TXT, LOG)."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    file_bytes = await file.read()
    if len(file_bytes) == 0:
        raise HTTPException(status_code=400, detail="Empty file")

    # Size limit: 10MB
    if len(file_bytes) > 10 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large (max 10MB)")

    # Parse file to extract text
    parsed = parse_file(file.filename, file_bytes)
    content = parsed["content"]
    input_type = detect_input_type(file.filename)

    options = {
        "mask": mask,
        "block_high_risk": block_high_risk,
        "log_analysis": log_analysis or input_type == "log",
    }

    result = run_pipeline(content, input_type, options)
    result["filename"] = file.filename
    result["file_size"] = parsed["size"]
    return result


@app.post("/playbook")
async def get_playbook(request: PlaybookRequest):
    """Generate a detailed security remediation playbook using AI."""
    try:
        from ai_insights import generate_remediation_playbook
        playbook = generate_remediation_playbook(
            request.content, request.findings, request.anomalies
        )
        return {"playbook": playbook}
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Playbook generation failed: {str(e)}")


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy", "service": "AI Secure Data Intelligence Platform"}


@app.get("/")
async def root():
    """Root endpoint with API info."""
    return {
        "name": "AI Secure Data Intelligence Platform",
        "version": "1.0.0",
        "endpoints": {
            "POST /analyze": "Analyze text, SQL, chat, or log content",
            "POST /upload": "Upload and analyze files (PDF, DOC, TXT, LOG)",
            "GET /health": "Health check",
        },
    }
