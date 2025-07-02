import uuid
import hashlib
import json
import asyncio
from contextlib import asynccontextmanager
from typing import Dict, List, Optional
import io
import re
from html import escape
import time
from datetime import datetime, timezone

from fastapi import (
    FastAPI, UploadFile, File, HTTPException, Security, BackgroundTasks, Request, Form
)
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sse_starlette.sse import EventSourceResponse
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.colors import navy, lightgrey, HexColor
from reportlab.lib.units import inch

from app.security import get_api_key
from app.analysis import initialize_rag_pipeline, analyze_log_data
from app.scanner import scan_website_headers, get_ai_header_analysis

# --- PDF GENERATION LOGIC ---
def create_report_pdf(title: str, timestamp: str, markdown_content: str, threat_summary: Optional[str] = None, findings_data: Optional[List[Dict]] = None) -> bytes:
    """
    Converts all report components into a single, styled PDF document.
    This version intelligently formats all markdown elements, including code blocks.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, rightMargin=0.7*inch, leftMargin=0.7*inch, topMargin=0.7*inch, bottomMargin=0.7*inch)
    
    # --- YOUR STYLES (UNCHANGED) ---
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(name='Title_Custom', parent=styles['h1'], fontSize=18, leading=22, spaceAfter=6, textColor=navy)
    timestamp_style = ParagraphStyle(name='Timestamp_Custom', parent=styles['Italic'], alignment=0, spaceBefore=6, spaceAfter=20)
    h1_style = ParagraphStyle(name='H1_Custom', parent=styles['h1'], fontSize=18, leading=22, spaceAfter=20, textColor=navy)
    h2_style = ParagraphStyle(name='H2_Custom', parent=styles['h2'], fontSize=14, leading=18, spaceAfter=15, textColor=navy)
    bullet_style = ParagraphStyle(name='Bullet_Custom', parent=styles['Bullet'], firstLineIndent=0, spaceBefore=2, leftIndent=18, bulletIndent=6)
    normal_style = styles['Normal']
    # --- END OF YOUR STYLES ---

    # --- NEW STYLE ADDED for Code Blocks ---
    code_style = ParagraphStyle(
        name='Code',
        parent=normal_style,
        fontName='Courier',
        fontSize=8,
        leading=12,
        leftIndent=18,
        rightIndent=18,
        spaceBefore=6,
        spaceAfter=12,
        borderPadding=8,
        backColor=HexColor("#F5F5F5"),
        borderColor=lightgrey,
        borderWidth=1,
    )

    story = []
    story.append(Paragraph(title, title_style))
    story.append(Paragraph(timestamp, timestamp_style))

    if threat_summary:
        story.append(Paragraph("Threat Summary:", h1_style))
        for line in threat_summary.split('\n'):
            if line.strip(): story.append(Paragraph(escape(line), bullet_style))
        story.append(Spacer(1, 24))

    # --- RE-ENGINEERED MARKDOWN PARSING LOOP ---
    in_code_block = False
    code_block_text = ""

    for line in markdown_content.split('\n'):
        # Handle code block logic
        if line.strip().startswith('```'):
            if in_code_block:
                # End of a code block, add the paragraph to the story
                story.append(Paragraph(code_block_text.replace('\n', '<br/>\n'), code_style))
                in_code_block = False
                code_block_text = ""
            else:
                # Start of a code block
                in_code_block = True
            continue # Skip the ``` line itself

        if in_code_block:
            code_block_text += escape(line) + "\n"
            continue

        # Handle other markdown elements
        line_stripped = line.strip()
        main_heading_match = re.match(r'^##\s*(.*)', line_stripped)
        
        if main_heading_match:
            story.append(Paragraph(escape(main_heading_match.group(1)), h1_style))
        elif line_stripped:
            line_formatted = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', line_stripped)
            story.append(Paragraph(line_formatted, normal_style))
        else:
            story.append(Spacer(1, 12))
    # --- END OF RE-ENGINEERED LOOP ---
            
    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes

# --- Application Lifecycle ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("🚀 App startup...")
    llm, chain, err = initialize_rag_pipeline()
    app.state.llm, app.state.rag_chain, app.state.startup_error = llm, chain, err
    print("✅ App startup complete.")
    yield

# --- FastAPI App Initialization ---
app = FastAPI(title="AI Security Suite Backend", lifespan=lifespan)

# --- Pydantic Models ---
class ScanRequest(BaseModel): url: str
class Finding(BaseModel):
    Line: int; Threat: str; Log_Entry: str = Field(..., alias="Log Entry")
class ReportRequest(BaseModel):
    markdown_content: str
    log_type: str
    threat_summary: Optional[str] = None
    detailed_findings: Optional[List[Finding]] = None

# --- In-memory Data Stores ---
jobs: Dict[str, Dict] = {}
analysis_cache: Dict[str, Dict] = {}

# --- Background Task ---
def run_analysis_in_background(job_id: str, content_hash: str, log_content: str, rag_chain: object, log_type: str):
    """
    Background task now correctly accepts and uses the 'log_type'.
    """
    try:
        jobs[job_id]["step"] = f"Stage 1 of 2: Scanning {log_type.capitalize()} log..."
        
        # Pass the log_type to the core analysis function
        analysis_result = analyze_log_data(log_content, rag_chain, log_type)

        jobs[job_id]["step"] = "Stage 2 of 2: Generating AI report..."
        time.sleep(2)
        
        analysis_cache[content_hash] = analysis_result
        jobs[job_id] = {"status": "complete", "result": analysis_result}
        print(f"BACKGROUND TASK [Job: {job_id}]: Finished.")

    except Exception as e:
        jobs[job_id] = {"status": "failed", "result": {"error": str(e)}}
        print(f"BACKGROUND TASK [Job: {job_id}]: Failed with error: {e}")

# --- API Endpoints ---
@app.get("/")
def health_check(request: Request, api_key: str = Security(get_api_key)):
    """Health check endpoint to verify that the AI pipeline is initialized."""
    if request.app.state.rag_chain:
        return {"status": "ok", "message": "AI services are running correctly."}
    else:
        return {"status": "error", "message": f"CRITICAL: AI Pipeline failed to initialize. Reason: {request.app.state.startup_error}"}

@app.post("/analyze/", status_code=202)
async def start_log_analysis(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    log_type: str = Form("nginx"),
    api_key: str = Security(get_api_key),
):
    """Handles log file uploads and starts a background analysis task."""
    rag_chain = request.app.state.rag_chain
    if not rag_chain: raise HTTPException(503, "Analysis service unavailable.")
    
    log_content_bytes = await file.read()
    content_hash = hashlib.sha256(log_content_bytes).hexdigest()
    job_id = str(uuid.uuid4())
    
    jobs[job_id] = {"status": "processing", "step": "Starting analysis...", "result": None}

    cache_key = f"{content_hash}_{log_type}"
    if cache_key in analysis_cache:
        jobs[job_id] = {"status": "complete", "result": analysis_cache[cache_key]}
    else:
        log_content_str = log_content_bytes.decode("utf-8", errors="ignore")
        background_tasks.add_task(
            run_analysis_in_background, job_id, cache_key, log_content_str, rag_chain, log_type
        )
    return {"message": "Analysis request received.", "job_id": job_id}

@app.get("/stream-results/{job_id}")
async def stream_results(request: Request, job_id: str, api_key: str = Security(get_api_key)):
    """Streams job status using Server-Sent Events (SSE)."""
    if job_id not in jobs: raise HTTPException(404, "Job not found.")
    async def event_generator():
        while True:
            if await request.is_disconnected(): break
            job_info = jobs.get(job_id, {})
            if job_info.get("status") != "processing":
                yield {"event": "end", "data": json.dumps(job_info)}; break
            else:
                yield {"event": "update", "data": json.dumps(job_info)}; await asyncio.sleep(2)
    return EventSourceResponse(event_generator())
    
@app.get("/results/{job_id}")
def get_job_results(job_id: str, api_key: str = Security(get_api_key)):
    """A simple RESTful endpoint for polling the status of a job (for n8n)."""
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job ID not found.")
    return jobs[job_id]

@app.post("/scan-website-headers")
async def scan_headers(req: ScanRequest, request: Request, api_key: str = Security(get_api_key)):
    """Orchestrates the website header scan and returns a complete report."""
    llm = request.app.state.llm
    if not llm: raise HTTPException(503, "AI service unavailable.")
    report = scan_website_headers(req.url)
    if "error" in report: raise HTTPException(400, f"Scan failed: {report['error']}")
    ai_report = get_ai_header_analysis(llm, report.get("scan_results", []), req.url)
    return {"scan_findings": report.get("scan_results", []), "ai_explanation": ai_report.get("ai_explanation")}

@app.post("/download-report")
async def download_pdf_report(req: ReportRequest, api_key: str = Security(get_api_key)):
    try:
        title = f"Security Report: {req.log_type.capitalize()} Log"
        timestamp = f"_{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}_"
        
        pdf_bytes = create_report_pdf(
            title=title,
            timestamp=timestamp,
            threat_summary=req.threat_summary,
            markdown_content=req.markdown_content,
        )
        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={req.log_type}_report.pdf"}
        )
    except Exception as e:
        print(f"Error during PDF generation: {e}")
        raise HTTPException(500, detail=f"Failed to generate PDF report: {e}")