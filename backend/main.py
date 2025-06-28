import uuid
import hashlib
import json
import asyncio
from contextlib import asynccontextmanager
from typing import Dict, Any
import io
import re
from html import escape

from fastapi import (
    FastAPI,
    UploadFile,
    File,
    HTTPException,
    Security,
    BackgroundTasks,
    Request,
)
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.colors import navy, black, blue


# --- Custom App Modules ---
from app.security import get_api_key
from app.analysis import initialize_rag_pipeline, analyze_log_data
from app.scanner import scan_website_headers, get_ai_header_analysis

# --- PDF GENERATION LOGIC ---
def create_report_pdf(markdown_content: str) -> bytes:
    """
    Converts a markdown string into a styled PDF document. This function is now
    part of main.py to bypass Docker caching issues with separate files.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=18)
    
    styles = getSampleStyleSheet()
    h1_style = ParagraphStyle(name='H1_Custom', parent=styles['h1'], fontSize=18, leading=22, spaceAfter=20, textColor=navy)
    h2_style = ParagraphStyle(name='H2_Custom', parent=styles['h2'], fontSize=14, leading=18, spaceAfter=15, textColor=navy)
    bullet_style = ParagraphStyle(name='Bullet_Custom', parent=styles['Bullet'], firstLineIndent=0, spaceBefore=2, leftIndent=18, bulletIndent=6)
    normal_style = styles['Normal']

    story = []
    
    def sanitize_and_format_line(line_text):
        """A robust function to convert a line of markdown into safe, parsable HTML."""
        line_text = escape(line_text)
        line_text = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', line_text)
        line_text = re.sub(r'(https?://[^\s`]+)', r'<a href="\1"><font color="blue">\1</font></a>', line_text)
        return line_text

    for line in markdown_content.split('\n'):
        formatted_line = sanitize_and_format_line(line.strip())
        if line.strip().startswith('### '): story.append(Paragraph(formatted_line.replace('### ', '', 1), h2_style))
        elif line.strip().startswith('## '): story.append(Paragraph(formatted_line.replace('## ', '', 1), h2_style))
        elif line.strip().startswith('# '): story.append(Paragraph(formatted_line.replace('# ', '', 1), h1_style))
        elif line.strip().startswith('* '): story.append(Paragraph(formatted_line.replace('* ', '', 1), bullet_style))
        elif line.strip() == '---': story.append(HRFlowable(width="100%", thickness=1, color=black, spaceBefore=12, spaceAfter=12))
        elif line.strip(): story.append(Paragraph(formatted_line, normal_style))
        else: story.append(Spacer(1, 12))
            
    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes

# --- Application Lifecycle ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manages the application's startup and shutdown events."""
    print("🚀 Application startup: Initializing RAG pipeline...")
    llm_instance, rag_chain_instance, error_message = initialize_rag_pipeline()
    app.state.llm = llm_instance
    app.state.rag_chain = rag_chain_instance
    app.state.startup_error = error_message
    print("✅ RAG pipeline initialization process complete.")
    yield
    print("👋 Application shutdown.")

# --- FastAPI App Initialization ---
app = FastAPI(
    title="Nginx AI Security Suite",
    description="Provides AI-powered log analysis and website security scanning.",
    lifespan=lifespan,
)

# --- Pydantic Models for Request Validation ---
class ScanRequest(BaseModel):
    url: str

class ReportRequest(BaseModel):
    markdown_content: str

# --- In-memory Data Stores & Background Task ---
jobs: Dict[str, Dict] = {}
analysis_cache: Dict[str, Dict] = {}

def run_analysis_in_background(job_id: str, content_hash: str, log_content: str, rag_chain: object):
    """Background task to run the slow AI analysis for logs."""
    analysis_result = analyze_log_data(log_content, rag_chain)
    analysis_cache[content_hash] = analysis_result
    jobs[job_id] = {"status": "complete", "result": analysis_result}

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
    api_key: str = Security(get_api_key)
):
    """Handles log file uploads and starts a background analysis task."""
    rag_chain = request.app.state.rag_chain
    if not rag_chain:
        raise HTTPException(status_code=503, detail="Analysis service is not available due to startup error.")
    
    log_content_bytes = await file.read()
    content_hash = hashlib.sha256(log_content_bytes).hexdigest()
    job_id = str(uuid.uuid4())
    
    if content_hash in analysis_cache:
        jobs[job_id] = {"status": "complete", "result": analysis_cache[content_hash]}
    else:
        jobs[job_id] = {"status": "processing", "result": None}
        log_content_str = log_content_bytes.decode("utf-8", errors="ignore")
        background_tasks.add_task(run_analysis_in_background, job_id, content_hash, log_content_str, rag_chain)
        
    return {"message": "Analysis request received.", "job_id": job_id}

@app.get("/stream-results/{job_id}")
async def stream_log_analysis_results(
    request: Request, job_id: str, api_key: str = Security(get_api_key)
):
    """Streams the status of a log analysis job using Server-Sent Events (SSE)."""
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job ID not found.")
        
    async def event_generator():
        while True:
            if await request.is_disconnected():
                break
            job_status = jobs[job_id]["status"]
            if job_status != "processing":
                yield {"event": "end", "data": json.dumps(jobs[job_id])}
                break
            else:
                yield {"event": "update", "data": json.dumps({"status": "processing"})}
                await asyncio.sleep(2)
                
    return EventSourceResponse(event_generator())

@app.post("/scan-website-headers")
async def start_website_scan(
    req: ScanRequest, request: Request, api_key: str = Security(get_api_key)
):
    """Orchestrates the website header scan and returns a complete report."""
    llm_instance = request.app.state.llm
    if not llm_instance:
        raise HTTPException(status_code=503, detail="AI service is not available due to startup error.")
        
    scan_report = scan_website_headers(req.url)
    if "error" in scan_report:
        raise HTTPException(status_code=400, detail=f"Failed to scan the specified URL. Reason: {scan_report['error']}")
        
    ai_report = get_ai_header_analysis(
        llm=llm_instance,
        scan_results=scan_report.get("scan_results", []),
        target_url=req.url
    )
    
    return {
        "scan_findings": scan_report.get("scan_results", []),
        "ai_explanation": ai_report.get("ai_explanation"),
    }

@app.post("/download-report")
async def download_pdf_report(req: ReportRequest, api_key: str = Security(get_api_key)):
    """Accepts markdown content and returns a generated PDF report."""
    try:
        pdf_bytes = create_report_pdf(req.markdown_content)
        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=SecurityReport.pdf"}
        )
    except Exception as e:
        print(f"Error during PDF generation: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to generate PDF report: {e}")