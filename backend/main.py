import uuid
import hashlib
import json
import asyncio
from contextlib import asynccontextmanager
from typing import Dict, Any, List, Optional
import io
import re
from html import escape
import time
from multiprocessing import Process, Queue, get_context
from datetime import datetime, timezone
from pathlib import Path
from fastapi import (
    FastAPI, UploadFile, File, HTTPException, Security, BackgroundTasks, Request, Form
)
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, HttpUrl
from sse_starlette.sse import EventSourceResponse
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, HRFlowable, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.colors import navy, black, blue, lightgrey, grey,  white, HexColor
from reportlab.lib.units import inch

from app.security import get_api_key
from app.analysis import initialize_rag_pipeline, analyze_log_data
from app.scanner import scan_website_headers, get_ai_header_analysis

JOBS_DIR = Path("file_queue/jobs")
RESULTS_DIR = Path("file_queue/results")
ARCHIVE_DIR = Path("file_queue/archive") # Consolidated archive directory
JOBS_DIR.mkdir(parents=True, exist_ok=True)
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)

# --- PDF GENERATION FOR LOG ANALYZER AND WEBSITE HEADER ANALYZER---
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

# --- PDF Generator for Scraper Reports ---
def create_scraper_report_pdf(title: str, timestamp: str, markdown_content: str, scrape_data: List[Dict]) -> bytes:
    """
    Generates a detailed PDF report including a comprehensive table of raw scraped data.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, rightMargin=0.5*inch, leftMargin=0.5*inch, topMargin=0.5*inch, bottomMargin=0.5*inch)
    
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(name='Title_Custom', parent=styles['h1'], fontSize=18, alignment=1, spaceAfter=6, textColor=navy)
    timestamp_style = ParagraphStyle(name='Timestamp_Custom', parent=styles['Normal'], alignment=1, spaceBefore=6, spaceAfter=20, textColor=grey)
    h1_style = ParagraphStyle(name='H1_Custom', parent=styles['h1'], fontSize=16, leading=20, spaceAfter=15, textColor=navy)
    normal_style = styles['Normal']
    table_cell_style = ParagraphStyle(name='TableCell', parent=normal_style, wordWrap='CJK', leading=12, fontSize=9)
    table_header_style = ParagraphStyle(name='TableHeader', parent=table_cell_style, fontName='Helvetica-Bold')


    story = []
    story.append(Paragraph(title, title_style))
    story.append(Paragraph(timestamp, timestamp_style))

    # Add AI analysis markdown content to the story
    for line in markdown_content.split('\n'):
        line = line.strip()
        if line.startswith('## '):
            story.append(Spacer(1, 12))
            story.append(Paragraph(line.replace('## ', ''), h1_style))
        elif line:
            line = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', line)
            story.append(Paragraph(line, normal_style))
        else:
            story.append(Spacer(1, 12))
            
    # Add the detailed Raw Scraped Data table
    if scrape_data:
        story.append(Spacer(1, 24))
        story.append(Paragraph("Raw Scraped Data", h1_style))
        story.append(Spacer(1, 12))

        header = [
            Paragraph("URL", table_header_style),
            Paragraph("Page Title", table_header_style),
            Paragraph("Links", table_header_style),
            Paragraph("Forms Found (Details)", table_header_style)
        ]
        
        table_data = [header]
        for item in scrape_data:
            # Create a detailed, multi-line string for all forms found on the page
            forms_details = []
            for form in item.get('forms_found', []):
                method = form.get('method', 'get').upper()
                action = escape(form.get('action', 'N/A'))
                interaction = escape(form.get('interaction_result', ''))
                
                inputs_list = []
                for i in form.get('inputs', []):
                    tag = escape(i.get('tag', 'input'))
                    itype = escape(i.get('type', 'N/A'))
                    name = escape(i.get('name', 'N/A'))
                    inputs_list.append(f"&nbsp;- {tag} (type: {itype}, name: {name})")
                
                inputs_str = "<br/>".join(inputs_list)
                form_detail_str = (
                    f"<b>Action:</b> {action}<br/>"
                    f"<b>Method:</b> {method}<br/>"
                    f"<b>Interaction:</b> {interaction}<br/>"
                    f"<b>Inputs:</b><br/>{inputs_str if inputs_str else '<i>None found</i>'}"
                )
                forms_details.append(form_detail_str)
            
            # Join multiple forms with a horizontal rule for readability
            forms_paragraph_content = "<br/><hr color='grey' width='50%'/><br/>".join(forms_details)

            row = [
                Paragraph(item.get('url', 'N/A'), table_cell_style),
                Paragraph(escape(item.get('page_title', 'N/A')), table_cell_style),
                Paragraph(str(item.get('links_found', 0)), table_cell_style),
                Paragraph(forms_paragraph_content if forms_paragraph_content else "None", table_cell_style)
            ]
            table_data.append(row)

        table = Table(table_data, colWidths=[1.8*inch, 1.5*inch, 0.5*inch, 3.7*inch])
        
        style = TableStyle([
            ('BACKGROUND', (0,0), (-1,0), lightgrey),
            ('TEXTCOLOR',(0,0),(-1,0), white),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0,0), (-1,0), 10),
            ('TOPPADDING', (0,0), (-1,0), 10),
            ('BACKGROUND', (0,1), (-1,-1), white),
            ('GRID', (0,0), (-1,-1), 1, lightgrey),
            ('BOX', (0,0), (-1,-1), 2, black),
        ])
        table.setStyle(style)
        story.append(table)

    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes

# --- Application Lifecycle ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Menginisialisasi semua komponen AI saat server FastAPI dimulai.
    """
    print("🚀 App startup: Initializing AI pipelines...")
    llm, rag_chain, startup_error = initialize_rag_pipeline()
    app.state.llm = llm
    app.state.rag_chain = rag_chain
    app.state.startup_error = startup_error
    if startup_error:
        print(f"🚨 CRITICAL STARTUP ERROR: {startup_error}")
    else:
        print("✅ App startup complete. AI models loaded.")
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

class InteractiveScraperRequest(BaseModel):
    start_url: HttpUrl # Use Pydantic's built-in URL validation
    domain: str
    max_pages: int
    user_agent: str
    
class ScraperReportRequest(BaseModel):
    job_id: str
    markdown_content: str
    raw_scrape_results: List[Dict]
    domain: str

# --- In-memory Data Stores ---
jobs: Dict[str, Dict] = {}
analysis_jobs: Dict[str, Dict] = {}
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
def get_analysis_job_results(job_id: str):
    if job_id not in analysis_jobs:
        raise HTTPException(status_code=404, detail="Analysis job ID not found.")
    return analysis_jobs[job_id]

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

@app.get("/result-scraper/{job_id}")
def get_scraper_job_results(job_id: str):
    results_file = RESULTS_DIR / f"{job_id}.json"
    if not results_file.exists():
        raise HTTPException(status_code=404, detail="Job ID not found.")
    
    with open(results_file, 'r') as f:
        return json.load(f)

@app.post("/interactive-scrape", status_code=202)
def start_interactive_scrape(req: InteractiveScraperRequest):
    job_id = str(uuid.uuid4())
    # Convert HttpUrl back to a string for JSON serialization
    job_data = req.model_dump()
    job_data['job_id'] = job_id
    job_data['start_url'] = str(req.start_url)
    job_data['domain_to_check'] = req.domain
    job_file = JOBS_DIR / f"{job_id}.json"
    with open(job_file, 'w') as f:
        json.dump(job_data, f)
    
    results_file = RESULTS_DIR / f"{job_id}.json"
    with open(results_file, 'w') as f:
        json.dump({"status": "queued", "message": "Job is in the queue..."}, f)
    return {"job_id": job_id}


@app.post("/cancel-scrape/{job_id}", status_code=200)
def cancel_interactive_scrape(job_id: str, api_key: str = Security(get_api_key)):
    """
    Cancels a running or queued scraper job by deleting its job file.
    """
    job_file = JOBS_DIR / f"{job_id}.json"
    result_file = RESULTS_DIR / f"{job_id}.json"
    
    if not job_file.is_file():
        # This can happen if the job finished just before cancellation was requested
        raise HTTPException(status_code=404, detail="Job not found in queue. It may have already completed.")

    try:
        job_file.unlink()
        print(f"CANCELLED [Job: {job_id}]: Removed job from queue.")
        
        # Also clean up the result file if it exists to prevent it from being orphaned
        if result_file.is_file():
            try:
                result_file.unlink()
                print(f"CANCELLED [Job: {job_id}]: Removed partial result file.")
            except OSError as e:
                # Log this but don't fail the whole request
                print(f"CANCEL WARNING [Job: {job_id}]: Could not remove result file. Error: {e}")

        return {"message": "Job cancellation request processed successfully."}
    except OSError as e:
        print(f"CANCEL ERROR [Job: {job_id}]: Could not remove job file. Error: {e}")
        raise HTTPException(status_code=500, detail=f"Error removing job file: {e}")

def archive_scraper_result(job_id: str):
    """
    Moves a completed scraper result file to the consolidated archive directory.
    This is run in the background after a user downloads the PDF report.
    """
    try:
        results_file = RESULTS_DIR / f"{job_id}.json"
        if results_file.exists():
            # Rename to avoid collision with the archived job file.
            archive_path = ARCHIVE_DIR / f"{job_id}.result.json"
            results_file.rename(archive_path)
            print(f"ARCHIVE [Job: {job_id}]: Successfully archived result file to {archive_path}")
    except Exception as e:
        print(f"ARCHIVE ERROR [Job: {job_id}]: Failed to archive result file. Error: {e}")

@app.post("/download-interactive-report")
async def download_interactive_pdf_report(req: ScraperReportRequest, background_tasks: BackgroundTasks, api_key: str = Security(get_api_key)):
    """
    Generates a PDF for the Web Scraper analysis, now including the raw data table.
    It also triggers a background task to archive the result file.
    """
    try:
        title = f"Web Scraper Analysis: {req.domain}"
        timestamp = f"_{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}_"
        
        pdf_bytes = create_scraper_report_pdf(
            title=title,
            timestamp=timestamp,
            markdown_content=req.markdown_content,
            scrape_data=req.raw_scrape_results # Pass the raw data to the generator
        )

        # After successfully generating the PDF, archive the source result file
        background_tasks.add_task(archive_scraper_result, req.job_id)

        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=InteractiveWebScraperReport.pdf"}
        )
    except Exception as e:
        print(f"Error during Scraper PDF generation: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate PDF report.")
