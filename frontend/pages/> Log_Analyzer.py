import streamlit as st
import requests
import os
import json
from sseclient import SSEClient

# --- PAGE CONFIGURATION & STATE ---
st.set_page_config(page_title="Log Analyzer", page_icon="📄", layout="wide")

def init_log_analyzer_state():
    """Initializes session state variables specific to this page."""
    st.session_state.setdefault('log_job_id', None)
    st.session_state.setdefault('log_analysis_complete', False)
    st.session_state.setdefault('log_analysis_result', None)
init_log_analyzer_state()

# --- BACKEND API CONFIGURATION ---
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")
API_KEY = os.getenv("BACKEND_API_KEY")
HEADERS = {"X-API-Key": API_KEY} if API_KEY else None

# --- UI & LOGIC ---
st.title("📄 AI-Powered Nginx Log Analyzer")
st.caption("Upload an Nginx access log. The system will use a RAG pipeline with Gemini to identify potential threats and provide a detailed report.")

if not HEADERS:
    st.error("FATAL ERROR: The frontend is missing the BACKEND_API_KEY environment variable.")
    st.stop()

uploaded_file = st.file_uploader(
    "Upload Nginx `access.log`",
    type=['log'],
    key="log_file_uploader" # A stable key for the uploader
)

col1, col2 = st.columns([1, 4])
with col1:
    analyze_button = st.button("Analyze Log", type="primary", use_container_width=True, disabled=(not uploaded_file))
with col2:
    if st.button("Clear & Reset", use_container_width=True):
        # Clear all session state keys to reset the page
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.rerun()

# --- SSE LISTENER ---
if analyze_button and uploaded_file:
    # Clear previous run state
    for key in list(st.session_state.keys()):
        if key.startswith('log_'):
             del st.session_state[key]
    init_log_analyzer_state()

    with st.status("🚀 Contacting server...", expanded=True) as status:
        try:
            status.update(label="Sending log file...", state="running")
            files = {'file': (uploaded_file.name, uploaded_file.getvalue(), uploaded_file.type)}
            response = requests.post(f"{BACKEND_URL}/analyze/", files=files, headers=HEADERS, timeout=90)
            response.raise_for_status()
            job_id = response.json().get("job_id")
            st.session_state['log_job_id'] = job_id
            
            status.update(label=f"✅ Job started! Listening for real-time results...", state="running")
            
            # Connect to the SSE stream
            stream_response = requests.get(f"{BACKEND_URL}/stream-results/{job_id}", headers=HEADERS, stream=True)
            client = SSEClient(stream_response)

            for event in client.events():
                if event.event == 'end':
                    result_data = json.loads(event.data)
                    st.session_state['log_analysis_complete'] = True
                    st.session_state['log_analysis_result'] = result_data
                    status.update(label="Analysis Complete!", state="complete", expanded=False)
                    st.rerun()
                    break
                elif event.event == 'update':
                    status.update(label="🧠 AI analysis in progress...", state="running")

        except requests.exceptions.RequestException as e:
            status.update(label="Connection Error!", state="error", expanded=True)
            st.error(f"Connection to backend failed: {e}")

# --- Display Logic ---
if st.session_state.get('log_analysis_complete'):
    st.header("📊 Log Analysis Report")
    result_content = st.session_state.get('log_analysis_result', {}).get("result", {})
    summary = result_content.get("summary", "No summary available.")
    details = result_content.get("details", {})

    # PDF Download Button Logic
    if summary and "No summary" not in summary:
        try:
            pdf_payload = {"markdown_content": summary}
            pdf_response = requests.post(
                f"{BACKEND_URL}/download-report",
                headers=HEADERS,
                json=pdf_payload
            )
            if pdf_response.status_code == 200:
                st.download_button(
                    label="⬇️ Download Report as PDF",
                    data=pdf_response.content,
                    file_name="LogAnalysisReport.pdf",
                    mime="application/pdf",
                    use_container_width=True
                )
            else:
                st.warning("Could not generate PDF report at this time.")
        except Exception as e:
            st.error(f"Failed to create PDF download link: {e}")

    # Display the report in the app
    with st.container(border=True):
        st.markdown(summary)
    
    with st.expander("Show AI Query & Retrieved Knowledge Sources"):
        st.json(details)

elif st.session_state.get('log_analysis_result') and st.session_state.get('log_analysis_result', {}).get('status') == 'failed':
    st.error("The analysis job failed on the backend.")
    st.json(st.session_state.get('log_analysis_result', {}).get('result'))