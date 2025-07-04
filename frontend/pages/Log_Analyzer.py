import streamlit as st
import requests
import os
import json
from sseclient import SSEClient
import pandas as pd # It's good practice to import pandas for the dataframe later

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
st.title("📄 AI-Powered Log Analyzer")
st.caption("Upload an Nginx or Apache access log. The system will use a hybrid Regex+AI pipeline to identify potential threats and provide a detailed report.")

if not HEADERS:
    st.error("FATAL ERROR: The frontend is missing the BACKEND_API_KEY environment variable.")
    st.stop()

# --- NEW: Log Type Selector Added Here ---
log_type = st.selectbox(
    "1. Select Log Format",
    ("Nginx", "Apache"),
    key="log_type_selector"
)

# --- Uploader label is now dynamic ---
uploaded_file = st.file_uploader(
    f"2. Upload your {log_type} `access.log` file",
    type=['log', 'txt'],
    key="log_file_uploader" 
)

col1, col2 = st.columns([1, 4])
with col1:
    analyze_button = st.button("3. Analyze Log File", type="primary", use_container_width=True, disabled=(not uploaded_file or st.session_state.log_job_id is not None))
with col2:
    if st.button("Clear & Reset", use_container_width=True):
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.rerun()

# --- SSE LISTENER (Updated to send log_type) ---
if analyze_button and uploaded_file:
    for key in list(st.session_state.keys()):
        if key.startswith('log_'):
             del st.session_state[key]
    init_log_analyzer_state()

    with st.status("🚀 Contacting server...", expanded=True) as status:
        try:
            status.update(label="Sending log file to backend...", state="running")
            
            # --- API call now sends the selected log_type ---
            files = {'file': (uploaded_file.name, uploaded_file.getvalue(), uploaded_file.type)}
            data = {'log_type': log_type.lower()} # e.g., 'nginx' or 'apache'
            
            response = requests.post(f"{BACKEND_URL}/analyze/", files=files, data=data, headers=HEADERS, timeout=90)
            # --- End of change ---

            response.raise_for_status()
            job_id = response.json().get("job_id")
            st.session_state['log_job_id'] = job_id
            
            status.update(label=f"✅ Job started! Listening for real-time results...", state="running")
            
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
                    update_data = json.loads(event.data)
                    step_message = update_data.get("step", "🧠 AI analysis in progress...")
                    status.update(label=f"⏳ {step_message}", state="running")

        except requests.exceptions.HTTPError as e:
            status.update(label="Analysis Failed!", state="error", expanded=True)
            st.error(f"Error from backend: {e.response.json().get('detail', str(e))}")
        except requests.exceptions.RequestException as e:
            status.update(label="Connection Error!", state="error", expanded=True)
            st.error(f"Connection to backend failed: {e}")

# --- Display Logic (Unchanged, but now includes a check for detailed_findings in PDF payload) ---
if st.session_state.get('log_analysis_complete'):
    st.header("📊 Log Analysis Report")
    result_content = st.session_state.get('log_analysis_result', {}).get("result", {})
    summary = result_content.get("summary", "No summary available.")
    detailed_findings = result_content.get("detailed_findings", []) # This key comes from your latest backend

    # Recreate the Threat Summary for the PDF
    from collections import Counter
    threat_counts = Counter(finding["Threat"] for finding in detailed_findings)
    threat_summary_for_pdf = "\n".join([f"- Found '{threat}' pattern {count} times." for threat, count in sorted(threat_counts.items())])

    # PDF Download Button Logic
    if summary and "No summary" not in summary:
        try:
            # Recreate the Threat Summary string on the frontend
            threat_counts = Counter(finding["Threat"] for finding in detailed_findings)
            threat_summary_for_pdf = "\n".join([f"- Found '{threat}' pattern {count} times." for threat, count in sorted(threat_counts.items())])

            # The payload now correctly includes all necessary fields
            pdf_payload = {
                "log_type": "log_analyzer",
                "markdown_content": summary,
                "threat_summary": threat_summary_for_pdf,
                "detailed_findings": detailed_findings
            }
            pdf_response = requests.post(f"{BACKEND_URL}/download-report", headers=HEADERS, json=pdf_payload)
            if pdf_response.status_code == 200:
                st.download_button(
                    label="⬇️ Download Full Report as PDF",
                    data=pdf_response.content,
                    file_name="LogAnalysisFullReport.pdf",
                    mime="application/pdf",
                    use_container_width=True
                )
        except Exception as e:
            st.error(f"Failed to create PDF download link: {e}")

    # Display the report in the app
    with st.container(border=True):
        st.markdown(summary)
    
    # Updated expander to show detailed findings table
    with st.expander("Show Detailed Threat Findings (Evidence)"):
        if detailed_findings:
            df = pd.DataFrame(detailed_findings)
            st.dataframe(df, use_container_width=True, hide_index=True)
        else:
            st.info("No specific threat lines were identified by the regex scan.")

elif st.session_state.get('log_analysis_result') and st.session_state.get('log_analysis_result', {}).get('status') == 'failed':
    st.error("The analysis job failed on the backend.")
    st.json(st.session_state.get('log_analysis_result', {}).get('result'))