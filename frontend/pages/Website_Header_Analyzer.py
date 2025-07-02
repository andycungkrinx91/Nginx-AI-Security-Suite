import streamlit as st
import requests
import os

# --- PAGE CONFIGURATION & STATE ---
st.set_page_config(page_title="Header Analyzer", page_icon="🌐", layout="wide")

# Initializes session state variables specific to this page
def init_header_analyzer_state():
    st.session_state.setdefault('header_scan_result', None)
    st.session_state.setdefault('header_url_input', "")

init_header_analyzer_state()

# --- BACKEND API CONFIGURATION ---
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")
API_KEY = os.getenv("BACKEND_API_KEY")
HEADERS = {"X-API-Key": API_KEY} if API_KEY else None

# --- UI & LOGIC ---
st.title("🌐 AI-Powered Website Header Analyzer")
st.caption("This tool performs a passive scan and uses Gemini to generate a detailed report with remediation advice.")

if not HEADERS:
    st.error("FATAL ERROR: The frontend is missing the BACKEND_API_KEY environment variable.")
    st.stop()

st.text_input(
    "Enter a website URL to scan (e.g., example.com)",
    key='header_url_input',
    help="You must have permission to scan this website."
)

col1, col2 = st.columns([1, 4])
with col1:
    scan_button = st.button(
        "Analyze with AI",
        type="primary",
        use_container_width=True,
        disabled=(not st.session_state.header_url_input)
    )
with col2:
    if st.button("Clear & Reset", use_container_width=True):
        st.session_state.header_url_input = ""
        st.session_state.header_scan_result = None
        st.rerun()

# This block executes when the scan button is clicked
if scan_button and st.session_state.header_url_input:
    st.session_state.header_scan_result = None # Clear previous results
    with st.status(f"Scanning {st.session_state.header_url_input} and generating AI report...", expanded=True) as status:
        try:
            response = requests.post(
                f"{BACKEND_URL}/scan-website-headers",
                headers=HEADERS,
                json={"url": st.session_state.header_url_input},
                timeout=90
            )
            response.raise_for_status() # Raises an error for bad status codes (4xx or 5xx)
            st.session_state.header_scan_result = response.json()
            status.update(label="Report Generated!", state="complete", expanded=False)
        except requests.exceptions.HTTPError as e:
            status.update(label="Scan Failed!", state="error")
            error_detail = e.response.json().get("detail", str(e))
            st.error(f"Failed to perform scan: {error_detail}")
        except requests.exceptions.RequestException as e:
            status.update(label="Connection Failed!", state="error")
            st.error(f"Failed to connect to the backend: {e}")
    st.rerun()

# --- DISPLAY LOGIC ---
if st.session_state.get('header_scan_result'):
    st.header("📊 AI-Generated Security Report")
    report = st.session_state.header_scan_result
    
    ai_explanation = report.get("ai_explanation")

    # PDF Download Button Logic
    if ai_explanation and "could not be generated" not in ai_explanation:
        try:
            # This payload is simpler, as it has no threat summary or detailed findings
            pdf_payload = {
                "log_type": "header_scanner",
                "markdown_content": ai_explanation
                # threat_summary and detailed_findings are omitted
            }
            pdf_response = requests.post(f"{BACKEND_URL}/download-report", headers=HEADERS, json=pdf_payload)
            if pdf_response.status_code == 200:
                st.download_button(
                    label="⬇️ Download Report as PDF",
                    data=pdf_response.content,
                    file_name="WebsiteHeaderSecurityReport.pdf",
                    mime="application/pdf",
                    use_container_width=True
                )
        except Exception as e:
            st.error(f"Failed to create PDF download link: {e}")

    # Display the main AI-generated explanation
    st.markdown(ai_explanation or "No AI explanation was provided by the backend.")

    st.markdown("---")

    # The raw findings are available in an expander for reference
    with st.expander("Show Raw Scan Findings"):
        # The key is "scan_findings" to match the backend
        report_data = report.get("scan_findings", [])
        if not report_data:
            st.warning("The API did not return any raw scan findings.")
        else:
            good_headers = [f for f in report_data if f['is_present']]
            bad_headers = [f for f in report_data if not f['is_present']]

            col1, col2 = st.columns(2)
            with col1:
                st.success(f"✅ Secure Headers Found: {len(good_headers)}")
            with col2:
                st.error(f"❌ Missing/Insecure Headers: {len(bad_headers)}")
            
            st.dataframe(report_data)