import streamlit as st
import requests
import os
import time
from urllib.parse import urlparse
import pandas as pd
import json

st.set_page_config(page_title="Interactive Web Scraper Analyzer", page_icon="🕷️", layout="wide")

if 'scraper_job_id' not in st.session_state:
    st.session_state.scraper_job_id = None
if 'scraper_result' not in st.session_state:
    st.session_state.scraper_result = None
if 'clean_domain' not in st.session_state:
    st.session_state.clean_domain = ""

BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")
API_KEY = os.getenv("BACKEND_API_KEY") # You can add API Key handling if needed
HEADERS = {"X-API-Key": API_KEY} if API_KEY else {}

USER_AGENTS = {
    "Chrome (Windows)": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Firefox (Windows)": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/114.0",
    "Edge (Windows)": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.51",
    "Chrome (macOS)": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Safari (macOS)": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5.1 Safari/605.1.15",
    "Firefox (macOS)": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/114.0",
    "Chrome (Linux)": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Firefox (Linux)": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/114.0",
    "Chrome (Android)": "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Mobile Safari/537.36",
    "Firefox (Android)": "Mozilla/5.0 (Android 13; Mobile; rv:109.0) Gecko/114.0 Firefox/114.0",
    "Safari (iPhone iOS 16)": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5.1 Mobile/15E148 Safari/604.1",
    "Chrome (iPhone iOS 16)": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/114.0.5735.124 Mobile/15E148 Safari/604.1",
    "Samsung Internet": "Mozilla/5.0 (Linux; Android 13; SM-S908B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Mobile Safari/537.36",
    "Facebook External Hit": "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
    "Googlebot": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Bingbot": "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "DuckDuckBot": "DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)",
    "YandexBot": "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
    "curl": "curl/7.81.0",
    "wget": "Wget/1.21.3",
    "Postman": "PostmanRuntime/7.32.3",
    "TwitterBot": "Twitterbot/1.0"
}

@st.cache_data(show_spinner="Generating PDF report...")
def get_pdf_report(job_id, domain, ai_analysis, raw_results):
    """
    Calls the backend to generate the PDF report. Caching prevents re-generating on every rerun.
    This function now correctly passes the job_id to enable backend result archiving.
    """
    pdf_payload = {
        "job_id": job_id,
        "domain": domain,
        "markdown_content": ai_analysis,
        "raw_scrape_results": raw_results
    }
    try:
        pdf_response = requests.post(f"{BACKEND_URL}/download-interactive-report", headers=HEADERS, json=pdf_payload)
        pdf_response.raise_for_status()
        return pdf_response.content
    except requests.exceptions.RequestException as e:
        st.error(f"Failed to generate PDF report: {e}")
        return None

st.title("🕷️ AI-Powered Interactive Web Scraper Analyzer")

# --- Input Form ---
# This entire form will be hidden once a scan result is available.
if not st.session_state.scraper_result:
    domain_input = st.text_input(
        "Enter a Domain to Scrape (e.g., books.toscrape.com)",
        key='scraper_domain_input'
    )
    max_pages_input = st.number_input(
        "Max Pages to Crawl", min_value=1, max_value=100, value=5
    )
    user_agent_key = st.selectbox("Select User Agent", options=list(USER_AGENTS.keys()))
    user_agent_string = USER_AGENTS[user_agent_key]

    if st.button("Scrape & Analyze", type="primary", use_container_width=True, disabled=(not domain_input or st.session_state.scraper_job_id is not None)):
        st.session_state.scraper_job_id = None
        st.session_state.scraper_result = None
        
        with st.spinner("Submitting scrape job to the backend..."):
            try:
                # Sanitize user input by removing leading/trailing whitespace
                start_url = domain_input.strip()
                if not start_url.startswith(('http://', 'https://')):
                    start_url = 'https://' + start_url
                
                parsed_url = urlparse(start_url)
                clean_domain = parsed_url.netloc

                if not clean_domain:
                     st.error("Invalid URL. Could not determine the domain.")
                else:
                    st.session_state.clean_domain = clean_domain
                    
                    payload = {"start_url": start_url, "domain": clean_domain, "max_pages": max_pages_input, "user_agent": user_agent_string}
                    response = requests.post(f"{BACKEND_URL}/interactive-scrape", headers=HEADERS, json=payload)
                    response.raise_for_status()
                    st.session_state.scraper_job_id = response.json().get("job_id")

            except requests.exceptions.RequestException as e:
                error_message = f"Failed to submit job: {e}"
                if e.response and e.response.text:
                    try: # Try to parse a specific error detail from the backend
                        detail = e.response.json().get("detail", e.response.text)
                        error_message = f"Error from backend: {detail}"
                    except json.JSONDecodeError:
                        error_message = f"Received an unreadable error from the backend: {e.response.text[:200]}"
                st.error(error_message)
                st.session_state.scraper_job_id = None

if st.session_state.scraper_job_id and not st.session_state.scraper_result:
    st.info("Analysis in progress... This may take a few minutes depending on the target website.")
    progress_bar = st.progress(0, text="Waiting for job to start...")
    
    status_map = {
        "queued": (10, "Job is queued..."),
        "Stage 1 of 3": (33, "Stage 1/3: Crawler is running..."),
        "Stage 2 of 3": (66, "Stage 2/3: Generating AI Analysis..."),
        "Stage 3 of 3": (90, "Stage 3/3: Finalizing report..."),
    }
    
    # The "Cancel" button is now outside the polling logic and will always be responsive.
    if st.button("Cancel Scan", key="cancel_scan_button"):
        try:
            requests.post(f"{BACKEND_URL}/cancel-scrape/{st.session_state.scraper_job_id}", headers=HEADERS)
            st.warning("Scan cancellation requested.")
            st.session_state.scraper_job_id = None
            time.sleep(1) # Give user time to see the message
            st.rerun()
        except requests.exceptions.RequestException as e:
            st.error(f"Failed to cancel job: {e}")

    # This block replaces the `while True` loop. It polls once, then forces a rerun.
    # This makes the app feel responsive and avoids duplicate widget errors.
    try:
        res = requests.get(f"{BACKEND_URL}/result-scraper/{st.session_state.scraper_job_id}", headers=HEADERS)
        res.raise_for_status()
        job_status = res.json()
        status = job_status.get("status")
        
        if status == "complete":
            st.session_state.scraper_result = job_status.get("result", {})
            progress_bar.progress(100, text="Analysis Complete!")
            time.sleep(1)
            st.rerun()
        elif status == "failed":
            st.error(f"Analysis failed: {job_status.get('error', 'Unknown error')}")
            st.session_state.scraper_job_id = None # Reset to allow new job
            # No rerun needed, the error message will persist until the user acts.
        else:
            # Job is still running, update progress and schedule a rerun
            message = job_status.get("message", "Processing...")
            progress_percent, progress_text = (5, message) # Default
            for key, (percent, text) in status_map.items():
                if key in message:
                    progress_percent, progress_text = percent, text
                    break
            progress_bar.progress(progress_percent, text=progress_text)
            
            # Force a rerun to poll again after a short delay
            time.sleep(3)
            st.rerun()

    except requests.exceptions.HTTPError as e:
        error_detail = e.response.text if e.response else "Unknown error"
        st.error(f"An error occurred: {error_detail}")
        st.session_state.scraper_job_id = None # Reset
    except requests.exceptions.RequestException as e:
        st.error(f"Could not retrieve job status: {e}")
        st.session_state.scraper_job_id = None # Reset

if st.session_state.scraper_result:
    # --- New Scan Button ---
    # Allows the user to clear results and start a new scan.
    if st.button("✨ Start New Scan", use_container_width=True):
        # Clear all scraper-related state
        st.session_state.scraper_job_id = None
        st.session_state.scraper_result = None
        st.session_state.clean_domain = ""
        st.rerun()
    st.markdown("---")

    result = st.session_state.scraper_result
    ai_analysis = result.get("ai_analysis", "No AI analysis was provided.")
    raw_results = result.get("raw_scrape_results", [])
    
    st.header("📊 AI-Generated Security Assessment")
    
    # Use the cached function to get the PDF bytes
    pdf_bytes = get_pdf_report(
        st.session_state.scraper_job_id,
        st.session_state.clean_domain,
        ai_analysis,
        raw_results
    )
    if pdf_bytes:
        st.download_button(
            label="⬇️ Download Full Report as PDF",
            data=pdf_bytes,
            file_name=f"Scraper_Report_{st.session_state.clean_domain.replace('.', '_')}.pdf",
            mime="application/pdf",
            use_container_width=True
        )
    st.markdown(ai_analysis)

    with st.expander("Show Raw Scraped Data"):
        if raw_results:
            # Improve data display with a DataFrame
            df = pd.DataFrame(raw_results)
            # Add a summary column for form interactions
            df['forms_summary'] = df['forms_found'].apply(
                lambda forms: f"{len(forms)} form(s) found." if forms else "None"
            )
            st.dataframe(df[['url', 'page_title', 'links_found', 'forms_summary']], use_container_width=True)
            st.info("Expand the JSON below for full technical details of each page.")
            st.json(raw_results)
        else:
            st.write("No raw data was returned from the scraper.")
