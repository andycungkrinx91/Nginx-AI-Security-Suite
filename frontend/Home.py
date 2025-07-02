import streamlit as st
import pandas as pd

# Page config should be set once, at the top of the main app page.
st.set_page_config(
    page_title="AI Security Suite",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        'Get Help': 'https://owasp.org/www-project-top-ten/',
        'Report a bug': None,
        'About': "# This is an AI-powered security tool suite!"
    }
)

# --- OWASP Regex Patterns Data ---
REGEX_DATA = {
    "ID": [f"[{i:03d}]" for i in range(1, 51)],
    "Threat Name": [
        "SQLi", "XSS", "RFI", "LFI", "Command Injection", "Brute Force", 
        "Path Traversal", "CSRF", "XXE", "SSRF", "Unvalidated Redirects", 
        "PHP Code Injection", "Javascript Injection", "Header Injection", 
        "LDAP Injection", "NoSQL Injection", "File Upload Bypass", 
        "OS Command Execution", "Directory Indexing Exposure", "Sensitive File Access", 
        "RCE", "SQLi Time-Based", "Unrestricted File Upload", "Command Substitution", 
        "HTML Injection", "Shellshock", "HTTP Response Splitting", "Buffer Overflow", 
        "SSTI", "Insecure Deserialization", "Reverse Shell (PHP)", "DNS Rebinding", 
        "SSRF via Proxy", "Session Fixation", "Unauthorized API Access", 
        "SQLi Union Select", "Clickjacking", "Open Redirect", "Weak Passwords", 
        "Excessive Input Validation", "WebSocket Hijacking", "Sudo Command Injection", 
        "SMTP Injection", "XML Injection", "HTML5 Storage Abuse", 
        "Debug Mode Disclosure", "Ruby on Rails Code Injection", "CAPTCHA Bypass", 
        "HTTP Parameter Pollution", "Abuse of Functionality"
    ]
}

# --- HEADER (UPDATED) ---
st.title("🛡️ AI Security Suite")
st.markdown("Welcome! This application is a set of tools designed to enhance your web server security using AI. **Select a tool from the sidebar to get started.**")

st.markdown("---")

# --- FEATURES SECTION (UPDATED) ---
st.subheader("Our Tools")

col1, col2 = st.columns(2)

with col1:
    with st.container(border=True):
        st.markdown("#### 📄 Log Analyzer")
        st.markdown("""
        Perform a deep analysis of your **Nginx** or **Apache** `access.log` files. The hybrid system uses regex to find known threats and then applies AI to generate a detailed report with actionable remediation advice.
        """)

with col2:
    with st.container(border=True):
        st.markdown("#### 🌐 Website Header Analyzer")
        st.markdown("""
        Scan a live website to check for essential security headers. This tool provides an AI-powered report explaining the risks of missing headers and gives you a ready-to-use Nginx configuration block to fix them.
        """)

st.info("Powered by a hybrid system combining high-speed Regex scanning with a Google Gemini RAG pipeline.", icon="🤖")

st.markdown("---")

# --- REGEX PATTERNS SECTION ---
st.subheader("Threat Intelligence")
with st.expander("👁️ View the 50 OWASP Threat Patterns We Scan For"):
    df = pd.DataFrame(REGEX_DATA)
    
    with st.container(height=300):
         st.dataframe(
             df,
             use_container_width=True,
             hide_index=True,
             column_config={
                 "ID": st.column_config.TextColumn("ID", width="small"),
                 "Threat Name": st.column_config.TextColumn("Threat Name"),
             }
         )

# --- FOOTER ---
st.markdown("---")
st.markdown(
    """
    <div style="text-align: center; color: grey;">
        <p>Copyright &copy; Andy Setiyawan 2025</p>
    </div>
    """,
    unsafe_allow_html=True
)