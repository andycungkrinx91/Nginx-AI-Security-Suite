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

# --- HEADER ---
st.title("🛡️ AI Security Suite")
st.markdown("Welcome! This application is a set of tools designed to enhance your web server security using AI. **Select a tool from the sidebar to get started.**")

st.markdown("---")

# --- FEATURES SECTION ---
st.subheader("Our Tools")

# Data for the tools table
tools_data = [
    {
        "icon": "📄",
        "title": "Log Analyzer",
        "description": "Perform a deep analysis of your Nginx or Apache `access.log` files. The hybrid system uses regex to find known threats and then applies AI to generate a detailed report with actionable remediation advice.",
        "image_url": "https://raw.githubusercontent.com/andycungkrinx91/Nginx-AI-Security-Suite/master/images/log-analyzer.png"
    },
    {
        "icon": "🌐",
        "title": "Website Header Analyzer",
        "description": "Scan a live website to check for essential security headers. This tool provides an AI-powered report explaining the risks of missing headers and gives you a ready-to-use Nginx configuration block to fix them.",
        "image_url": "https://raw.githubusercontent.com/andycungkrinx91/Nginx-AI-Security-Suite/master/images/header-analyzer.png"
    },
    {
        "icon": "🕷️",
        "title": "Interactive Web Scraper Analyzer",
        "description": "Utilizes **Playwright** to launch a real browser, navigate to a URL, and analyze its structure and visible links. The AI then assesses the page for potential security attack surfaces.",
        "image_url": "https://raw.githubusercontent.com/andycungkrinx91/Nginx-AI-Security-Suite/master/images/scraper-analyzer.png"
    }
]

# Build the HTML table string to display tools with clickable thumbnails
html_table = """
<style>
    .tools-table { width: 100%; border-collapse: collapse; }
    .tools-table td { padding: 15px; vertical-align: top; border-bottom: 1px solid #333; }
    .tools-table img { width: 150px; border-radius: 8px; border: 1px solid #444; transition: transform 0.2s; }
    .tools-table img:hover { transform: scale(1.05); }
    .tools-table h4 { margin-top: 0; }
</style>
<table class="tools-table">
"""

for tool in tools_data:
    html_table += f"""
    <tr>
        <td style="width: 160px;">
            <a href="{tool['image_url']}" target="_blank">
                <img src="{tool['image_url']}" alt="{tool['title']}">
            </a>
        </td>
        <td>
            <h4>{tool['icon']} {tool['title']}</h4>
            <p>{tool['description']}</p>
        </td>
    </tr>
    """

html_table += "</table>"

st.markdown(html_table, unsafe_allow_html=True)

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