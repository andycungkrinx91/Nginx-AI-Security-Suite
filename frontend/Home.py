import streamlit as st

# Page config should be set once, at the top of the main app page.
st.set_page_config(
    page_title="Nginx AI Security Suite",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        'Get Help': 'https://www.google.com/search?q=nginx+security',
        'Report a bug': None,
        'About': "# This is an AI-powered security tool suite!"
    }
)

# --- HEADER ---
st.title("🛡️ Nginx AI Security Suite")
st.markdown("Welcome! This application is a set of tools designed to enhance your web server security using AI. **Select a tool from the sidebar to get started.**")

st.markdown("---")

# --- FEATURES SECTION ---
st.subheader("Our Tools")

col1, col2 = st.columns(2)

with col1:
    with st.container(border=True):
        st.markdown("#### 📄 Log Analyzer")
        st.markdown("""
        Perform a deep analysis of your Nginx `access.log` files. The AI will identify potential security threats like:
        - SQL Injection (SQLi)
        - Cross-Site Scripting (XSS)
        - Path Traversal
        - Malicious reconnaissance scans
        
        Receive a detailed report with actionable remediation advice.
        """)

with col2:
    with st.container(border=True):
        st.markdown("#### 🌐 Website Header Analyzer")
        st.markdown("""
        Scan a live website to check for essential security headers. This tool provides an AI-powered report explaining the risks of missing headers and gives you a ready-to-use Nginx configuration block to fix them.
        
        A great way to audit your site's public-facing security posture.
        """)

st.info("Powered by a Retrieval-Augmented Generation (RAG) pipeline using Google's Gemini models.", icon="🤖")


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