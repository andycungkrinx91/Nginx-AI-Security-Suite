import os
import re
from typing import Dict, Any, Tuple, List
from collections import Counter

# --- LangChain & Google AI Imports ---
from langchain_google_genai import GoogleGenerativeAI, GoogleGenerativeAIEmbeddings
from langchain.prompts import PromptTemplate
from langchain_core.runnables import RunnableLambda
from langchain_core.output_parsers import StrOutputParser
from langchain_community.vectorstores import FAISS
from langchain.docstore.document import Document
from datetime import datetime, timezone

# --- Globals & Configuration ---
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
GEMINI_MODEL_NAME = os.getenv("GEMINI_MODEL_NAME", "gemini-1.5-flash")
EMBEDDING_MODEL_NAME = os.getenv("EMBEDDING_MODEL_NAME", "models/text-embedding-004")
REGEX_PATTERNS_PATH = "owasp_regex_patterns.txt"
FAISS_INDEX_PATH = "vector_store" # The FAISS index will now store our cached reports

COMPILED_REGEX_PATTERNS: List[Dict] = []
# --- Global AI components to be initialized ---
embeddings_model = None
vector_store = None
rag_chain = None

def load_and_compile_regex():
    """Loads and compiles individual regex patterns from the specified file."""
    global COMPILED_REGEX_PATTERNS
    script_dir = os.path.dirname(__file__)
    regex_file_path = os.path.join(script_dir, '..', REGEX_PATTERNS_PATH)
    try:
        with open(regex_file_path, 'r') as f:
            for line in f:
                match = re.match(r'\[(\d+)\]\s*([^:]+):\s*(.*)', line)
                if match:
                    rule_id, name, pattern = match.groups()
                    COMPILED_REGEX_PATTERNS.append({"id": rule_id.strip(), "name": name.strip(), "pattern": re.compile(pattern.strip())})
        print(f"✅ Successfully loaded {len(COMPILED_REGEX_PATTERNS)} regex patterns.")
    except Exception as e:
        print(f"Warning: Could not load regex patterns: {e}")

def scan_log_and_summarize(log_content: str) -> Tuple[List[Dict], str]:
    """
    Scans log content, returns a list of detailed findings, and a concise summary string.
    """
    detailed_findings = []
    threat_names = []
    for i, line in enumerate(log_content.splitlines()):
        for regex in COMPILED_REGEX_PATTERNS:
            if regex["pattern"].search(line):
                detailed_findings.append({"Line": i + 1, "Threat": regex['name'], "Log Entry": line})
                threat_names.append(regex['name'])
                break # Move to next line after first match
    
    # Create the summary string from the Counter object before returning.
    summary_counts = Counter(threat_names)
    summary_string = "\n".join([f"- Found '{threat}' pattern {count} times." for threat, count in summary_counts.items()])

    return detailed_findings, summary_string

def initialize_rag_pipeline() -> Tuple[Any, Any, str]:
    """Initializes all AI components, including the FAISS vector store for caching."""
    global embeddings_model, vector_store, rag_chain
    load_and_compile_regex()

    if not GOOGLE_API_KEY:
        return None, None, "CRITICAL: GOOGLE_API_KEY environment variable not found."

    try:
        llm = GoogleGenerativeAI(
            model=GEMINI_MODEL_NAME,
            google_api_key=GOOGLE_API_KEY,
            temperature=0.8,
            max_output_tokens=10240
        )
        embeddings_model = GoogleGenerativeAIEmbeddings(model=EMBEDDING_MODEL_NAME)
        
        # Correctly check for the index.faiss file, not just the directory
        faiss_file_path = os.path.join(FAISS_INDEX_PATH, "index.faiss")
        if os.path.exists(faiss_file_path):
            print(f"Loading existing FAISS vector store from: {FAISS_INDEX_PATH}")
            vector_store = FAISS.load_local(FAISS_INDEX_PATH, embeddings_model, allow_dangerous_deserialization=True)
        else:
            print(f"No FAISS index found. Creating a new empty one at: {FAISS_INDEX_PATH}")
            os.makedirs(FAISS_INDEX_PATH, exist_ok=True)
            initial_text = ["Welcome to the AI Security Suite Knowledge Base"]
            vector_store = FAISS.from_texts(initial_text, embeddings_model)
            vector_store.save_local(FAISS_INDEX_PATH)

        prompt_template = """{report_header}
        You are a world-class cybersecurity analyst. You have been provided with a concise summary of threats found in an Nginx log file. Your goal is to write a comprehensive security report based on this summary.
        Your response MUST be detailed and structured in the following sections using Markdown:
        {report_header}

        ## Threat Summary:
        {context}
        ---
        ## 1. Executive Summary
        Provide a high-level overview of the findings. Mention the most critical threats discovered based on the threat summary.

        ## 2. Detailed Threat Analysis
        List of specific for each threat type found (e.g., SQLi, XSS), create a subsection. Explain the general risk of this type of attack and why it is a concern.

        ## 3. Multi-Layer Hardening Recommendations
        Provide a prioritized list of specific, actionable steps to mitigate the identified threat types at the Web Server (Nginx/WAF), Application, and Network layers.

        ## 4. Further Reading
        Search 2-3 high-quality real reference links from global best website in security focus for the most critical threats found. dont use owaps.org. never explain just provide the links.
        """
        PROMPT = PromptTemplate.from_template(prompt_template)

        rag_chain = PROMPT | llm | StrOutputParser()
        
        return llm, rag_chain, None

    except Exception as e:
        print(f"🚨 FATAL ERROR DURING RAG PIPELINE INITIALIZATION 🚨\n{e}")
        return None, None, str(e)


def analyze_log_data(log_content: str, rag_chain: Any) -> Dict[str, Any]:
    """The analysis workflow with semantic caching and the dynamic report header."""
    global vector_store, embeddings_model
    if not all([rag_chain, vector_store, embeddings_model]):
        return {"summary": "## Analysis Failed", "detailed_findings": []}
    
    detailed_findings, summary_for_cache = scan_log_and_summarize(log_content)
    
    if not detailed_findings:
        return {"summary": "## ✅ No Threats Detected", "detailed_findings": []}

    cached_results = vector_store.similarity_search_with_relevance_scores(summary_for_cache, k=1, score_threshold=0.95)
    
    if cached_results:
        print("✅ SEMANTIC CACHE HIT: Found a matching previous analysis.")
        return {
            "summary": cached_results[0][0].page_content,
            "detailed_findings": detailed_findings,
            "source": "Retrieved from Semantic Cache"
        }

    print("SEMANTIC CACHE MISS: Generating new report from AI.")
    try:
        current_time_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        report_header = f"# Security Report Logs\n\n_{current_time_utc}_"

        # Invoke the chain, now providing the dynamic header and the threat summary
        ai_summary = rag_chain.invoke({
            "report_header": report_header,
            "context": summary_for_cache
        })
        
        # Update the cache with the new report
        new_doc = Document(page_content=ai_summary, metadata={"source_query": summary_for_cache})
        vector_store.add_documents([new_doc])
        vector_store.save_local(FAISS_INDEX_PATH)
        vector_store = FAISS.load_local(FAISS_INDEX_PATH, embeddings_model, allow_dangerous_deserialization=True)
        print("CACHE UPDATE: Saved new AI report and reloaded FAISS index.")

        return {
            "summary": ai_summary,
            "detailed_findings": detailed_findings,
            "source": "Newly Generated by AI"
        }
    except Exception as e:
        return {"summary": f"## AI Analysis Error\n\n**Error:** {e}", "details": {"regex_findings": detailed_findings}}





