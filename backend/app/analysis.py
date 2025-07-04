import os
import re
from typing import Dict, Any, Tuple, List
from collections import Counter
from datetime import datetime, timezone

# --- LangChain & Google AI Imports ---
from langchain_google_genai import GoogleGenerativeAI, GoogleGenerativeAIEmbeddings
from langchain.prompts import PromptTemplate
from langchain_core.runnables import RunnablePassthrough
from langchain_core.output_parsers import StrOutputParser
from langchain_community.vectorstores import FAISS
from langchain.docstore.document import Document

# --- Globals & Configuration ---
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
GEMINI_MODEL_NAME = os.getenv("GEMINI_MODEL_NAME", "gemini-1.5-flash")
EMBEDDING_MODEL_NAME = os.getenv("EMBEDDING_MODEL_NAME", "models/text-embedding-004")
# Define paths for both regex pattern files, located in the backend root
NGINX_REGEX_PATH = "owasp_regex_patterns.txt"
APACHE_REGEX_PATH = "apache_regex_patterns.txt"
FAISS_INDEX_PATH = "vector_store"

# This dictionary will hold the compiled patterns for each log type
COMPILED_REGEX_PATTERNS: Dict[str, List[Dict]] = {"nginx": [], "apache": []}
# Global AI components to be initialized at startup
embeddings_model = None
vector_store = None
rag_chain = None

def load_and_compile_regex():
    """
    Loads and compiles regex patterns for both Nginx and Apache at startup.
    """
    pattern_files = {"nginx": NGINX_REGEX_PATH, "apache": APACHE_REGEX_PATH}
    
    for log_type, file_name in pattern_files.items():
        script_dir = os.path.dirname(__file__)
        regex_file_path = os.path.join(script_dir, '..', file_name)
        try:
            with open(regex_file_path, 'r') as f:
                for line in f:
                    match = re.match(r'\[(\d+)\]\s*([^:]+):\s*(.*)', line)
                    if match:
                        rule_id, name, pattern = match.groups()
                        try:
                            COMPILED_REGEX_PATTERNS[log_type].append({
                                "id": rule_id.strip(),
                                "name": name.strip(),
                                "pattern": re.compile(pattern.strip())
                            })
                        except re.error as e:
                            print(f"Warning: Could not compile regex for '{name}' in {file_name}: {e}")
            print(f"✅ Successfully loaded {len(COMPILED_REGEX_PATTERNS[log_type])} regex patterns for {log_type}.")
        except Exception as e:
            print(f"An error occurred loading {file_name}: {e}")

def scan_log_and_summarize(log_content: str, log_type: str) -> Tuple[List[Dict], str]:
    """
    Scans log content using the appropriate regex set, returns a list of detailed 
    findings, and a deterministic, sorted summary string for consistent caching.
    """
    detailed_findings = []
    threat_names = []
    patterns_to_use = COMPILED_REGEX_PATTERNS.get(log_type, [])
    
    for i, line in enumerate(log_content.splitlines()):
        for regex in patterns_to_use:
            if regex["pattern"].search(line):
                detailed_findings.append({"Line": i + 1, "Threat": regex['name'], "Log Entry": line})
                threat_names.append(regex['name'])
                break # Move to next line after first match
    
    summary_counts = Counter(threat_names)
    # Sort the summary lines alphabetically to ensure the summary string is
    # always identical for the same set of threats. This is critical for cache hits.
    summary_lines = [f"- Found '{threat}' pattern {count} times." for threat, count in sorted(summary_counts.items())]
    summary_string = "\n".join(summary_lines)
    
    return detailed_findings, summary_string

def initialize_rag_pipeline() -> Tuple[Any, Any, str]:
    """
    Initializes all AI components, including the FAISS vector store for semantic caching
    and a pure LCEL chain for generation.
    """
    global embeddings_model, vector_store, rag_chain
    load_and_compile_regex()

    if not GOOGLE_API_KEY:
        return None, None, "CRITICAL: GOOGLE_API_KEY environment variable not found."

    try:
        llm = GoogleGenerativeAI(model=GEMINI_MODEL_NAME, temperature=0.8, max_output_tokens=20480)
        embeddings_model = GoogleGenerativeAIEmbeddings(model=EMBEDDING_MODEL_NAME)
        
        # Correctly check for the index.faiss file to prevent startup errors
        faiss_file_path = os.path.join(FAISS_INDEX_PATH, "index.faiss")
        if os.path.exists(faiss_file_path):
            print(f"Loading existing FAISS vector store from: {FAISS_INDEX_PATH}")
            vector_store = FAISS.load_local(FAISS_INDEX_PATH, embeddings_model, allow_dangerous_deserialization=True)
        else:
            print(f"No FAISS index found. Creating a new empty one at: {FAISS_INDEX_PATH}")
            os.makedirs(FAISS_INDEX_PATH, exist_ok=True)
            initial_text = ["Initial document for the knowledge base."]
            vector_store = FAISS.from_texts(initial_text, embeddings_model)
            vector_store.save_local(FAISS_INDEX_PATH)

        # The full, detailed, and dynamic prompt template
        prompt_template = """{report_header}

        You are a world-class cybersecurity analyst. You have been provided with a concise summary of threats found in an **{log_type}** log file. Your goal is to write a comprehensive detailed security report based on this summary.

        **Threat Summary:**
        {context}
        ---
        ## 1. Executive Summary
        Provide a high-level overview of the findings for this {log_type} log analysis. Mention the most critical threats discovered based on the threat summary.
        
        ## 2. Detailed Threat Analysis
        List number of specific for each threat type found for this {log_type}. explain the general risk and why it is a concern.
        
        ## 3. Multi-Layer Hardening Recommendations
        List of Provide a prioritized specific detail and actionable steps to mitigate the identified threats types for this {log_type} log. Include configurations if applicable.
        
        ## 4. Further Reading
        List search result of 2-3 high-quality real reference links for this {log_type}. with newline and number in every link. from global internet website only in security focus for the most critical threats found. dont explain anything give link only. dont use owaps.org.
        """
        PROMPT = PromptTemplate.from_template(prompt_template)

        # The LCEL Chain, correctly defined to pass all variables
        rag_chain = (
            RunnablePassthrough() 
            | PROMPT
            | llm
            | StrOutputParser()
        )
        
        return llm, rag_chain, None

    except Exception as e:
        print(f"🚨 FATAL ERROR DURING RAG PIPELINE INITIALIZATION 🚨\n{e}")
        return None, None, str(e)


def analyze_log_data(log_content: str, rag_chain: Any, log_type: str) -> Dict[str, Any]:
    """
    The full analysis workflow with semantic caching, regex scanning, and detailed reporting.
    """
    global vector_store, embeddings_model
    if not all([rag_chain, vector_store, embeddings_model]):
        return {"summary": "## Analysis Failed: AI pipeline not ready.", "detailed_findings": []}
    
    detailed_findings, summary_for_cache = scan_log_and_summarize(log_content, log_type)
    
    if not detailed_findings:
        return {"summary": "## ✅ No Threats Detected", "detailed_findings": []}

    # Add log_type to the cache query to make it unique for Nginx vs. Apache
    cache_query = f"LogType: {log_type}\n{summary_for_cache}"
    cached_results = vector_store.similarity_search_with_relevance_scores(cache_query, k=1, score_threshold=0.95)
    
    if cached_results:
        print("✅ SEMANTIC CACHE HIT: Found a matching previous analysis.")
        return {
            "summary": cached_results[0][0].page_content,
            "detailed_findings": detailed_findings,
            "source": "Retrieved from Semantic Cache"
        }

    # Cache Miss: Generate new report from the AI
    print("SEMANTIC CACHE MISS: Generating new report from AI.")
    try:
        current_time_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        report_header = f"# Security Report: {log_type.capitalize()} Log\n\n_{current_time_utc}_"

        ai_summary = rag_chain.invoke({
            "report_header": report_header,
            "context": summary_for_cache,
            "log_type": log_type.capitalize() # Pass the log_type to the prompt
        })
        
        # Save the new report back to the knowledge base
        new_doc = Document(page_content=ai_summary, metadata={"source_query": cache_query})
        vector_store.add_documents([new_doc])
        vector_store.save_local(FAISS_INDEX_PATH)
        # Reload the index to ensure the next request sees the new data
        vector_store = FAISS.load_local(FAISS_INDEX_PATH, embeddings_model, allow_dangerous_deserialization=True)
        print("CACHE UPDATE: Saved new AI report and reloaded FAISS index.")

        return {
            "summary": ai_summary,
            "detailed_findings": detailed_findings,
            "source": "Newly Generated by AI"
        }
    except Exception as e:
        return {"summary": f"## AI Analysis Error\n\n**Error:** {e}", "details": {"regex_findings": detailed_findings}}