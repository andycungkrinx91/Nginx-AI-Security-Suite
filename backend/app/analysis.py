import os
import re
from typing import Dict, Any, Tuple, List

# --- LangChain & Google AI Imports ---
from langchain_google_genai import GoogleGenerativeAI, GoogleGenerativeAIEmbeddings
from langchain_community.vectorstores import FAISS
from langchain.chains import RetrievalQA
from langchain.prompts import PromptTemplate
from langchain.docstore.document import Document

# --- Environment and Path Configuration ---
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
GEMINI_MODEL_NAME = os.getenv("GEMINI_MODEL_NAME", "gemini-1.5-flash-latest")
EMBEDDING_MODEL_NAME = os.getenv("EMBEDDING_MODEL_NAME", "models/text-embedding-004")
# --- FILENAME UPDATED HERE ---
# The path to the regex patterns file, assuming it's in the backend root
REGEX_PATTERNS_PATH = "owasp_regex_patterns.txt"

# --- Global variable for compiled regex patterns ---
COMPILED_REGEX_PATTERNS: List[Dict] = []


def load_and_compile_regex():
    """
    Loads and compiles regex patterns from the specified file.
    This version now correctly parses the '[ID] Name:Pattern' format.
    """
    global COMPILED_REGEX_PATTERNS
    script_dir = os.path.dirname(__file__)
    regex_file_path = os.path.join(script_dir, '..', REGEX_PATTERNS_PATH)
    
    print(f"Attempting to load and compile regex patterns from: {os.path.abspath(regex_file_path)}")
    try:
        with open(regex_file_path, 'r') as f:
            for line in f:
                # Use regex to parse the format: [ID] Name:Pattern
                match = re.match(r'\[(\d+)\]\s*([^:]+):\s*(.*)', line)
                if match:
                    rule_id, name, pattern = match.groups()
                    try:
                        COMPILED_REGEX_PATTERNS.append({
                            "id": rule_id.strip(),
                            "name": name.strip(),
                            "pattern": re.compile(pattern.strip())
                        })
                    except re.error as e:
                        print(f"Warning: Could not compile regex for '{name}' (ID: {rule_id}): {e}")
        print(f"✅ Successfully loaded and compiled {len(COMPILED_REGEX_PATTERNS)} regex patterns.")
    except FileNotFoundError:
        print(f"Warning: {regex_file_path} not found. Regex scanning will be disabled.")
    except Exception as e:
        print(f"An error occurred while loading regex patterns: {e}")


def scan_log_with_regex(log_content: str) -> List[str]:
    """
    Scans log content with pre-compiled regex patterns and returns a list of unique findings.
    """
    findings = set()
    if not COMPILED_REGEX_PATTERNS:
        return []

    for i, line in enumerate(log_content.splitlines()):
        for regex in COMPILED_REGEX_PATTERNS:
            if regex["pattern"].search(line):
                # Include the ID in the finding for better traceability
                finding = f"Line {i+1}: [ID {regex['id']}] Found potential '{regex['name']}' pattern."
                findings.add(finding)
    return sorted(list(findings))


def initialize_rag_pipeline() -> Tuple[Any, Any, str]:
    """
    Initializes the RAG pipeline and loads the regex patterns for the hybrid analysis system.
    """
    load_and_compile_regex()

    if not GOOGLE_API_KEY:
        error_msg = "CRITICAL: GOOGLE_API_KEY environment variable not found."
        return None, None, error_msg

    try:
        llm = GoogleGenerativeAI(
            model=GEMINI_MODEL_NAME,
            google_api_key=GOOGLE_API_KEY,
            temperature=0.8,
            max_output_tokens=10240
        )
        
        prompt_template = """You are a world-class cybersecurity analyst. You have been provided with a summary of potential threats found by a regex scanner in an Nginx log file. Your goal is to provide a comprehensive, clear, and actionable security report based on these findings.

        **Regex Scan Findings:**
        ```
        {context}
        ```

        **Log Snippet (for additional context):**
        ```
        {question}
        ```

        Your response MUST be detailed and structured in Markdown with the following sections:

        ## 1. Executive Summary
        Provide a high-level overview of the findings. Mention the most critical threats discovered based on the regex scan.

        ## 2. Detailed Threat Analysis
        For each threat type found by the scanner (e.g., SQLi, XSS), create a subsection. Explain the risk, why it was flagged, and what the attacker's goal might be. Reference specific lines and rule IDs if possible.

        ## 3. Multi-Layer Hardening Recommendations
        Provide a prioritized list of specific, actionable steps to mitigate the identified threats at the Web Server (Nginx/WAF), Application, and Network layers.

        ## 4. Further Reading
        Provide 2-3 high-quality reference links from authoritative sources (like OWASP) for the most critical threats found.
        """
        PROMPT = PromptTemplate(template=prompt_template, input_variables=["context", "question"])

        dummy_retriever = FAISS.from_texts(
            ["Placeholder for RAG chain initialization"], 
            GoogleGenerativeAIEmbeddings(model=EMBEDDING_MODEL_NAME, google_api_key=GOOGLE_API_KEY)
        ).as_retriever()

        chain = RetrievalQA.from_chain_type(
            llm=llm,
            chain_type="stuff",
            retriever=dummy_retriever,
            chain_type_kwargs={"prompt": PROMPT},
            return_source_documents=False
        )
        
        return llm, chain, None

    except Exception as e:
        error_details = f"ERROR DETAILS: {e}"
        print(f"🚨 FATAL ERROR DURING RAG PIPELINE INITIALIZATION 🚨\n{error_details}")
        return None, None, str(e)


def analyze_log_data(log_content: str, rag_chain: Any) -> Dict[str, Any]:
    """
    New analysis workflow: First, scan with Regex, then use the AI to analyze those specific findings.
    """
    if not rag_chain:
        return {"summary": "## Analysis Failed\n\n**Reason:** AI pipeline is not available."}

    regex_findings = scan_log_with_regex(log_content)
    
    if not regex_findings:
        return {
            "summary": "## ✅ No Threats Detected\n\nNo suspicious patterns were found in the log file based on the configured regular expressions.",
            "details": {"regex_findings": []}
        }

    context_for_ai = "\n".join(regex_findings)
    log_snippet_for_ai = "\n".join(log_content.strip().splitlines()[:20])

    try:
        result = rag_chain.invoke({
            "query": log_snippet_for_ai,
            "context": context_for_ai
        })
        
        return {
            "summary": result.get("result", "No AI summary provided."),
            "details": {"regex_findings": regex_findings}
        }
    except Exception as e:
        return {"summary": f"## AI Analysis Error\n\n**Error:** {e}", "details": {"regex_findings": regex_findings}}