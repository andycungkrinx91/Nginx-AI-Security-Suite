import os
from typing import Dict, Any, Tuple

from langchain_google_genai import GoogleGenerativeAI, GoogleGenerativeAIEmbeddings
from langchain_community.vectorstores import FAISS
from langchain.chains import RetrievalQA
from langchain.prompts import PromptTemplate
from langchain.docstore.document import Document

# --- Environment and Path Configuration ---
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
GEMINI_MODEL_NAME = os.getenv("GEMINI_MODEL_NAME", "gemini-1.5-flash-latest")
EMBEDDING_MODEL_NAME = os.getenv("EMBEDDING_MODEL_NAME", "models/text-embedding-004")
FAISS_INDEX_PATH = "vector_store/faiss_index"


def initialize_rag_pipeline() -> Tuple[Any, Any, str]:
    """
    Initializes and returns the RAG pipeline components.
    On success, returns (llm, rag_chain, None).
    On failure, returns (None, None, error_message).
    """
    if not GOOGLE_API_KEY:
        error_msg = "CRITICAL: GOOGLE_API_KEY environment variable not found."
        print(error_msg)
        return None, None, error_msg

    try:
        llm = GoogleGenerativeAI(
            model=GEMINI_MODEL_NAME,
            google_api_key=GOOGLE_API_KEY,
            temperature=0.8,
            max_output_tokens=10240
        )
        embeddings = GoogleGenerativeAIEmbeddings(model=EMBEDDING_MODEL_NAME, google_api_key=GOOGLE_API_KEY)

        if os.path.exists(FAISS_INDEX_PATH):
            vector_store = FAISS.load_local(FAISS_INDEX_PATH, embeddings, allow_dangerous_deserialization=True)
        else:
            vector_store = create_and_save_new_index(embeddings)

        retriever = vector_store.as_retriever()

        # --- NEW & IMPROVED PROMPT ---
        prompt_template = """You are a world-class cybersecurity analyst and incident responder. Your goal is to provide a comprehensive, clear, and actionable security report based on the provided Nginx log snippet and retrieved context.

        Context: {context}

        Log Snippet: {question}

        Your response MUST be detailed and structured in the following five parts using Markdown. Use bolding and bullet points to make the report easy to read.

        ## 1. Threat Classification & Severity
            * **Threat**: Clearly state the most likely attack pattern (e.g., SQL Injection, Cross-Site Scripting, Path Traversal, Reconnaissance Scan). If no threat is apparent, state "Informational" or "No Immediate Threat Detected."
            * **Severity**: Assign a severity level (Critical, High, Medium, Low, or Informational) and briefly justify your reasoning.

        ## 2. Detailed Analysis & Indicators
            * Explain *exactly* why you classified the log entry as you did, referencing the context provided.
            * Quote the specific malicious parts of the log snippet that act as Indicators of Compromise (IoCs).
            * Explain the attacker's likely goal with this specific payload.

        ## 3. Multi-Layer Hardening Recommendations
            * Provide a prioritized list of specific, actionable steps to mitigate this threat.
            * **Web Server Layer (Nginx/WAF):** Suggest specific Nginx configuration changes or ModSecurity-style WAF rules to block this pattern at the edge.
            * **Application Layer:** Describe the necessary code changes (e.g., "Use parameterized queries/prepared statements to prevent SQLi," or "Implement context-aware output encoding for all user-supplied data to prevent XSS").
            * **Network Layer:** Suggest relevant firewall rules if applicable (e.g., "Block the attacking IP address `123.45.67.89` at the network firewall").

        ## 4. Incident Response Next Steps
            * Provide a short, actionable checklist of immediate steps the user should take. For example:
                * Investigate other logs from the same source IP address.
                * Check if the attack was successful by looking for unusual database activity or defaced pages.
                * Scan the application for similar vulnerabilities.

        ## 5. Further Reading
            * Based on the threat, provide 2-3 high-quality reference links to authoritative sources that describe the attack. Use the following links as your source of truth:
                * SQL Injection: `https://owasp.org/www-community/attacks/SQL_Injection`
                * Cross-Site Scripting (XSS): `https://owasp.org/www-community/attacks/xss/`
                * Path Traversal: `https://owasp.org/www-community/attacks/Path_Traversal`
        """
        PROMPT = PromptTemplate(template=prompt_template, input_variables=["context", "question"])

        rag_chain = RetrievalQA.from_chain_type(
            llm=llm,
            chain_type="stuff",
            retriever=retriever,
            chain_type_kwargs={"prompt": PROMPT},
            return_source_documents=True,
        )
        return llm, rag_chain, None

    except Exception as e:
        error_details = f"ERROR DETAILS: {e}"
        print(f"🚨 FATAL ERROR DURING RAG PIPELINE INITIALIZATION 🚨\n{error_details}")
        return None, None, str(e)


def create_and_save_new_index(embeddings: Any) -> FAISS:
    """Creates a new FAISS index from a base knowledge base and saves it."""
    print(f"No FAISS index found. Creating a new one at: {FAISS_INDEX_PATH}")
    knowledge_base = [
        Document(page_content="SQL Injection (SQLi) indicators include ' or 1=1, UNION SELECT.", metadata={"source": "OWASP-SQLi"}),
        Document(page_content="Cross-Site Scripting (XSS) indicators include <script>, onerror=, javascript:.", metadata={"source": "OWASP-XSS"}),
        Document(page_content="Path Traversal indicators are '../' or '..\\' sequences.", metadata={"source": "OWASP-PathTraversal"}),
        Document(page_content="Reconnaissance scanning can be identified by user agents like Nmap or Nikto.", metadata={"source": "Scanning-Tools"}),
    ]
    vector_store = FAISS.from_documents(knowledge_base, embeddings)
    os.makedirs(FAISS_INDEX_PATH, exist_ok=True)
    vector_store.save_local(FAISS_INDEX_PATH)
    print("New FAISS index created and saved successfully.")
    return vector_store


def analyze_log_data(log_content: str, rag_chain: Any) -> Dict[str, Any]:
    """Main analysis function receives the rag_chain as an argument."""
    if not rag_chain:
        return {"summary": "## Analysis Failed\n\n**Reason:** RAG chain is not available."}

    question_snippet = "\n".join(log_content.strip().splitlines()[:10])
    try:
        result = rag_chain.invoke({"query": question_snippet})
        retrieved_sources = [doc.metadata.get("source", "Unknown Source") for doc in result.get("source_documents", [])]
        return {
            "summary": result.get("result", "No summary provided."),
            "details": {"retrieved_sources": retrieved_sources},
        }
    except Exception as e:
        return {"summary": f"## AI Analysis Error\n\n**Error:** {e}", "details": {}}