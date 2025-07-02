import requests
from typing import List, Dict, Any

def scan_website_headers(url: str) -> Dict:
    """
    Performs a passive scan of a website's HTTP security headers.
    This function does not use any AI models.
    """
    headers_to_check = {
        "Strict-Transport-Security": "Tells browsers to only use HTTPS.",
        "Content-Security-Policy": "Helps prevent XSS by defining allowed content sources.",
        "X-Frame-Options": "Protects against clickjacking attacks.",
        "X-Content-Type-Options": "Prevents MIME-sniffing.",
        "Referrer-Policy": "Enhances user privacy by controlling referrer information.",
        "Permissions-Policy": "Controls which browser features can be used.",
    }
    results = []
    try:
        # Add a scheme if missing for user convenience
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        response = requests.get(url, timeout=10)
        found_headers = {k.lower(): v for k, v in response.headers.items()}

        for header, explanation in headers_to_check.items():
            if header.lower() in found_headers:
                results.append({"name": header, "finding": "Present", "is_present": True})
            else:
                results.append({"name": header, "finding": "Missing", "is_present": False})

    except requests.RequestException as e:
        return {"error": str(e), "scan_results": []}

    return {"scan_results": results}


def get_ai_header_analysis(llm: Any, scan_results: List[Dict], target_url: str) -> Dict:
    """
    Sends scan results to the AI for analysis and remediation advice.
    This version uses an improved prompt for a more structured report.
    """
    if not llm:
        return {"ai_explanation": "AI model object was not provided to the function."}

    missing_headers = [item["name"] for item in scan_results if not item["is_present"]]
    if not missing_headers:
        return {"ai_explanation": "## ✅ All Recommended Security Headers Found!\n\nExcellent work. No remediation is needed at this time."}

    prompt = f"""
    As a cybersecurity expert, you are reviewing the security headers for the website: `{target_url}`.

    The following critical security headers are missing: **{', '.join(missing_headers)}**.

    Please provide a concise, actionable report in Markdown format. The report MUST have the following three sections:
    **Security Headers Summary:**

    ## 1. Overall Security Grade
    Assign a letter grade (A, B, C, D, or F) based on the number and importance of the missing headers and briefly explain your reasoning.

    ## 2. Impact of Missing Headers
    Briefly explain the security risk associated with each of the missing headers. Use bullet points for clarity.

    ## 3. Nginx Remediation Guide
    Provide a single, ready-to-use Nginx configuration code block with the correct `add_header` directives to fix all the missing headers.

    ## 4. Apache Remediation Guide
    Provide a single, ready-to-use Apache configuration code block with the correct `add_header` directives to fix all the missing headers. Or using .htaccess if applicable.
    """

    try:
        response = llm.invoke(prompt)
        ai_explanation = response.content if hasattr(response, 'content') else str(response)
        return {"ai_explanation": ai_explanation}
    except Exception as e:
        print(f"Error during AI header analysis invocation: {e}")
        return {"ai_explanation": f"An error occurred while communicating with the AI model: {e}"}