import json
import os
import time
import traceback
from pathlib import Path
import multiprocessing

from scrapy.crawler import CrawlerProcess
from scrapy.signalmanager import dispatcher
from scrapy import signals

from app.scraper import InteractiveSpider
from app.analysis import initialize_rag_pipeline # Pastikan impor ini benar

# --- Konfigurasi Antrian Berbasis File ---
JOBS_DIR = Path("file_queue/jobs")
RESULTS_DIR = Path("file_queue/results")
ARCHIVE_DIR = Path("file_queue/archive") # Consolidated archive directory
JOBS_DIR.mkdir(parents=True, exist_ok=True)
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)

def run_crawl(job_data: dict):
    job_id = job_data["job_id"]
    results_file = RESULTS_DIR / f"{job_id}.json"
    scraped_results = []

    def item_scraped(item, response, spider):
        scraped_results.append(dict(item))

    dispatcher.connect(item_scraped, signal=signals.item_scraped)

    try:
        with open(results_file, 'w') as f:
            json.dump({"status": "processing", "message": "Stage 1 of 3: Crawler is running..."}, f)
        
        process = CrawlerProcess(settings={
            "LOG_LEVEL": "INFO",
            "TWISTED_REACTOR": "twisted.internet.asyncioreactor.AsyncioSelectorReactor",
            "SPIDER_MIDDLEWARES": {'scrapy.spidermiddlewares.offsite.OffsiteMiddleware': None},
            "DOWNLOAD_HANDLERS": {
                "http": "scrapy_playwright.handler.ScrapyPlaywrightDownloadHandler",
                "https": "scrapy_playwright.handler.ScrapyPlaywrightDownloadHandler",
            },
            "PLAYWRIGHT_LAUNCH_OPTIONS": {"args": ["--no-sandbox"], "headless": True},
            "PLAYWRIGHT_DEFAULT_NAVIGATION_TIMEOUT": 60000,
        })
        
        process.crawl(InteractiveSpider, **job_data)
        process.start()
        
        dispatcher.disconnect(item_scraped, signal=signals.item_scraped)

        errors = [item for item in scraped_results if "error" in item]
        if errors:
            raise Exception(f"Crawler finished with errors: {errors[0]['error']}")

        final_results = [item for item in scraped_results if "error" not in item]
        if not final_results:
            raise Exception("Crawler did not find any data.")

        # --- Tahap Analisis AI ---
        with open(results_file, 'w') as f:
            json.dump({"status": "processing", "message": "Stage 2 of 3: Generating AI Analysis..."}, f)

        # Initialize the AI model inside the child process for resource safety.
        # This prevents state corruption between different scan jobs.
        llm, _, startup_error = initialize_rag_pipeline()
        if startup_error:
            raise Exception(f"AI model failed to initialize in worker process: {startup_error}")

        total_pages = len(final_results)
        pages_with_forms = sum(1 for page in final_results if page.get("forms_found"))
        
        interaction_attempts = []
        for page in final_results:
            for form in page.get("forms_found", []):
                if "Success:" in form.get("interaction_result", ""):
                    interaction_attempts.append(form['interaction_result'])
        
        interaction_summary = "No successful form interactions were recorded."
        if interaction_attempts:
            interaction_summary = f"The scanner automatically interacted with {len(interaction_attempts)} form(s)."

        user_agent = job_data.get('user_agent', 'N/A')
        # Menggunakan templat yang Anda berikan
        summary_for_ai = (
            f"A web crawl was performed on the domain '{job_data['domain_to_check']}'.\n"
            f"- Total pages discovered: {total_pages}.\n"
            f"- Pages containing one or more forms: {pages_with_forms}.\n"
            f"- Automated Interaction Summary: {interaction_summary}\n"
            f"- User-Agent used for scan: `{user_agent}`"
        )
        
        prompt = f"""You are an expert security analyst with 10 years of experience defending against global hacking threats. You have been provided with the results of a web crawl.

        **Crawl Summary:**
        {summary_for_ai}

        **Instructions:**
        Based on the summary, write a professional security assessment in Markdown format.
        - **Do not** include a title, date, or subject line. The report will be embedded in a document that already has these elements.
        - Begin the report directly with the first section heading.

        The report must include these sections:
        1.  **## Potential Attack Surface:** Analyze the findings, such as the number and type of forms discovered, as a potential vector for attacks like SQL injection, XSS, or credential stuffing.
        2.  **## Recommended Actions:** Suggest concrete next steps for a security administrator based on the attack surface. For example, recommend penetration testing on identified forms, reviewing input validation, or ensuring rate limiting is in place.
        3.  **## Defending Against Malicious Scrapers:** Provide general advice on how to identify and block malicious bots and scrapers, referencing the User-Agent that was used for this scan.
        """
        
        response = llm.invoke(prompt)
        ai_analysis = response.content if hasattr(response, 'content') else str(response)
        
        # --- Tahap Finalisasi ---
        with open(results_file, 'w') as f:
            json.dump({"status": "processing", "message": "Stage 3 of 3: Finalizing report..."}, f)
        
        final_report = {"ai_analysis": ai_analysis, "raw_scrape_results": final_results}
        
        with open(results_file, 'w') as f:
            json.dump({"status": "complete", "result": final_report}, f)

    except Exception as e:
        error_message = f"Job {job_id} failed: {e}"
        print(error_message)
        with open(results_file, 'w') as f:
            json.dump({"status": "failed", "error": str(e)}, f)

if __name__ == "__main__":
    print("🚀 Scraper worker started. Watching for jobs in ./file_queue/jobs/")
    while True:
        job_files = sorted(JOBS_DIR.glob("*.json"))
        if job_files:
            job_file = job_files[0]
            try:
                with open(job_file, 'r') as f:
                    job_data = json.load(f)

                # Run the crawl in a separate process to isolate the Twisted reactor.
                # This is necessary because the reactor cannot be restarted in the same process.
                job_id = job_data.get('job_id', 'unknown')
                print(f"✅ Received new job: {job_id}")

                # Using multiprocessing.Process ensures each Scrapy crawl runs in a clean,
                # isolated environment, preventing the "ReactorNotRestartable" error.
                process = multiprocessing.Process(target=run_crawl, args=(job_data,))
                process.start()
                process.join() # Wait for the crawl process to complete.

                print(f"🏁 Finished job: {job_id}.")
            except Exception as e:
                print(f"CRITICAL WORKER ERROR: Could not process job file {job_file}. Error: {e}")
            finally:
                # Archive the job file to the consolidated archive directory.
                try:
                    # Rename to avoid collision with the archived result file.
                    archive_path = ARCHIVE_DIR / f"{job_file.stem}.job.json"
                    job_file.rename(archive_path)
                    print(f"🗄️  Archived job file to: {archive_path}")
                except Exception as move_e:
                    print(f"ERROR: Could not move job file {job_file}. Deleting it. Error: {move_e}")
                    os.remove(job_file) # Fallback to deleting if move fails
        else:
            time.sleep(5)