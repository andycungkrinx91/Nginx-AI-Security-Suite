import scrapy
from scrapy.spiders import Spider
from typing import Dict, List, Any, AsyncGenerator, Optional
from urllib.parse import urlparse
import traceback

# --- Refactored Form Interaction Logic ---

async def _handle_login_form(form_handle) -> str:
    """Attempts to fill a detected login form."""
    try:
        await form_handle.locator("input[type='text'], input[type='email']").first.fill("testuser@example.com")
        await form_handle.locator("input[type='password']").first.fill("fakepassword123!")
        return "Success: Attempted to fill login form."
    except Exception as e:
        return f"Info: Login form interaction failed. Error: {str(e)[:100]}"

async def _handle_search_form(form_handle) -> str:
    """Attempts to fill a detected search form."""
    try:
        await form_handle.locator("input[type='text'], input[type='search']").first.fill("security test query")
        return "Success: Submitted a test search query."
    except Exception as e:
        return f"Info: Search form interaction failed. Error: {str(e)[:100]}"

async def _handle_contact_form(form_handle) -> str:
    """Attempts to fill a detected contact/feedback form."""
    try:
        if await form_handle.locator("input[name*='name']").count() > 0:
            await form_handle.locator("input[name*='name']").first.fill("Test User")
        if await form_handle.locator("input[name*='email']").count() > 0:
            await form_handle.locator("input[name*='email']").first.fill("test.contact@example.com")
        if await form_handle.locator("textarea").count() > 0:
            await form_handle.locator("textarea").first.fill("This is a test message from a security scanner.")
        return "Success: Attempted to fill contact form."
    except Exception as e:
        return f"Info: Contact form interaction failed. Error: {str(e)[:100]}"

def _get_form_keywords(inputs: List[Dict[str, str]]) -> List[str]:
    """Extracts keywords from form input names and IDs for better matching."""
    keywords = set()
    for form_input in inputs:
        # Add words from 'name' and 'id' attributes to the keyword set
        for attr in ['name', 'id']:
            if form_input.get(attr):
                # Split by common delimiters and add to set
                parts = re.split(r'[_-]', form_input[attr].lower())
                keywords.update(parts)
    return list(keywords)

# --- End of Refactored Logic ---

import re # Add re import for the new helper function

class InteractiveSpider(Spider):
    """
    A hybrid spider that uses Scrapy for crawling and Playwright for rendering
    and actively interacting with login, search, and contact forms.
    """
    name = 'interactivespider'

    def __init__(self, start_url='', domain_to_check='', user_agent=None, max_pages=15, *args, **kwargs):
        super(InteractiveSpider, self).__init__(*args, **kwargs)
        self.start_urls = [start_url]
        self.domain_to_check = domain_to_check
        self.user_agent = user_agent
        self.max_pages = int(max_pages)
        self.crawled_pages = set()

    async def start(self):
        """
        This is the modern, asynchronous Scrapy entry point for spiders.
        It generates the initial requests to be crawled and is now async.
        """
        for url in self.start_urls:
            yield scrapy.Request(
                url,
                meta={
                    "playwright": True,
                    "playwright_include_page": True,
                    "playwright_context_args": {
                        "user_agent": self.user_agent,
                        "ignore_https_errors": True,
                    },
                },
                callback=self.parse,
                errback=self.errback_httpbin,
            )

    async def errback_httpbin(self, failure):
        self.logger.error(f"Request failed: {failure.request.url} - {failure.value}")
        yield {"error": f"Failed to download {failure.request.url}: {failure.value}"}

    async def parse(self, response):
        page = response.meta.get("playwright_page")
        try:
            if not page:
                raise Exception("Playwright page not found in response meta.")
            if len(self.crawled_pages) >= self.max_pages or response.url in self.crawled_pages:
                return

            await page.wait_for_load_state("networkidle", timeout=60000)
            self.crawled_pages.add(response.url)
            page_title = await page.title()
            
            forms_found = []
            for form_handle in await page.query_selector_all('form'):
                action = await form_handle.get_attribute('action') or ''
                method = await form_handle.get_attribute('method') or 'get'
                inputs_raw = await form_handle.evaluate("(form) => Array.from(form.querySelectorAll('input, textarea, select')).map(el => ({ tag: el.tagName.toLowerCase(), type: el.type, name: el.name, id: el.id }))")
                
                form_data = {
                    'action': response.urljoin(action), 
                    'method': method.lower(), 
                    'inputs': inputs_raw, 
                    'interaction_result': 'Form identified, but not a target for interaction.'
                }
                
                # Use the new helper to get more reliable keywords
                form_keywords = _get_form_keywords(inputs_raw)

                # Refactored logic to call helper functions
                if any(kw in form_keywords for kw in ["user", "login", "email", "pass", "pwd"]):
                    form_data['interaction_result'] = await _handle_login_form(form_handle)
                elif any(kw in form_keywords for kw in ["search", "query", "q"]):
                    form_data['interaction_result'] = await _handle_search_form(form_handle)
                elif any(kw in form_keywords for kw in ["message", "comment", "contact", "feedback"]):
                    form_data['interaction_result'] = await _handle_contact_form(form_handle)
                
                forms_found.append(form_data)
            
            links = await page.evaluate("() => Array.from(document.querySelectorAll('a')).map(a => a.href)")
            item = {
                'url': response.url, 
                'page_title': page_title, 
                'links_found': len(links), 
                'forms_found': forms_found
            }
            yield item

            for link in links:
                if len(self.crawled_pages) >= self.max_pages:
                    break
                absolute_url = response.urljoin(link)
                if self.domain_to_check in urlparse(absolute_url).netloc and absolute_url not in self.crawled_pages:
                    yield scrapy.Request(
                        absolute_url,
                        meta={"playwright": True, "playwright_include_page": True, "playwright_context_args": {"user_agent": self.user_agent}},
                        callback=self.parse,
                        errback=self.errback_httpbin,
                    )
        except Exception:
            error_details = traceback.format_exc()
            self.logger.error(f"An error occurred while parsing {response.url}:\n{error_details}")
            yield {"error": f"Failed to parse {response.url}. Details: {error_details}"}
        finally:
            if page and not page.is_closed():
                await page.close()