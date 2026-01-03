from playwright.async_api import async_playwright
from urllib.parse import urlparse, parse_qs
import asyncio
import re
from app.engine.db import add_asset

class SmartCrawler:
    def __init__(self, target_url, scan_id, on_asset_found=None):
        self.target_url = target_url
        self.scan_id = scan_id
        self.visited = set()
        self.scope_domain = urlparse(target_url).netloc
        self.on_asset_found = on_asset_found

    async def _report_asset(self, url, type, method="GET", params=None):
        params_list = params or []
        add_asset(self.scan_id, url, type, method, params_list)
        if self.on_asset_found:
            asset_data = {
                "scan_id": self.scan_id,
                "url": url,
                "type": type,
                "method": method,
                "params": params_list # Pass list directly, no JSON string here
            }
            if asyncio.iscoroutinefunction(self.on_asset_found):
                await self.on_asset_found(asset_data)
            else:
                self.on_asset_found(asset_data)

    def is_in_scope(self, url):
        try:
            parsed = urlparse(url)
            # 1. Subdomain Lock (Strict)
            if not (parsed.netloc == self.scope_domain or parsed.netloc.endswith("." + self.scope_domain)):
                return False
            
            # 2. Safety Controls (Auth/Destructive Action Protection)
            # Prevent crawler from hitting logout or delete endpoints
            risk_keywords = ['logout', 'signout', 'logoff', 'delete', 'destroy', 'remove']
            if any(k in url.lower() for k in risk_keywords):
                return False
                
            return True
        except:
            return False

    async def crawl(self):
        async with async_playwright() as p:
            # Launch browser with security disabled to find more issues
            browser = await p.chromium.launch(headless=True, args=['--no-sandbox'])
            context = await browser.new_context(ignore_https_errors=True)
            page = await context.new_page()

            # Hook into network requests to find API endpoints
            page.on("request", self.handle_request)
            
            try:
                # 1. Initial Navigation
                if not self.is_in_scope(self.target_url):
                    print("Target out of scope!")
                    return

                await page.goto(self.target_url, timeout=30000, wait_until="networkidle")
                await self.extract_page_data(page)

                # 2. Find internal links and crawl deeper (BFS limited depth)
                # For this demo, we do a shallow crawl (1-depth) to be fast
                links = await page.evaluate("""
                    () => Array.from(document.querySelectorAll('a')).map(a => a.href)
                """)
                
                # Filter by Scope and Visited
                unique_links = set([l for l in links if self.is_in_scope(l)])
                
                for link in list(unique_links)[:10]: # Limit to 10 for demo speed
                    if link not in self.visited:
                        try:
                            await page.goto(link, timeout=10000)
                            await self.extract_page_data(page)
                        except:
                            pass

            except Exception as e:
                print(f"Crawl error: {e}")
            finally:
                await browser.close()

    async def handle_request(self, request):
        # Capture API calls (XHR/Fetch)
        if request.resource_type in ["xhr", "fetch"]:
            url = request.url
            if self.is_in_scope(url):
                params = list(parse_qs(urlparse(url).query).keys())
                await self._report_asset(url, "api", request.method, params)

    async def extract_page_data(self, page):
        url = page.url
        if url in self.visited:
            return
        self.visited.add(url)
        
        # Log the page itself
        params = list(parse_qs(urlparse(url).query).keys())
        await self._report_asset(url, "page", "GET", params)

        # Extract Forms/Inputs (Potential Injection Points)
        inputs = await page.evaluate("""
            () => Array.from(document.querySelectorAll('input, textarea')).map(i => ({
                name: i.name || i.id,
                type: i.type
            }))
        """)
        
        if inputs:
            param_names = [i['name'] for i in inputs if i['name']]
            if param_names:
                await self._report_asset(url, "form", "POST", param_names)

        # Extract JS files for secret scanning
        scripts = await page.evaluate("""
            () => Array.from(document.querySelectorAll('script')).map(s => s.src).filter(s => s)
        """)
        for script in scripts:
            if self.scope_domain in script:
                await self._report_asset(script, "script", "GET")
