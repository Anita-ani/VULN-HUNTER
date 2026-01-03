from app.engine.modules.base import BaseVulnerability

class OpenRedirectModule(BaseVulnerability):
    def __init__(self, session):
        super().__init__(session)
        self.payloads = [
            "https://google.com", 
            "//google.com", 
            "//google.com%2f%2e%2e", 
            "javascript:alert(1)"
        ]

    async def check(self, url, method, param, scan_id):
        for payload in self.payloads:
            try:
                if method == "GET":
                    # Check if param is likely a redirect param
                    if param.lower() not in ['next', 'url', 'target', 'r', 'dest', 'destination', 'redirect', 'redirect_uri', 'return', 'return_to']:
                        # Skip unlikely params to save time, or keep strict if user wants deep scan.
                        # For "unlimited" enterprise grade, let's scan everything but maybe prioritize known params.
                        pass
                    
                    target_url = f"{url}?{param}={payload}"
                    async with self.session.get(target_url, allow_redirects=False, timeout=5) as resp:
                        # Check for 3xx and Location header
                        if resp.status in [301, 302, 303, 307, 308]:
                            location = resp.headers.get("Location", "")
                            if "google.com" in location or "javascript:alert" in location:
                                self.report(scan_id, "Open Redirect", "Medium",
                                            f"{url}",
                                            f"Payload: {payload}\nLocation: {location}",
                                            f"""
                                            <div class='space-y-2'>
                                                <p class='font-bold text-orange-400'>Vulnerability Detected: Open Redirect</p>
                                                <p>The application redirects the user to an untrusted external domain via the '<b>{param}</b>' parameter.</p>
                                                <div class='bg-gray-800 p-2 rounded border border-gray-700 font-mono text-xs'>
                                                    GET {url}?{param}={payload} HTTP/1.1<br>
                                                    <span class='text-yellow-400'>HTTP {resp.status} Found</span><br>
                                                    <span class='text-red-400'>Location: {location}</span>
                                                </div>
                                                <p class='font-bold text-green-400 mt-2'>Remediation:</p>
                                                <ul class='list-disc list-inside text-sm'>
                                                    <li>Validate the redirect URL against a whitelist.</li>
                                                    <li>Force local redirects (e.g., ensure it starts with `/` but not `//`).</li>
                                                </ul>
                                            </div>
                                            """)
                                return
            except:
                pass
