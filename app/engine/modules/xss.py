from app.engine.modules.base import BaseVulnerability

class XSSModule(BaseVulnerability):
    def __init__(self, session):
        super().__init__(session)
        self.payloads = [
            '"><script>alert(1)</script>', 
            '<img src=x onerror=alert(1)>',
            'javascript:alert(1)//',
            '<svg/onload=alert(1)>'
        ]

    async def check(self, url, method, param, scan_id):
        for payload in self.payloads:
            try:
                if method == "GET":
                    target_url = f"{url}?{param}={payload}"
                    async with self.session.get(target_url, timeout=5) as resp:
                        text = await resp.text()
                        if payload in text:
                            self.report(scan_id, "Reflected XSS", "High", 
                                        f"{url}", 
                                        f"Payload: {payload}\nParam: {param}",
                                        f"""
                                        <div class='space-y-2'>
                                            <p class='font-bold text-red-400'>Vulnerability Detected: Reflected Cross-Site Scripting (XSS)</p>
                                            <p>The application reflects user input from the '<b>{param}</b>' parameter without proper sanitization. This allows an attacker to inject malicious JavaScript.</p>
                                            <div class='bg-gray-800 p-2 rounded border border-gray-700 font-mono text-xs'>
                                                GET {url}?{param}={payload} HTTP/1.1
                                            </div>
                                            <p class='font-bold text-green-400 mt-2'>Remediation:</p>
                                            <ul class='list-disc list-inside text-sm'>
                                                <li>Implement Context-Aware Output Encoding (e.g., HTML entity encoding).</li>
                                                <li>Use Content Security Policy (CSP) to restrict script execution.</li>
                                                <li>Validate and sanitize all input on the server side.</li>
                                            </ul>
                                        </div>
                                        """)
                            return # Stop after one finding per param to avoid noise
            except:
                pass
