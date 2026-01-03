from app.engine.modules.base import BaseVulnerability

class CRLFModule(BaseVulnerability):
    def __init__(self, session):
        super().__init__(session)
        self.payloads = [
            "%0d%0aSet-Cookie:crlf=injection", 
            "%0d%0aX-Injected-Header:test"
        ]

    async def check(self, url, method, param, scan_id):
        for payload in self.payloads:
            try:
                if method == "GET":
                    target_url = f"{url}?{param}={payload}"
                    async with self.session.get(target_url, timeout=5) as resp:
                        # Check headers for injection
                        for k, v in resp.headers.items():
                            if k.lower() == "x-injected-header" or "crlf=injection" in str(resp.headers):
                                self.report(scan_id, "CRLF Injection (HTTP Response Splitting)", "High",
                                            f"{url}",
                                            f"Payload: {payload}",
                                            f"""
                                            <div class='space-y-2'>
                                                <p class='font-bold text-red-400'>Vulnerability Detected: CRLF Injection</p>
                                                <p>The application allows newline characters in input to be reflected in HTTP headers, enabling Response Splitting or Header Injection.</p>
                                                <div class='bg-gray-800 p-2 rounded border border-gray-700 font-mono text-xs'>
                                                    GET {url}?{param}={payload} HTTP/1.1<br>
                                                    <span class='text-red-400'>Set-Cookie: crlf=injection</span>
                                                </div>
                                                <p class='font-bold text-green-400 mt-2'>Remediation:</p>
                                                <ul class='list-disc list-inside text-sm'>
                                                    <li>Strip newline characters (CR/LF) from user input before using in headers.</li>
                                                    <li>Update web server/framework to latest version (most modern frameworks prevent this).</li>
                                                </ul>
                                            </div>
                                            """)
                                return
            except:
                pass
