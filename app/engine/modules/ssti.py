from app.engine.modules.base import BaseVulnerability

class SSTIModule(BaseVulnerability):
    def __init__(self, session):
        super().__init__(session)
        # Math injection is the classic check
        self.payloads = [
            "{{7*7}}", 
            "${7*7}", 
            "<%= 7*7 %>", 
            "#{7*7}"
        ]
        self.signature = "49"

    async def check(self, url, method, param, scan_id):
        for payload in self.payloads:
            try:
                if method == "GET":
                    target_url = f"{url}?{param}={payload}"
                    async with self.session.get(target_url, timeout=5) as resp:
                        text = await resp.text()
                        if self.signature in text and payload not in text: 
                            # If 49 is present but {{7*7}} is NOT, it was evaluated.
                            # (Simple heuristic, can be prone to false positives if 49 is naturally there, 
                            # but "payload not in text" helps rule out reflection)
                            self.report(scan_id, "Server-Side Template Injection (SSTI)", "High",
                                        f"{url}",
                                        f"Payload: {payload}\nResult: {self.signature}",
                                        f"""
                                        <div class='space-y-2'>
                                            <p class='font-bold text-red-400'>Vulnerability Detected: Template Injection (SSTI)</p>
                                            <p>The application evaluated a template expression injected into the '<b>{param}</b>' parameter. This often leads to RCE.</p>
                                            <div class='bg-gray-800 p-2 rounded border border-gray-700 font-mono text-xs'>
                                                GET {url}?{param}={payload} HTTP/1.1<br>
                                                <span class='text-red-400'>Response contains: "49" (Evaluated from 7*7)</span>
                                            </div>
                                            <p class='font-bold text-green-400 mt-2'>Remediation:</p>
                                            <ul class='list-disc list-inside text-sm'>
                                                <li>Use "Logic-less" templates (like Mustache).</li>
                                                <li>Sanitize input before passing to template engines.</li>
                                                <li>Sandboxing the template environment.</li>
                                            </ul>
                                        </div>
                                        """)
                            return
            except:
                pass
