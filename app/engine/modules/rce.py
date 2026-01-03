from app.engine.modules.base import BaseVulnerability

class RCEModule(BaseVulnerability):
    def __init__(self, session):
        super().__init__(session)
        # Time-based checks are harder to do reliably without blocking, so we use echo/print checks
        self.payloads = [
            "; cat /etc/passwd", 
            "| cat /etc/passwd", 
            "`cat /etc/passwd`",
            "; type C:\\Windows\\win.ini",
            "| type C:\\Windows\\win.ini"
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
                                self.report(scan_id, "Remote Code Execution (RCE)", "Critical",
                                            f"{url}",
                                            f"Payload: {payload}\nSignature Match: {sig}",
                                            f"""
                                            <div class='space-y-2'>
                                                <p class='font-bold text-red-500'>CRITICAL: Remote Code Execution (RCE)</p>
                                                <p>The application executes operating system commands injected via the '<b>{param}</b>' parameter. This allows full server compromise.</p>
                                                <div class='bg-gray-800 p-2 rounded border border-gray-700 font-mono text-xs'>
                                                    GET {url}?{param}={payload} HTTP/1.1<br>
                                                    <span class='text-red-400'>Response contains: "{sig}"</span>
                                                </div>
                                                <p class='font-bold text-green-400 mt-2'>Remediation:</p>
                                                <ul class='list-disc list-inside text-sm'>
                                                    <li>Avoid using system calls (exec, system, passthru) with user input.</li>
                                                    <li>Use language-specific APIs instead of shell commands.</li>
                                                </ul>
                                            </div>
                                            """)
                                return
            except:
                pass
