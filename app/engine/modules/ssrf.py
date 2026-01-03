from app.engine.modules.base import BaseVulnerability

class SSRFModule(BaseVulnerability):
    async def check(self, url, method, param, scan_id):
        payloads = [
            "http://127.0.0.1:80",
            "http://localhost:22",
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd",
            "file:///c:/windows/win.ini"
        ]

        for payload in payloads:
            target_url = url
            if method == "GET":
                if "?" in url:
                    target_url = f"{url}&{param}={payload}"
                else:
                    target_url = f"{url}?{param}={payload}"
                
                try:
                    async with self.session.get(target_url, allow_redirects=False, timeout=5) as resp:
                        text = await resp.text()
                        if "root:x:0:0" in text or "[extensions]" in text or "ami-id" in text:
                            self.report(scan_id, "SSRF Detected", "Critical", target_url, payload, f"Server fetched local/cloud resource: {payload}")
                            return
                except:
                    pass
            
            elif method == "POST":
                # Simple form replacement
                data = {param: payload}
                try:
                    async with self.session.post(url, data=data, allow_redirects=False, timeout=5) as resp:
                        text = await resp.text()
                        if "root:x:0:0" in text or "[extensions]" in text or "ami-id" in text:
                            self.report(scan_id, "SSRF Detected", "Critical", url, payload, f"Server fetched local/cloud resource: {payload}")
                            return
                except:
                    pass
