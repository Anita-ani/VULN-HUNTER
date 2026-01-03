from app.engine.modules.base import BaseVulnerability
import json

class NoSQLiModule(BaseVulnerability):
    async def check(self, url, method, param, scan_id):
        # NoSQL Injection Payloads
        # Often relies on passing JSON objects or special operators
        
        payloads = [
            '{"$ne": null}',
            '{"$gt": ""}',
            '{"$where": "sleep(1000)"}' # Timing attack (simplified)
        ]

        for payload in payloads:
            # 1. GET Param (PHP/Node sometimes parses array syntax like param[$ne]=null)
            # URL Encoded: param[$ne]=null
            
            # Simple bypass attempt: param[$ne]=random_impossible_val
            
            target_url = url
            # Construct array-like param
            # ?param[$ne]=godzilla
            
            injection_key = f"{param}[$ne]"
            injection_val = "godzilla"
            
            if "?" in url:
                target_url = f"{url}&{injection_key}={injection_val}"
            else:
                target_url = f"{url}?{injection_key}={injection_val}"
                
            try:
                async with self.session.get(target_url, allow_redirects=False) as resp:
                    # If we get a 200 OK and different content length than normal, it's suspicious.
                    # But we need a baseline. For now, we look for explicit errors or obvious bypasses.
                    text = await resp.text()
                    if "MongoError" in text or "ReferenceError" in text:
                         self.report(scan_id, "NoSQL Injection Error", "High", target_url, injection_key, "Database error returned: Possible NoSQL Injection.")
            except:
                pass

            if method == "POST":
                # JSON Body Injection is most common for NoSQL
                # We try to send a JSON body where the param is an object
                try:
                    # payload_obj = {param: {"$ne": "godzilla"}}
                    json_payload = {param: {"$ne": "godzilla"}}
                    
                    async with self.session.post(url, json=json_payload, allow_redirects=False) as resp:
                         text = await resp.text()
                         # If it logs us in or shows data, we might see changes.
                         # Error detection:
                         if "MongoError" in text or "ReferenceError" in text:
                             self.report(scan_id, "NoSQL Injection Error", "High", url, str(json_payload), "Database error returned: Possible NoSQL Injection.")
                except:
                    pass
