from app.engine.modules.base import BaseVulnerability

class ProtoPollutionModule(BaseVulnerability):
    async def check(self, url, method, param, scan_id):
        # Client-Side / Server-Side Prototype Pollution
        # We try to inject a property into the prototype
        
        # Method 1: Query Params
        # ?__proto__[polluted]=true
        
        payloads = [
            ("__proto__[polluted]", "true"),
            ("constructor[prototype][polluted]", "true")
        ]

        for key_inject, value_inject in payloads:
            target_url = url
            if "?" in url:
                target_url = f"{url}&{key_inject}={value_inject}"
            else:
                target_url = f"{url}?{key_inject}={value_inject}"
            
            try:
                # We check if the response REFLECTS this property in a way that implies assignment
                # or if the application crashes/behaves oddly.
                # Ideally, we'd check a subsequent request, but stateless fuzzing is limited.
                # We look for reflection of the key in a JSON response.
                
                async with self.session.get(target_url, allow_redirects=False) as resp:
                    text = await resp.text()
                    # If the response is JSON and contains "polluted": "true", it might be reflected or polluted.
                    if '"polluted": "true"' in text or '"polluted":"true"' in text:
                         self.report(scan_id, "Prototype Pollution (Reflected)", "High", target_url, key_inject, "Property injected via prototype chain reflected in response.")
            except:
                pass
            
            if method == "POST":
                # JSON Body Injection
                # { "proto": { "polluted": true } }
                # This is harder to do with generic 'param' logic without parsing the original body structure.
                # We will try a flat injection if possible.
                data = {key_inject: value_inject}
                try:
                    async with self.session.post(url, data=data, allow_redirects=False) as resp:
                         text = await resp.text()
                         if '"polluted": "true"' in text or '"polluted":"true"' in text:
                             self.report(scan_id, "Prototype Pollution (Reflected)", "High", url, key_inject, "Property injected via prototype chain reflected in response.")
                except:
                    pass
