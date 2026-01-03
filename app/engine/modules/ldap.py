from app.engine.modules.base import BaseVulnerability

class LDAPModule(BaseVulnerability):
    async def check(self, url, method, param, scan_id):
        # LDAP Injection Payloads
        payloads = [
            "*",
            ")(&",
            ")(|(&",
            "admin*)((|userpassword=*)",
            "*)(uid=*))(|(uid=*"
        ]

        for payload in payloads:
            target_url = url
            if method == "GET":
                if "?" in url:
                    target_url = f"{url}&{param}={payload}"
                else:
                    target_url = f"{url}?{param}={payload}"
                
                try:
                    async with self.session.get(target_url, allow_redirects=False) as resp:
                        text = await resp.text()
                        if "LDAPException" in text or "com.sun.jndi.ldap" in text:
                            self.report(scan_id, "LDAP Injection", "High", target_url, payload, "LDAP Error detected in response.")
                except:
                    pass
            
            elif method == "POST":
                data = {param: payload}
                try:
                    async with self.session.post(url, data=data, allow_redirects=False) as resp:
                        text = await resp.text()
                        if "LDAPException" in text or "com.sun.jndi.ldap" in text:
                            self.report(scan_id, "LDAP Injection", "High", url, payload, "LDAP Error detected in response.")
                except:
                    pass
