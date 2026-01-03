import requests
from bs4 import BeautifulSoup
import socket
from urllib.parse import urlparse

class Scanner:
    def __init__(self, target_url, custom_headers=None):
        self.target_url = target_url if target_url.startswith("http") else f"http://{target_url}"
        self.domain = urlparse(self.target_url).netloc
        self.custom_headers = custom_headers or {}
        self.results = {
            "recon": {},
            "vulnerabilities": [],
            "info": {}
        }

    def run_all(self):
        self.basic_recon()
        self.check_headers()
        self.check_robots()
        self.check_cors()
        return self.results

    def basic_recon(self):
        try:
            response = requests.get(self.target_url, headers=self.custom_headers, timeout=5)
            self.results["info"]["status_code"] = response.status_code
            self.results["info"]["server"] = response.headers.get("Server", "Unknown")
            
            # DNS Resolution
            try:
                ip = socket.gethostbyname(self.domain)
                self.results["info"]["ip_address"] = ip
            except Exception as e:
                self.results["info"]["ip_address"] = f"Failed to resolve: {str(e)}"
                
        except Exception as e:
            self.results["error"] = str(e)

    def check_headers(self):
        try:
            response = requests.get(self.target_url, headers=self.custom_headers, timeout=5)
            headers = response.headers
            
            # Security Headers to check
            security_headers = {
                "X-Frame-Options": "Protection against Clickjacking",
                "X-Content-Type-Options": "Prevents MIME-sniffing",
                "Strict-Transport-Security": "Enforces HTTPS (HSTS)",
                "Content-Security-Policy": "Mitigates XSS and Data Injection",
                "X-XSS-Protection": "Legacy XSS Filter"
            }

            for header, desc in security_headers.items():
                if header not in headers:
                    self.results["vulnerabilities"].append({
                        "type": "Missing Security Header",
                        "severity": "Low",
                        "detail": f"{header} is missing. {desc}"
                    })
                else:
                    self.results["recon"][header] = headers[header]
                    
            # Check for sensitive headers
            if "Server" in headers:
                self.results["vulnerabilities"].append({
                    "type": "Information Disclosure",
                    "severity": "Low",
                    "detail": f"Server header reveals technology: {headers['Server']}"
                })

            if "X-Powered-By" in headers:
                self.results["vulnerabilities"].append({
                    "type": "Information Disclosure",
                    "severity": "Low",
                    "detail": f"X-Powered-By header reveals technology: {headers['X-Powered-By']}"
                })

        except Exception as e:
            pass

    def check_robots(self):
        try:
            robots_url = f"{self.target_url}/robots.txt"
            response = requests.get(robots_url, headers=self.custom_headers, timeout=5)
            if response.status_code == 200:
                self.results["recon"]["robots.txt"] = "Found"
                # Check for sensitive paths in robots.txt
                sensitive_paths = ["admin", "login", "dashboard", "config", "backup"]
                for line in response.text.splitlines():
                    if "Disallow" in line:
                        for path in sensitive_paths:
                            if path in line:
                                self.results["vulnerabilities"].append({
                                    "type": "Sensitive Path in robots.txt",
                                    "severity": "Info",
                                    "detail": f"Found sensitive path in robots.txt: {line.strip()}"
                                })
            else:
                self.results["recon"]["robots.txt"] = "Not Found"
        except:
            self.results["recon"]["robots.txt"] = "Error checking"

    def check_cors(self):
        try:
            origin = "https://evil.com"
            headers = {"Origin": origin}
            # Merge custom headers with test headers
            headers.update(self.custom_headers)
            
            response = requests.get(self.target_url, headers=headers, timeout=5)
            
            aca_origin = response.headers.get("Access-Control-Allow-Origin")
            aca_creds = response.headers.get("Access-Control-Allow-Credentials")
            
            if aca_origin == origin:
                severity = "High" if aca_creds == "true" else "Medium"
                detail = f"Server reflects arbitrary Origin: {aca_origin}. Credentials allowed: {aca_creds}."
                if severity == "High":
                    detail += " Check for data exfiltration possibilities (Required for high impact)."
                
                self.results["vulnerabilities"].append({
                    "type": "CORS Misconfiguration",
                    "severity": severity,
                    "detail": detail
                })
            elif aca_origin == "*":
                 self.results["vulnerabilities"].append({
                    "type": "CORS Misconfiguration",
                    "severity": "Low",
                    "detail": "Wildcard (*) Access-Control-Allow-Origin found. (Public API?)"
                })
        except:
            pass
