import aiohttp
import asyncio
from app.engine.db import add_asset, add_finding
from urllib.parse import urljoin

class ContentDiscoverer:
    def __init__(self, scan_id):
        self.scan_id = scan_id
        self.wordlist = [
            "admin", "login", "dashboard", "api", "backup", "config",
            ".env", ".git/HEAD", "robots.txt", "sitemap.xml",
            "backup.sql", "database.sql", "test", "dev", "staging",
            "wp-admin", "administrator", "manager", "console"
        ]

    async def scan_asset(self, target_url, on_found=None):
        # Only scan base URLs or directories, not files
        if target_url.endswith(('.png', '.jpg', '.css', '.js')):
            return

        # Ensure trailing slash for directory concatenation
        base_url = target_url if target_url.endswith('/') else target_url + '/'
        
        async with aiohttp.ClientSession() as session:
            tasks = []
            for path in self.wordlist:
                tasks.append(self.check_path(session, base_url, path, on_found))
            
            await asyncio.gather(*tasks)

    async def check_path(self, session, base_url, path, on_found):
        url = urljoin(base_url, path)
        try:
            async with session.get(url, timeout=3, allow_redirects=False) as resp:
                if resp.status in [200, 301, 302, 403]:
                    # Found something interesting
                    asset_type = "dir"
                    if "." in path: asset_type = "file"
                    
                    add_asset(self.scan_id, url, asset_type, "GET", [str(resp.status)])
                    
                    if on_found:
                         data = {
                            "scan_id": self.scan_id,
                            "url": url,
                            "type": asset_type,
                            "method": "GET",
                            "params": [str(resp.status)]
                        }
                         if asyncio.iscoroutinefunction(on_found):
                             await on_found(data)
                         else:
                             on_found(data)

                    # Vulnerability Checks
                    if path == ".env" and resp.status == 200:
                         add_finding(self.scan_id, "Critical Config Leak", "Critical", url, 
                                     "Exposed .env file", 
                                     f"""
                                     <div class='space-y-2'>
                                        <p class='font-bold text-red-500'>CRITICAL: .env File Exposed</p>
                                        <p>The application's environment configuration file is publicly accessible. This often contains database credentials, API keys, and secrets.</p>
                                        <div class='bg-gray-800 p-2 rounded border border-gray-700 font-mono text-xs'>
                                            GET {url} HTTP/1.1<br>
                                            <span class='text-green-400'>HTTP 200 OK</span>
                                        </div>
                                     </div>
                                     """)
                    elif path == ".git/HEAD" and resp.status == 200:
                        add_finding(self.scan_id, "Source Code Exposure", "High", url, 
                                     "Exposed .git directory", 
                                     "The .git repository is accessible. Attackers can download the entire source code history.")
        except:
            pass
