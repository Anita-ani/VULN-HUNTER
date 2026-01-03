import asyncio
import socket
from app.engine.db import add_asset, add_finding
from urllib.parse import urlparse

class PortScanner:
    def __init__(self, scan_id):
        self.scan_id = scan_id
        self.common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 
            53: "DNS", 80: "HTTP", 443: "HTTPS", 
            110: "POP3", 143: "IMAP", 445: "SMB", 
            3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 
            6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
        }

    async def check_port(self, host, port):
        try:
            fut = asyncio.open_connection(host, port)
            try:
                reader, writer = await asyncio.wait_for(fut, timeout=1.5)
                # If connected, get banner if possible
                banner = ""
                try:
                    # Send a simple probe
                    writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                    await writer.drain()
                    data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                    banner = data.decode('utf-8', errors='ignore').split('\n')[0].strip()
                except:
                    pass
                finally:
                    writer.close()
                    await writer.wait_closed()
                return port, True, banner
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return port, False, None
        except:
            return port, False, None

    async def scan_target(self, target_url, on_found=None):
        domain = urlparse(target_url).netloc
        if ":" in domain:
            domain = domain.split(":")[0]

        print(f"[*] Starting Port Scan on {domain}...")
        
        tasks = [self.check_port(domain, port) for port in self.common_ports.keys()]
        results = await asyncio.gather(*tasks)

        for port, is_open, banner in results:
            if is_open:
                service = self.common_ports.get(port, "Unknown")
                label = f"{domain}:{port} ({service})"
                
                # Report as Asset
                add_asset(self.scan_id, label, "port", "TCP", [banner if banner else ""])
                
                if on_found:
                    # Notify UI
                    data = {
                        "scan_id": self.scan_id,
                        "url": label,
                        "type": "port",
                        "method": "TCP",
                        "params": [banner]
                    }
                    if asyncio.iscoroutinefunction(on_found):
                        await on_found(data)
                    else:
                        on_found(data)

                # Heuristic Vuln Checks based on Ports
                if port == 21:
                    add_finding(self.scan_id, "Insecure Service", "Medium", label, 
                                "FTP Port 21 is Open", "FTP transmits data in cleartext. Consider using SFTP.")
                elif port == 23:
                    add_finding(self.scan_id, "Insecure Service", "High", label, 
                                "Telnet Port 23 is Open", "Telnet is unencrypted and vulnerable to sniffing. Use SSH.")
