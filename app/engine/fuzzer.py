import aiohttp
import asyncio
import json
from app.engine.modules.xss import XSSModule
from app.engine.modules.sqli import SQLiModule
from app.engine.modules.lfi import LFIModule
from app.engine.modules.rce import RCEModule
from app.engine.modules.ssti import SSTIModule
from app.engine.modules.open_redirect import OpenRedirectModule
from app.engine.modules.crlf import CRLFModule
from app.engine.modules.ssrf import SSRFModule
from app.engine.modules.xxe import XXEModule
from app.engine.modules.proto_pollution import ProtoPollutionModule
from app.engine.modules.nosqli import NoSQLiModule
from app.engine.modules.ldap import LDAPModule

class AutoFuzzer:
    def __init__(self, scan_id, concurrency=10):
        self.scan_id = scan_id
        self.sem = asyncio.Semaphore(concurrency) # Rate Limiting / Safety Cap
        
    async def fuzz_asset(self, asset):
        url = asset['url']
        method = asset['method']
        params = asset.get('params')

        # Skip if no params (unless it's a specific path check)
        if not params or params == '[]':
            return

        if isinstance(params, list):
             param_list = params
        else:
            try:
                param_list = json.loads(params)
            except:
                param_list = []

        async with aiohttp.ClientSession() as session:
            # Instantiate all modules with the session
            # This architecture allows unlimited expansion by adding more classes here
            modules = [
                XSSModule(session),
                SQLiModule(session),
                LFIModule(session),
                RCEModule(session),
                SSTIModule(session),
                OpenRedirectModule(session),
                CRLFModule(session),
                SSRFModule(session),
                XXEModule(session),
                ProtoPollutionModule(session),
                NoSQLiModule(session),
                LDAPModule(session)
            ]
            
            tasks = []
            for param in param_list:
                for m in modules:
                    # Run safely within semaphore limits
                    tasks.append(self.run_safe(m.check, url, method, param, self.scan_id))
            
            if tasks:
                await asyncio.gather(*tasks)

    async def run_safe(self, func, *args):
        async with self.sem:
            try:
                await func(*args)
            except Exception as e:
                pass
