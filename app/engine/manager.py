import asyncio
from app.engine.crawler import SmartCrawler
from app.engine.fuzzer import AutoFuzzer
from app.engine.port_scanner import PortScanner
from app.engine.discovery import ContentDiscoverer
from app.engine.db import create_scan, update_scan_status, get_scan_results, init_bounty_db
import sqlite3
import json

class BountyEngine:
    def __init__(self):
        init_bounty_db()

    async def start_scan(self, target_url):
        # 1. Create Scan Job
        scan_id = create_scan(target_url)
        
        # 2. Initialize Queue for Producer-Consumer
        self.asset_queue = asyncio.Queue()
        
        # Run async in background
        asyncio.create_task(self.run_workflow(scan_id, target_url))
        
        return scan_id

    async def run_workflow(self, scan_id, target_url):
        try:
            print(f"[{scan_id}] Starting Workflow for {target_url}...")
            
            # Phase 1: Network Recon (Port Scan)
            port_scanner = PortScanner(scan_id)
            await port_scanner.scan_target(target_url, on_found=self.asset_queue.put)
            
            # Phase 2: Web Recon & Pentest
            # Start Consumers (Fuzzers + Content Discovery)
            # We add a specialized Discovery worker alongside Fuzzers
            workers = []
            
            # 2 Fuzzer Workers (XSS/SQLi)
            for i in range(2):
                workers.append(asyncio.create_task(self.fuzzer_worker(scan_id, i)))
            
            # 1 Content Discovery Worker
            workers.append(asyncio.create_task(self.discovery_worker(scan_id)))
            
            # Start Producer (Crawler)
            crawler = SmartCrawler(target_url, scan_id, on_asset_found=self.asset_queue.put)
            await crawler.crawl()
            
            # Wait for queue to drain then cancel consumers
            await self.asset_queue.join()
            for w in workers: w.cancel()
            
            print(f"[{scan_id}] Scan completed.")
            update_scan_status(scan_id, "completed")

        except Exception as e:
            print(f"[{scan_id}] Scan Failed: {e}")
            update_scan_status(scan_id, "failed")

    async def discovery_worker(self, scan_id):
        discoverer = ContentDiscoverer(scan_id)
        while True:
            asset = await self.asset_queue.get()
            try:
                # Only brute-force directories or the root
                if asset['type'] in ['page', 'dir']:
                    await discoverer.scan_asset(asset['url'], on_found=self.asset_queue.put)
            except Exception as e:
                print(f"[Discovery] Error: {e}")
            finally:
                self.asset_queue.task_done()

    async def fuzzer_worker(self, scan_id, worker_id):
        fuzzer = AutoFuzzer(scan_id)
        while True:
            # Get asset from queue
            asset = await self.asset_queue.get()
            try:
                # print(f"[Worker {worker_id}] Fuzzing {asset['url']}...")
                await fuzzer.fuzz_asset(asset)
                            
            except Exception as e:
                print(f"[Worker {worker_id}] Error: {e}")
            finally:
                self.asset_queue.task_done()

    def get_status(self, scan_id):
        raw_results = get_scan_results(scan_id)
        if not raw_results or not raw_results['scan']:
            return {"error": "Scan not found"}

        # Format for Vis.js Graph
        nodes = []
        edges = []
        
        # Central Target Node
        target_url = raw_results['scan']['target']
        nodes.append({
            "id": "target", 
            "label": target_url, 
            "group": "target",
            "value": 20
        })

        # Asset Nodes
        for asset in raw_results['assets']:
            asset_id = f"asset_{asset['id']}"
            label = asset['url'].replace(target_url, "")
            if not label: label = "/"
            
            # Better Labeling for Ports/Dirs
            if asset['type'] == 'port':
                label = asset['url'] # e.g. domain:80 (HTTP)
            
            nodes.append({
                "id": asset_id,
                "label": label[:15] + "..." if len(label) > 15 else label,
                "group": asset['type'] if asset['type'] in ['port', 'dir', 'file'] else "asset",
                "title": f"{asset['type'].upper()}: {asset['url']}"
            })
            edges.append({
                "id": f"edge_target_{asset_id}", 
                "from": "target", 
                "to": asset_id
            })

        # Finding Nodes (Red)
        for finding in raw_results['findings']:
            finding_id = f"finding_{finding['id']}"
            # Try to link to asset, otherwise link to target
            parent_id = "target" 
            # Simple matching: if finding location is in assets
            for asset in raw_results['assets']:
                if asset['url'] == finding['location']:
                    parent_id = f"asset_{asset['id']}"
                    break
            
            severity_group = "finding"
            if finding['severity'].lower() == "critical": severity_group = "finding_critical"
            elif finding['severity'].lower() == "high": severity_group = "finding_high"
            elif finding['severity'].lower() == "medium": severity_group = "finding_medium"
            elif finding['severity'].lower() == "low": severity_group = "finding_low"

            nodes.append({
                "id": finding_id,
                "label": finding['vuln_type'][:15] + "..." if len(finding['vuln_type']) > 15 else finding['vuln_type'],
                "group": severity_group,
                "title": f"[{finding['severity']}] {finding['vuln_type']}",
                "level": finding['severity']
            })
            edges.append({
                "id": f"edge_{parent_id}_{finding_id}",
                "from": parent_id, 
                "to": finding_id
            })

        return {
            "scan": raw_results['scan'],
            "graph": {"nodes": nodes, "edges": edges},
            "findings": raw_results['findings'],
            "assets_count": len(raw_results['assets']),
            "findings_count": len(raw_results['findings'])
        }
