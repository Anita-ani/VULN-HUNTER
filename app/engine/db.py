import sqlite3
import json
from datetime import datetime
from typing import List, Dict

DB_NAME = "bounty.db"

def init_bounty_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    
    # Scan Jobs Table
    c.execute('''CREATE TABLE IF NOT EXISTS scans
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  target TEXT,
                  status TEXT,
                  start_time TEXT,
                  end_time TEXT,
                  findings_count INTEGER)''')
                  
    # Assets Table (Discovered URLs, Subdomains)
    c.execute('''CREATE TABLE IF NOT EXISTS assets
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  scan_id INTEGER,
                  url TEXT,
                  type TEXT, -- page, api, script, image
                  method TEXT,
                  params TEXT, -- JSON list of detected params
                  FOREIGN KEY(scan_id) REFERENCES scans(id))''')

    # Findings Table (Vulnerabilities)
    c.execute('''CREATE TABLE IF NOT EXISTS findings
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  scan_id INTEGER,
                  vuln_type TEXT,
                  severity TEXT,
                  location TEXT, -- URL or Param
                  proof TEXT,
                  description TEXT,
                  request_payload TEXT,
                  response_data TEXT,
                  detection_logic TEXT,
                  confidence TEXT,
                  impact TEXT,
                  FOREIGN KEY(scan_id) REFERENCES scans(id))''')
    
    # Migration for existing DBs
    try:
        c.execute("ALTER TABLE findings ADD COLUMN request_payload TEXT")
        c.execute("ALTER TABLE findings ADD COLUMN response_data TEXT")
        c.execute("ALTER TABLE findings ADD COLUMN detection_logic TEXT")
        c.execute("ALTER TABLE findings ADD COLUMN confidence TEXT")
        c.execute("ALTER TABLE findings ADD COLUMN impact TEXT")
    except:
        pass
                  
    conn.commit()
    conn.close()

def create_scan(target):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("INSERT INTO scans (target, status, start_time, findings_count) VALUES (?, 'running', ?, 0)",
              (target, datetime.now().isoformat()))
    scan_id = c.lastrowid
    conn.commit()
    conn.close()
    return scan_id

def update_scan_status(scan_id, status):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    if status == "completed":
        c.execute("UPDATE scans SET status = ?, end_time = ? WHERE id = ?",
                  (status, datetime.now().isoformat(), scan_id))
    else:
        c.execute("UPDATE scans SET status = ? WHERE id = ?", (status, scan_id))
    conn.commit()
    conn.close()

def add_asset(scan_id, url, type, method="GET", params=None):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("INSERT INTO assets (scan_id, url, type, method, params) VALUES (?, ?, ?, ?, ?)",
              (scan_id, url, type, method, json.dumps(params or [])))
    conn.commit()
    conn.close()

def add_finding(scan_id, vuln_type, severity, location, proof, description, 
                request_payload=None, response_data=None, detection_logic=None, confidence="Medium", impact=None):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("""INSERT INTO findings 
                 (scan_id, vuln_type, severity, location, proof, description, 
                  request_payload, response_data, detection_logic, confidence, impact) 
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
              (scan_id, vuln_type, severity, location, proof, description, 
               request_payload, response_data, detection_logic, confidence, impact))
    
    # Update count
    c.execute("UPDATE scans SET findings_count = findings_count + 1 WHERE id = ?", (scan_id,))
    conn.commit()
    conn.close()

def get_scan_results(scan_id):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    scan = c.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    assets = c.execute("SELECT * FROM assets WHERE scan_id = ?", (scan_id,)).fetchall()
    findings = c.execute("SELECT * FROM findings WHERE scan_id = ?", (scan_id,)).fetchall()
    
    conn.close()
    return {
        "scan": dict(scan) if scan else None,
        "assets": [dict(row) for row in assets],
        "findings": [dict(row) for row in findings]
    }
