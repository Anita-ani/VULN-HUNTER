import sqlite3
from datetime import datetime

DB_NAME = "proxy_history.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS history
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  timestamp TEXT,
                  method TEXT,
                  url TEXT,
                  request_headers TEXT,
                  request_body TEXT,
                  response_status INTEGER,
                  response_headers TEXT,
                  response_body TEXT)''')
    conn.commit()
    conn.close()

def log_flow(flow):
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        
        req_headers = dict(flow.request.headers)
        res_headers = dict(flow.response.headers) if flow.response else {}
        
        c.execute('''INSERT INTO history 
                     (timestamp, method, url, request_headers, request_body, 
                      response_status, response_headers, response_body)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                  (datetime.now().isoformat(),
                   flow.request.method,
                   flow.request.url,
                   str(req_headers),
                   flow.request.content.decode('utf-8', 'ignore') if flow.request.content else "",
                   flow.response.status_code if flow.response else 0,
                   str(res_headers),
                   flow.response.content.decode('utf-8', 'ignore') if flow.response and flow.response.content else ""))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error logging flow: {e}")
