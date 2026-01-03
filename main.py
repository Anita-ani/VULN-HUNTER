from fastapi import FastAPI, Request, Form, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from app.scanner import Scanner
from app.engine.manager import BountyEngine # New Enterprise Engine
import uvicorn
import os
import sqlite3
import requests
import ast

app = FastAPI(title="Bug Bounty Assistant Enterprise")
engine = BountyEngine()

# Create templates directory if it doesn't exist
if not os.path.exists("templates"):
    os.makedirs("templates")

templates = Jinja2Templates(directory="templates")

DB_NAME = "proxy_history.db"

def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

# --- Enterprise Auto-Scan Endpoints ---

@app.post("/scan/auto", response_class=JSONResponse)
async def start_auto_scan(target: str = Form(...)):
    scan_id = await engine.start_scan(target)
    return {"status": "started", "scan_id": scan_id}

@app.get("/scan/{scan_id}", response_class=JSONResponse)
async def get_scan_status(scan_id: int):
    results = engine.get_status(scan_id)
    return results

# --- Legacy & Proxy Endpoints ---

@app.post("/scan", response_class=HTMLResponse)
async def scan_target(request: Request, target: str = Form(...), custom_header: str = Form(None)):
    
    headers = {}
    if custom_header and ":" in custom_header:
        key, value = custom_header.split(":", 1)
        headers[key.strip()] = value.strip()

    scanner = Scanner(target, custom_headers=headers)
    results = scanner.run_all()
    return templates.TemplateResponse("index.html", {
        "request": request,
        "results": results,
        "target": target,
        "custom_header": custom_header
    })

# --- Proxy / Repeater Endpoints (REMOVED) ---

if __name__ == "__main__":
    # We will run this via start.py to include mitmproxy
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
