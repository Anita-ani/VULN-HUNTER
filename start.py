import subprocess
import time
import sys
import os

def run_services():
    print("[*] Starting Bug Bounty Assistant...")

    # Start FastAPI Backend
    port = int(os.environ.get("PORT", 8000))
    print(f"[*] Launching Web Interface (FastAPI) on port {port}...")
    fastapi_process = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", str(port)],
        cwd=os.getcwd()
    )

    # Start Mitmproxy
    print("[*] Launching Proxy Server (Mitmproxy) on port 8081...")
    # We use mitmdump because we want to run headless and use our addon
    mitm_process = subprocess.Popen(
        ["mitmdump", "-s", "app/proxy_addon.py", "--listen-host", "0.0.0.0", "--listen-port", "8081", "--ssl-insecure"],
        cwd=os.getcwd()
    )

    print("\n[+] System is running!")
    print(f"    -> Web Dashboard: http://0.0.0.0:{port}")
    print("    -> Proxy Server:  127.0.0.1:8081")
    print("    -> Configure your browser/tools to use this proxy to capture traffic.")
    print("\nPress Ctrl+C to stop all services.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping services...")
        fastapi_process.terminate()
        mitm_process.terminate()
        print("[*] Done.")

if __name__ == "__main__":
    run_services()
