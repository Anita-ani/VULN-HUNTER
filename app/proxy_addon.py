import sys
import os

# Add the parent directory to sys.path so 'app' module can be found
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from mitmproxy import http
from app.db_logger import log_flow, init_db

# Initialize DB on startup
init_db()

class TrafficLogger:
    def response(self, flow: http.HTTPFlow):
        # We capture only when response is received to get full picture
        log_flow(flow)

addons = [TrafficLogger()]
