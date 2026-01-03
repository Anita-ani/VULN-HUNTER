from abc import ABC, abstractmethod
from app.engine.db import add_finding

class BaseVulnerability(ABC):
    def __init__(self, session):
        self.session = session

    @abstractmethod
    async def check(self, url, method, param, scan_id):
        """
        Perform vulnerability check.
        :param url: Target URL
        :param method: HTTP Method (GET/POST)
        :param param: Parameter name to test
        :param scan_id: Current Scan ID for reporting
        """
        pass

    def report(self, scan_id, title, severity, location, proof, description, 
               request_payload=None, response_data=None, detection_logic=None, confidence="Medium", impact=None):
        add_finding(scan_id, title, severity, location, proof, description, 
                    request_payload, response_data, detection_logic, confidence, impact)
