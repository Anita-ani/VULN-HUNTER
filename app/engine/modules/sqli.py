from app.engine.modules.base import BaseVulnerability

class SQLiModule(BaseVulnerability):
    def __init__(self, session):
        super().__init__(session)
        self.payloads = ["'", "' OR '1'='1", '"', "') OR ('1'='1"]
        self.errors = [
            "syntax error", "mysql_fetch", "ORA-", "PostgreSQL", 
            "SQLite/JDBCDriver", "System.Data.SqlClient", "Unclosed quotation mark"
        ]

    async def check(self, url, method, param, scan_id):
        for payload in self.payloads:
            try:
                if method == "GET":
                    target_url = f"{url}?{param}={payload}"
                    async with self.session.get(target_url, timeout=5) as resp:
                        text = await resp.text()
                        for err in self.errors:
                            if err.lower() in text.lower():
                                self.report(scan_id, "SQL Injection", "Critical",
                                            f"{url}",
                                            f"Payload: {payload}\nError: {err}",
                                            f"""
                                            <div class='space-y-2'>
                                                <p class='font-bold text-red-500'>CRITICAL: SQL Injection (SQLi) Detected</p>
                                                <p>The application's database driver returned an error message indicating a syntax error in the SQL query. This confirms that the '<b>{param}</b>' parameter is directly concatenated into a SQL statement.</p>
                                                <div class='bg-gray-800 p-2 rounded border border-gray-700 font-mono text-xs'>
                                                    GET {url}?{param}={payload} HTTP/1.1<br>
                                                    <span class='text-red-400'>Response contains: "{err}"</span>
                                                </div>
                                                <p class='font-bold text-green-400 mt-2'>Remediation:</p>
                                                <ul class='list-disc list-inside text-sm'>
                                                    <li>Use Parameterized Queries (Prepared Statements) for ALL database access.</li>
                                                    <li>Use an ORM (Object Relational Mapper) that handles escaping automatically.</li>
                                                    <li>Never concatenate user input directly into SQL strings.</li>
                                                </ul>
                                            </div>
                                            """)
                                return
            except:
                pass
