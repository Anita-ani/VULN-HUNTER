# Vuln Hunter Enterprise 

**Vuln Hunter Enterprise** is a next-generation, automated web vulnerability scanner and reconnaissance tool. It combines a powerful asynchronous fuzzing engine with an interactive, physics-based network graph visualization to help security researchers and bug bounty hunters identify critical vulnerabilities in real-time.

##  Key Features

###  Advanced Auto-Fuzzer
The core of Vuln Hunter is its modular, asynchronous fuzzing engine (`AutoFuzzer`). It concurrently tests for a wide range of critical vulnerabilities using "Fast & Premium" logic:
*   **OWASP Top 10 Coverage**:
    *   **SQL Injection (SQLi)**: Detects error-based and boolean-blind injections.
    *   **Cross-Site Scripting (XSS)**: Identifies reflected XSS vectors.
    *   **XML External Entity (XXE)**: Tests for local file inclusion via XML parsing.
    *   **Server-Side Request Forgery (SSRF)**: Checks for cloud metadata and local service exposure.
    *   **Insecure Deserialization**: (Covered via RCE/Proto Pollution checks).
*   **Deep System Exploitation**:
    *   **Remote Code Execution (RCE)**: Scans for command injection flaws.
    *   **Local File Inclusion (LFI)**: Probes for path traversal and system file access.
    *   **Server-Side Template Injection (SSTI)**: Tests major template engines (Jinja2, Twig, etc.).
*   **Modern Web Flaws**:
    *   **Prototype Pollution**: Client-side and server-side prototype chain injection.
    *   **NoSQL Injection**: MongoDB/NoSQL specific query operator injection.
    *   **LDAP Injection**: Directory service query manipulation.
    *   **Open Redirects**: Unvalidated redirect destinations.
    *   **CRLF Injection**: HTTP response splitting checks.

###  Interactive Graph Dashboard
*   **Visual Reconnaissance**: Real-time network graph visualization using Vis.js.
*   **Dynamic Discovery**: Nodes (Domains, Files, Parameters) appear instantly as they are crawled.
*   **Vulnerability Highlighting**: Found vulnerabilities are attached as red, pulsing nodes to their respective assets.
*   **Physics-Based UI**: Drag, zoom, and stabilize nodes for better analysis.

###  Reporting & Management
*   **JSON Export**: Generate and download comprehensive scan reports with one click.
*   **Dashboard**: Monitor scan progress, asset count, and vulnerability stats live.

##  Architecture
*   **Frontend**: HTML5, TailwindCSS, Vis.js (Single Page Application).
*   **Backend**: Python FastAPI (High-performance Async I/O).
*   **Engine**: `aiohttp` for concurrent fuzzing, modular plugin system.
*   **Proxy**: Integrated `mitmproxy` support for traffic interception (optional).

##  Installation & Usage

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/Anita-ani/VULN-HUNTER.git
    cd VULN-HUNTER
    ```

2.  **Install Dependencies**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Start the Platform**
    ```bash
    python start.py
    ```
    *   **Web Dashboard**: [http://127.0.0.1:8000](http://127.0.0.1:8000)
    *   **Proxy Server**: [http://127.0.0.1:8081](http://127.0.0.1:8081)

4.  **Start Scanning**
    *   Navigate to the dashboard.
    *   Enter a target URL (e.g., `http://testphp.vulnweb.com`).
    *   Watch the graph populate and vulnerabilities appear!

## 🛡️ Disclaimer
This tool is for **educational and authorized testing purposes only**. Do not use this tool on systems you do not have explicit permission to test. The authors are not responsible for any misuse.

---
*Built with ❤️ for the Bug Bounty Community.*
