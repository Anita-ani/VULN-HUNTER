# Vuln Hunter Enterprise 🛡️

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.95%2B-009688?style=for-the-badge&logo=fastapi)
![AsyncIO](https://img.shields.io/badge/Async-Powered-red?style=for-the-badge)
![Security](https://img.shields.io/badge/Security-Tooling-black?style=for-the-badge)

**Vuln Hunter Enterprise** is a next-generation, automated web vulnerability scanner and reconnaissance tool. It combines a powerful asynchronous fuzzing engine with an interactive, physics-based network graph visualization to help security researchers and bug bounty hunters identify critical vulnerabilities in real-time.

---

## ⚡ Why Vuln Hunter?

| Feature | Vuln Hunter | Traditional Scanners | Burp Suite |
| :--- | :---: | :---: | :---: |
| **Visual Recon** | ✅ **Live Graph** | ❌ List-based | ❌ Tree-based |
| **Architecture** | 🚀 **Async/Event-Driven** | 🐢 Threaded/Linear | 🐢 Threaded |
| **Extensibility**| 🧩 **Python Modules** | 🔒 Closed/Complex | 🧩 BApps (Java) |
| **Cost** | 💸 **Open Source** | 💰 $$$ | 💰 $$$ |

---

## 🎯 Who This Is For
*   **Bug Bounty Hunters**: Automate initial recon and finding discovery.
*   **AppSec Engineers**: Continuous scanning of internal assets.
*   **Red Teamers**: Rapid visualization of target infrastructure.
*   **Security Researchers**: Modular platform for testing new exploit vectors.

---

## 🚀 Key Features

### 🧠 Advanced Auto-Fuzzer
The core of Vuln Hunter is its modular, asynchronous fuzzing engine (`AutoFuzzer`). It concurrently tests for a wide range of critical vulnerabilities using "Fast & Premium" logic:

*   **OWASP Top 10 Coverage**:
    *   **SQL Injection (SQLi)**: Detects error-based and boolean-blind injections.
    *   **Cross-Site Scripting (XSS)**: Identifies reflected XSS vectors.
    *   **XML External Entity (XXE)**: Tests for local file inclusion via XML parsing.
    *   **Server-Side Request Forgery (SSRF)**: Checks for cloud metadata and local service exposure.
    *   **Insecure Deserialization**: Heuristically detected via RCE and object manipulation indicators (not full chain verification).
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

### 🌐 Interactive Graph Dashboard
*   **Visual Reconnaissance**: Real-time network graph visualization using Vis.js.
*   **Dynamic Discovery**: Nodes (Domains, Files, Parameters) appear instantly as they are crawled.
*   **Vulnerability Highlighting**: Found vulnerabilities are attached as red, pulsing nodes to their respective assets.
*   **Physics-Based UI**: Drag, zoom, and stabilize nodes for better analysis.

### 📊 Reporting & Management
*   **JSON Export**: Generate and download comprehensive scan reports with one click.
*   **Dashboard**: Monitor scan progress, asset count, and vulnerability stats live.
*   **Proof-of-Concept Retention**: (Planned) Reports include exact request/response evidence for validation.

---

## 🔮 Enterprise Roadmap (Planned)
To justify the "Enterprise" moniker and ensure scalability for professional environments, we are actively developing:

*   **🔐 Role-Based Access Control (RBAC)**: Multi-user environments with admin/viewer roles.
*   **💾 Scan Persistence**: PostgreSQL integration for long-term history and trend analysis.
*   **🛡️ Authentication**: API Key and OAuth2 support for secure deployment.
*   **🐳 Containerization**: Official Docker and Kubernetes Helm charts.
*   **📊 CVSS Scoring**: Automated severity scoring based on finding context.

---

## 🛠️ Architecture
*   **Frontend**: HTML5, TailwindCSS, Vis.js (Single Page Application).
*   **Backend**: Python FastAPI (High-performance Async I/O).
*   **Engine**: `aiohttp` for concurrent fuzzing, modular plugin system.
*   **Proxy**: Integrated `mitmproxy` support for traffic interception (optional).

---

## 📦 Installation & Usage

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

---

## 🛡️ Disclaimer
This tool is for **educational and authorized testing purposes only**. Do not use this tool on systems you do not have explicit permission to test. The authors are not responsible for any misuse.

---
*Built with ❤️ for the Bug Bounty Community.*
