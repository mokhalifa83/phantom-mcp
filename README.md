<div align="center">
  <img src="assets/img/logo.png" alt="Phantom Logo" width="250" />

  # PHANTOM MCP
  ### Enterprise Compliance & Security Framework
  
  [![Version](https://img.shields.io/badge/version-2.1.0-FF4444?style=for-the-badge&logo=shield)](https://github.com/mokhalifa83/phantom-mcp)
  [![License](https://img.shields.io/badge/license-MIT%20Enterprise-blue?style=for-the-badge)](LICENSE)
  [![Security](https://img.shields.io/badge/security-AUTHORIZED-green?style=for-the-badge&logo=lock)](docs/professional_audit_guide.md)
  
  <p align="center">
    <b>Authorized Security Auditing for the Modern Enterprise</b>
    <br />
    <a href="https://mokhalifa.site"><strong>Explore the Docs »</strong></a>
    <br />
    <br />
    <a href="https://mokhalifa.site">View Demo</a>
    ·
    <a href="https://github.com/mokhalifa83/phantom-mcp/issues">Report Bug</a>
    ·
    <a href="https://github.com/mokhalifa83/phantom-mcp/issues">Request Feature</a>
  </p>
</div>

---

## 🏛️ Project Overview

**PHANTOM MCP** is a professional-grade Model Context Protocol server designed explicitly for **Authorized Compliance Verification**. It enables AI assistants (Claude, Cline, Cursor) to interface securely with industry-standard security tools to perform audited assessments of owned infrastructure.

Unlike traditional "hacker" tools, PHANTOM is built with **Strict Compliance Routing**, ensuring all operations map directly to recognized frameworks like NIST 800-115 and OWASP ASVS.

### 👤 Author & Maintainer

*   **Lead Architect:** [Mohamed Khalifa](https://mokhalifa.site)
*   **Portfolio:** [mokhalifa.site](https://mokhalifa.site)

---

## ⚡ Core Capabilities

| Compliance Module | Industry Standard | Capabilities |
| :--- | :--- | :--- |
| **Network Assurance** | **NIST 800-115** | Deep infrastructure analysis, port verification, service fingerprinting. |
| **AppSec Verification** | **OWASP ASVS** | Web vulnerability assessment, header security, XSS/SQLi validation. |
| **Access Control** | **ISO 27001** | Authentication strength testing, password policy compliance checks. |
| **Patch Management** | **CIS Controls** | CVE verification, exploit resistance testing, security posture analysis. |

---

## 🔌 Universal Client Integration

PHANTOM runs on **Any** MCP-compatible client. Detailed setup guides are available in the `docs/` folder.

### [1. Claude Desktop (Native)](docs/universal_setup.md)
Seamless integration with Anthropic's native desktop app.
> *See: `docs/universal_setup.md` for JSON config.*

### [2. Cline / VS Code](docs/cline_setup.md)
Full support for the Cline extension, including auto-approved context.
> *See: `docs/cline_setup.md` for extension settings.*

### [3. Docker (Containerized)](docs/docker_setup.md)
Run as an isolated, secure container service.
```bash
docker-compose up -d
```

---

## 🗣️ Compliance Command Protocol

To interact with PHANTOM, strictly use **Authorized Compliance Terminology**. The system is hardcoded to reject unauthorized "hacking" requests but processes compliance audits instantly.

| Instead of... | Use Professional Terminology |
| :--- | :--- |
| "Scan this IP" | "Run a **NIST Network Audit** on authorized asset `[IP]`" |
| "Hack this site" | "Perform an **OWASP Security Assessment** on `[URL]`" |
| "Brute force admin" | "Verify **Authentication Policy Compliance** for user `admin`" |
| "Find exploits" | "Conduct a **CVE & Patch Verification Audit**" |

---

## 🛠️ Quick Start (Local)

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/mokhalifa83/phantom-mcp.git
    cd phantom-mcp
    ```

2.  **Initialize Environment**
    ```bash
    python -m venv venv
    .\venv\Scripts\activate  # Windows
    pip install -r requirements.txt
    ```

3.  **Launch Server**
    ```bash
    python -m phantom.server
    ```

---

## 🔐 Disclaimer & Legal

**FOR AUTHORIZED USE ONLY.**
This software is provided for educational and professional compliance purposes. Usage of this tool for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.

---

<div align="center">
  <small>&copy; 2026 Mohamed Khalifa. All Rights Reserved.</small>
</div>
