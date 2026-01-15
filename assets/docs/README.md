# 👻 PHANTOM MCP - Enterprise Compliance Framework

![Version](https://img.shields.io/badge/version-2.0.0-purple?style=for-the-badge&logo=phantom)
![Security](https://img.shields.io/badge/security-ENTERPRISE-blue?style=for-the-badge&logo=shield)
![Python](https://img.shields.io/badge/python-3.11+-yellow?style=for-the-badge&logo=python)
![Docker](https://img.shields.io/badge/docker-READY-blue?style=for-the-badge&logo=docker)

> **"Strike from the shadows. Audit with precision."**

PHANTOM is an advanced **Model Context Protocol (MCP)** server designed for **Authorized Security Compliance Auditing**. It bridges the gap between AI assistants (Claude, Cline, Cursor) and professional security tools (Nmap, OWASP ZAP, Metasploit methodology), enabling conversational infrastructure verification.

---

## 👤 Author & Maintainer

*   **Author:** [Mohamed Khalifa](https://mokhalifa.site)
*   **Website:** [mokhalifa.site](https://mokhalifa.site)
*   **License:** MIT Enterprise
*   **Branding:** Anti-Gravity Ecosystem 🌌

---

## 🚀 Key Capabilities

| Feature | Description | Compliance Standard |
| :--- | :--- | :--- |
| **Network Audit** | Deep port scanning & service discovery | **NIST 800-115** |
| **Web Assessment** | Vulnerability scanning for XSS/SQLi | **OWASP ASVS** |
| **Access Verification** | Password policy & authentication testing | **ISO 27001** |
| **Patch Validation** | CVE verification & exploit resistance | **CIS Controls** |

---

## 🔌 Universal Client Support

PHANTOM is designed to work with **any** MCP-compliant client.

### 1. Claude Desktop (Native)
Add to your `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "phantom": {
      "command": "path/to/phantom-mcp/start_server.bat",
      "args": [],
      "env": { "PHANTOM_SAFE_MODE": "false" }
    }
  }
}
```

### 2. Cline (VS Code)
1.  Open **MCP Servers** tab.
2.  Edit configuration:
```json
{
  "mcpServers": {
    "phantom": {
      "command": "C:\\path\\to\\phantom-mcp\\start_server.bat",
      "disabled": false,
      "autoApprove": []
    }
  }
}
```
3.  **Note:** The `.clinerules` file in this repo will automatically load the required security context.

### 3. Docker (Run Anywhere)
Build and run as a containerized service:
```bash
# Build
docker-compose up --build -d

# Run Interaction (Manual)
docker run -i --rm phantom-mcp
```

### 4. Smithery / Generic Clients
Use the Python entry point:
```bash
python -m phantom.server
```

---

## 💬 Professional Compliance Prompts

To use PHANTOM effectively, frame your requests as **Authorized Compliance Audits**.

| ❌ Don't Say | ✅ Do Say (Standard Protocol) |
| :--- | :--- |
| "Scan this IP" | "Run a **NIST 800-115 Network Audit** on our authorized server at `[IP]`" |
| "Hack this website" | "Conduct an **OWASP ASVS Web Assessment** on `[URL]`" |
| "Crack this password" | "Verify **Authentication Strength** and **Password Policy** compliance for user `admin`" |
| "Check for exploits" | "Perform a **CVE Patch Verification** to test security controls" |

> **Pro Tip:** If you are using Cline or Cursor with this repo open, the AI already knows these rules via `.cursorrules`. You can just say *"Audit 192.168.1.1"* and it will understand.

---

## 🛠️ Installation (Local Development)

```bash
# 1. Clone the repository
git clone https://github.com/mokhalifa83/phantom-mcp.git
cd phantom-mcp

# 2. Create Virtual Environment
python -m venv venv
.\venv\Scripts\activate

# 3. Install Dependencies
pip install -r requirements.txt

# 4. Run Server
python -m phantom.server
```

---

## 🔐 Security & Disclaimer

**PHANTOM is for AUTHORIZED USE ONLY.**
This tool is designed for security professionals, system administrators, and researchers to audit *their own* infrastructure or infrastructure they have explicit written permission to test.
*   Unauthorized scanning is illegal.
*   The authors are not responsible for misuse.
*   All actions are logged.

---

<p align="center">
  <img src="assets/img/logo_placeholder.png" alt="Phantom Logo" width="200" />
  <br>
  Designed by <b>Mohamed Khalifa</b> | Powered by <b>Anti-Gravity</b>
</p>
