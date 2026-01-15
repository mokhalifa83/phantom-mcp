# 👻 PHANTOM MCP - Usage Guide

## Getting Started

This guide will help you use PHANTOM MCP for authorized security testing.

## Starting the Server

```bash
# Activate virtual environment
source venv/bin/activate  # Windows: venv\Scripts\activate

# Start PHANTOM server
python -m phantom.server
```

## Using with Claude Desktop

Once configured in Claude Desktop, you can interact with PHANTOM through natural language:

### Example Conversations

**Basic Reconnaissance:**
```
"Scan example.com for open ports"
"Find subdomains for target.com"
"Gather OSINT information about example.com"
```

**Vulnerability Scanning:**
```
"Check https://example.com for web vulnerabilities"
"Test the API at https://api.example.com for security issues"
"Detect what CMS is running on example.com"
```

**Exploitation:**
```
"Search for exploits related to Apache 2.4.49"
"What exploits are available for WordPress 5.8?"
```

**Reporting:**
```
"Generate a security report for my recent scan"
"Create an HTML report with all findings"
```

## Available Tools

### 🔍 Reconnaissance

#### Port Scanning
```
Tool: port_scan
Purpose: Discover open ports and services

Usage: "Scan 192.168.1.1 for open ports"
       "Scan example.com ports 1-1000"
```

#### Subdomain Enumeration
```
Tool: subdomain_enum
Purpose: Find subdomains

Usage: "Find subdomains for example.com"
       "Enumerate subdomains using DNS and certificate transparency"
```

#### OSINT Gathering
```
Tool: osint_gather
Purpose: Collect open source intelligence

Usage: "Gather OSINT about example.com"
       "Search for data breaches for example.com"
```

### 🛡️ Vulnerability Scanning

#### Web Vulnerability Scan
```
Tool: web_vuln_scan
Purpose: Test web applications for OWASP Top 10

Usage: "Check https://example.com for vulnerabilities"
       "Scan example.com for XSS and SQL injection"
```

#### API Security Test
```
Tool: api_security_test
Purpose: Test API endpoints

Usage: "Test the REST API at https://api.example.com"
       "Check API authentication"
```

#### CMS Detection
```
Tool: cms_detect
Purpose: Identify and scan CMS platforms

Usage: "Detect CMS on example.com"
       "Check example.com for WordPress vulnerabilities"
```

### 💥 Exploitation

#### Exploit Search
```
Tool: exploit_search
Purpose: Find exploits in databases

Usage: "Search for Apache 2.4.49 exploits"
       "Find exploits for CVE-2021-41773"
```

#### ⚠️ Auto Exploitation (Disabled by default)
```
Tool: auto_exploit
Purpose: Automated exploitation

⚠️ DANGER: Requires explicit authorization and configuration
```

#### ⚠️ Password Attacks (Disabled by default)
```
Tool: password_attack
Purpose: Credential testing

⚠️ WARNING: Only use on systems you own or have authorization for
```

### 🎯 Post-Exploitation

#### Privilege Escalation Check
```
Tool: priv_esc_check
Purpose: Find privilege escalation vectors

Usage: "Check for Linux privilege escalation opportunities"
       "Find Windows privesc vectors"
```

### 📊 Reporting

#### Generate Report
```
Tool: generate_report
Purpose: Create professional security reports

Usage: "Generate an HTML security report"
       "Create a report with all findings"
```

## Best Practices

### 1. Always Get Authorization

✅ **DO:**
- Get written permission before testing
- Test only systems you own or are authorized to test
- Keep detailed records of authorization
- Follow scope defined in engagement

❌ **DON'T:**
- Test systems without permission
- Exceed authorized scope
- Test production systems without approval
- Use findings for malicious purposes

### 2. Use Safe Mode

PHANTOM includes a safe mode that prevents dangerous operations:

```yaml
# configs/phantom.yaml
security:
  safe_mode: true  # Keep enabled unless explicitly needed
```

### 3. Start with Passive Reconnaissance

Begin with non-intrusive techniques:
1. OSINT gathering
2. Subdomain enumeration
3. Port scanning

Then progress to active testing only when authorized.

### 4. Document Everything

- Keep logs of all activities
- Generate reports for findings
- Document authorization
- Track remediation

## Common Workflows

### Basic Security Assessment

1. **Reconnaissance**
   ```
   "Scan example.com for open ports"
   "Find subdomains for example.com"
   "Gather OSINT about example.com"
   ```

2. **Vulnerability Scanning**
   ```
   "Check https://example.com for web vulnerabilities"
   "Test API endpoints for security issues"
   ```

3. **Reporting**
   ```
   "Generate a comprehensive security report"
   ```

### Bug Bounty Workflow

1. **Discovery**
   ```
   "Enumerate subdomains for target.com"
   "Scan discovered subdomains"
   ```

2. **Testing**
   ```
   "Check each subdomain for vulnerabilities"
   "Test for common web vulnerabilities"
   ```

3. **Validation**
   ```
   "Search for known exploits"
   "Verify vulnerability exists"
   ```

## Safety Features

### Rate Limiting
PHANTOM includes built-in rate limiting to prevent overwhelming targets.

### Input Validation
All inputs are validated to prevent injection attacks.

### Confirmation Prompts
High-risk operations require confirmation (when enabled).

## Troubleshooting

### "Tool disabled in configuration"
- Check `configs/tools.yaml` or `configs/phantom.yaml`
- Enable the tool if authorized to use it

### "Target appears to be in restricted range"
- Ensure target is not localhost/private IP without confirmation
- Verify you have authorization

### "AI features not available"
- Check ANTHROPIC_API_KEY is set correctly
- Verify API key has proper permissions

## Advanced Usage

### Custom Wordlists

Place custom wordlists in the `wordlists/` directory:

```
wordlists/
├── custom_subdomains.txt
├── custom_passwords.txt
└── custom_directories.txt
```

Use them in scans:
```
"Enumerate subdomains using my custom wordlist"
```

### Session Management

PHANTOM maintains session data for comprehensive reporting:

```
"Generate report for session abc-123"
"List all active sessions"
```

## Next Steps

- Review [Legal Guidelines](legal.md)
- Explore [Installation Guide](installation.md)
- Check [API Reference](api.md)

## Support

Need help?
- 📧 Email: support@phantom-mcp.dev
- 💬 Discord: [Join our server](https://discord.gg/phantom)
- 🐛 Issues: [GitHub Issues](https://github.com/yourusername/phantom-mcp/issues)

---

**👻 Strike from the shadows. Test with purpose. Defend with knowledge.**
