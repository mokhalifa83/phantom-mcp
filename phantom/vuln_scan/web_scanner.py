"""
👻 PHANTOM - Web Vulnerability Scanner

Scan web applications for common vulnerabilities (OWASP Top 10).
⚠️ REQUIRES AUTHORIZATION ⚠️
"""

import asyncio
from typing import List, Dict, Any
import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re

from phantom.logger import get_logger
from phantom.config import PhantomConfig

logger = get_logger("phantom.vuln_scan.web")


class WebVulnScanner:
    """Web application vulnerability scanner."""
    
    def __init__(self, config: PhantomConfig):
        """
        Initialize web vulnerability scanner.
        
        Args:
            config: PHANTOM configuration
        """
        self.config = config
        self.vulnerabilities: List[Dict[str, Any]] = []
        logger.info("Web vulnerability scanner initialized")
    
    async def scan(
        self,
        url: str,
        scan_depth: str = "normal",
        check_xss: bool = True,
        check_sqli: bool = True,
        check_xxe: bool = True,
    ) -> List[Dict[str, Any]]:
        """
        Scan web application for vulnerabilities.
        
        Args:
            url: Target URL
            scan_depth: Scan depth (quick, normal, intensive)
            check_xss: Check for XSS vulnerabilities
            check_sqli: Check for SQL Injection
            check_xxe: Check for XXE vulnerabilities
            
        Returns:
            List of detected vulnerabilities
        """
        logger.info(f"Starting web vulnerability scan on {url}")
        logger.warning(f"⚠️  Ensure you have authorization to test {url}")
        
        self.vulnerabilities = []
        
        tasks = []
        
        # Basic security headers check
        tasks.append(self._check_security_headers(url))
        
        # SSL/TLS configuration
        tasks.append(self._check_ssl_config(url))
        
        # XSS testing
        if check_xss:
            tasks.append(self._test_xss(url))
        
        # SQL Injection testing
        if check_sqli:
            tasks.append(self._test_sql_injection(url))
        
        # Directory traversal
        tasks.append(self._test_directory_traversal(url))
        
        # Information disclosure
        tasks.append(self._check_info_disclosure(url))
        
        # Run all checks
        await asyncio.gather(*tasks, return_exceptions=True)
        
        logger.info(f"Web scan completed: {len(self.vulnerabilities)} vulnerabilities found")
        return self.vulnerabilities
    
    async def _check_security_headers(self, url: str) -> None:
        """
        Check for missing security headers.
        
        Args:
            url: Target URL
        """
        logger.debug("Checking security headers")
        
        important_headers = {
            "X-Frame-Options": "Clickjacking protection",
            "X-Content-Type-Options": "MIME type sniffing protection",
            "Strict-Transport-Security": "HTTPS enforcement",
            "Content-Security-Policy": "XSS and data injection protection",
            "X-XSS-Protection": "XSS filter",
            "Referrer-Policy": "Referrer information control",
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    missing_headers = []
                    
                    for header, description in important_headers.items():
                        if header not in response.headers:
                            missing_headers.append(header)
                    
                    if missing_headers:
                        self.vulnerabilities.append({
                            "type": "Missing Security Headers",
                            "severity": "MEDIUM",
                            "title": "Missing Security Headers",
                            "description": f"Missing headers: {', '.join(missing_headers)}",
                            "url": url,
                            "remediation": "Add recommended security headers to prevent various attacks",
                        })
        
        except Exception as e:
            logger.error(f"Security headers check failed: {e}")
    
    async def _check_ssl_config(self, url: str) -> None:
        """
        Check SSL/TLS configuration.
        
        Args:
            url: Target URL
        """
        if not url.startswith("https://"):
            self.vulnerabilities.append({
                "type": "SSL/TLS",
                "severity": "HIGH",
                "title": "No HTTPS",
                "description": "Website does not use HTTPS encryption",
                "url": url,
                "remediation": "Implement SSL/TLS certificate and redirect HTTP to HTTPS",
            })
    
    async def _test_xss(self, url: str) -> None:
        """
        Test for XSS vulnerabilities.
        
        Args:
            url: Target URL
        """
        logger.debug("Testing for XSS vulnerabilities")
        
        # XSS payloads
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg/onload=alert('XSS')>",
        ]
        
        try:
            # Test reflected XSS
            async with aiohttp.ClientSession() as session:
                for payload in xss_payloads:
                    test_url = f"{url}?q={payload}"
                    
                    try:
                        async with session.get(
                            test_url,
                            timeout=aiohttp.ClientTimeout(total=5)
                        ) as response:
                            content = await response.text()
                            
                            # Check if payload is reflected unescaped
                            if payload in content:
                                self.vulnerabilities.append({
                                    "type": "XSS",
                                    "severity": "HIGH",
                                    "title": "Reflected Cross-Site Scripting (XSS)",
                                    "description": f"XSS payload reflected in response: {payload}",
                                    "url": test_url,
                                    "remediation": "Properly escape and sanitize user input",
                                })
                                break  # Stop after first detection
                    
                    except asyncio.TimeoutError:
                        continue
        
        except Exception as e:
            logger.error(f"XSS testing failed: {e}")
    
    async def _test_sql_injection(self, url: str) -> None:
        """
        Test for SQL Injection vulnerabilities.
        
        Args:
            url: Target URL
        """
        logger.debug("Testing for SQL Injection")
        
        # SQL injection payloads
        sqli_payloads = [
            "'",
            "1' OR '1'='1",
            "' OR 1=1--",
            "\" OR \"1\"=\"1",
            "' UNION SELECT NULL--",
        ]
        
        try:
            async with aiohttp.ClientSession() as session:
                for payload in sqli_payloads:
                    test_url = f"{url}?id={payload}"
                    
                    try:
                        async with session.get(
                            test_url,
                            timeout=aiohttp.ClientTimeout(total=5)
                        ) as response:
                            content = await response.text()
                            
                            # Look for SQL error messages
                            sql_errors = [
                                "SQL syntax",
                                "mysql_",
                                "MySQLSyntaxErrorException",
                                "SQLException",
                                "ORA-",
                                "PostgreSQL",
                                "Microsoft SQL",
                            ]
                            
                            for error in sql_errors:
                                if error.lower() in content.lower():
                                    self.vulnerabilities.append({
                                        "type": "SQL Injection",
                                        "severity": "CRITICAL",
                                        "title": "SQL Injection Vulnerability",
                                        "description": f"SQL error message detected with payload: {payload}",
                                        "url": test_url,
                                        "remediation": "Use parameterized queries and input validation",
                                    })
                                    return  # Stop after detection
                    
                    except asyncio.TimeoutError:
                        continue
        
        except Exception as e:
            logger.error(f"SQL injection testing failed: {e}")
    
    async def _test_directory_traversal(self, url: str) -> None:
        """
        Test for directory traversal vulnerabilities.
        
        Args:
            url: Target URL
        """
        logger.debug("Testing for directory traversal")
        
        traversal_payloads = [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "..\\..\\..\\windows\\win.ini",
        ]
        
        try:
            async with aiohttp.ClientSession() as session:
                for payload in traversal_payloads:
                    test_url = f"{url}?file={payload}"
                    
                    try:
                        async with session.get(
                            test_url,
                            timeout=aiohttp.ClientTimeout(total=5)
                        ) as response:
                            content = await response.text()
                            
                            # Check for sensitive file markers
                            if "root:" in content or "[extensions]" in content:
                                self.vulnerabilities.append({
                                    "type": "Directory Traversal",
                                    "severity": "HIGH",
                                    "title": "Directory Traversal Vulnerability",
                                    "description": f"Sensitive file access detected with payload: {payload}",
                                    "url": test_url,
                                    "remediation": "Validate and sanitize file paths, use allowlists",
                                })
                                break
                    
                    except asyncio.TimeoutError:
                        continue
        
        except Exception as e:
            logger.error(f"Directory traversal testing failed: {e}")
    
    async def _check_info_disclosure(self, url: str) -> None:
        """
        Check for information disclosure.
        
        Args:
            url: Target URL
        """
        logger.debug("Checking for information disclosure")
        
        try:
            # Check common sensitive files
            sensitive_paths = [
                "/.git/config",
                "/.env",
                "/config.php",
                "/phpinfo.php",
                "/robots.txt",
                "/.htaccess",
            ]
            
            async with aiohttp.ClientSession() as session:
                for path in sensitive_paths:
                    test_url = urljoin(url, path)
                    
                    try:
                        async with session.get(
                            test_url,
                            timeout=aiohttp.ClientTimeout(total=5)
                        ) as response:
                            if response.status == 200:
                                self.vulnerabilities.append({
                                    "type": "Information Disclosure",
                                    "severity": "MEDIUM",
                                    "title": f"Sensitive File Exposed: {path}",
                                    "description": f"Sensitive file accessible at {test_url}",
                                    "url": test_url,
                                    "remediation": "Remove or protect sensitive files",
                                })
                    
                    except asyncio.TimeoutError:
                        continue
        
        except Exception as e:
            logger.error(f"Information disclosure check failed: {e}")
