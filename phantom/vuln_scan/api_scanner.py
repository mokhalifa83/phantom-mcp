"""
👻 PHANTOM - API Security Scanner

Test API endpoints for security vulnerabilities.
"""

import aiohttp
from typing import Dict, List, Any
from phantom.logger import get_logger
from phantom.config import PhantomConfig

logger = get_logger("phantom.vuln_scan.api")


class APIScanner:
    """API security testing."""
    
    def __init__(self, config: PhantomConfig):
        self.config = config
        logger.info("API scanner initialized")
    
    async def scan(
        self,
        api_url: str,
        api_type: str = "rest",
        test_auth: bool = True,
        test_injection: bool = True,
    ) -> Dict[str, Any]:
        """Scan API for security issues."""
        logger.info(f"Scanning API: {api_url}")
        
        results = {
            "url": api_url,
            "api_type": api_type,
            "vulnerabilities": [],
        }
        
        # Test authentication bypass
        if test_auth:
            await self._test_auth_bypass(api_url, results)
        
        # Test injection
        if test_injection:
            await self._test_injection(api_url, results)
        
        logger.info(f"API scan completed: {len(results['vulnerabilities'])} issues")
        return results
    
    async def _test_auth_bypass(self, url: str, results: Dict[str, Any]) -> None:
        """Test for authentication bypass."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        results["vulnerabilities"].append({
                            "type": "Authentication",
                            "severity": "HIGH",
                            "description": "API endpoint accessible without authentication",
                        })
        except Exception as e:
            logger.debug(f"Auth test error: {e}")
    
    async def _test_injection(self, url: str, results: Dict[str, Any]) -> None:
        """Test for injection vulnerabilities."""
        payloads = ["'", "<script>", "${7*7}"]
        
        try:
            async with aiohttp.ClientSession() as session:
                for payload in payloads:
                    test_url = f"{url}?param={payload}"
                    async with session.get(test_url) as response:
                        content = await response.text()
                        if payload in content:
                            results["vulnerabilities"].append({
                                "type": "Injection",
                                "severity": "MEDIUM",
                                "description": f"Potential injection with payload: {payload}",
                            })
                            break
        except Exception as e:
            logger.debug(f"Injection test error: {e}")
