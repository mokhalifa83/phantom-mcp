"""
👻 PHANTOM - CMS Scanner

Detect and scan Content Management Systems.
"""

import aiohttp
import re
from typing import Dict, Any
from bs4 import BeautifulSoup
from phantom.logger import get_logger
from phantom.config import PhantomConfig

logger = get_logger("phantom.vuln_scan.cms")


class CMSScanner:
    """CMS detection and vulnerability scanning."""
    
    def __init__(self, config: PhantomConfig):
        self.config = config
        logger.info("CMS scanner initialized")
    
    async def scan(self, url: str) -> Dict[str, Any]:
        """Detect CMS and scan for vulnerabilities."""
        logger.info(f"Detecting CMS for: {url}")
        
        results = {
            "url": url,
            "cms": None,
            "version": None,
            "vulnerabilities": [],
        }
        
        # Detect CMS type
        cms_type = await self._detect_cms(url, results)
        
        if cms_type:
            logger.info(f"Detected CMS: {cms_type}")
            results["cms"] = cms_type
            
            # Scan for CMS-specific vulnerabilities
            if cms_type == "WordPress":
                await self._scan_wordpress(url, results)
            elif cms_type == "Joomla":
                await self._scan_joomla(url, results)
            elif cms_type == "Drupal":
                await self._scan_drupal(url, results)
        
        return results
    
    async def _detect_cms(self, url: str, results: Dict[str, Any]) -> str:
        """Detect CMS type."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    content = await response.text()
                    soup = BeautifulSoup(content, "html.parser")
                    
                    # WordPress detection
                    if soup.find("meta", {"name": "generator", "content": re.compile("WordPress")}):
                        version_match = re.search(r"WordPress ([\d.]+)", content)
                        if version_match:
                            results["version"] = version_match.group(1)
                        return "WordPress"
                    
                    # Joomla detection
                    if soup.find("meta", {"name": "generator", "content": re.compile("Joomla")}):
                        version_match = re.search(r"Joomla! ([\d.]+)", content)
                        if version_match:
                            results["version"] = version_match.group(1)
                        return "Joomla"
                    
                    # Drupal detection
                    if soup.find("meta", {"name": "Generator", "content": re.compile("Drupal")}):
                        return "Drupal"
                    
                    # Check common CMS paths
                    if "/wp-content/" in content or "/wp-includes/" in content:
                        return "WordPress"
                    
                    if "/components/com_" in content:
                        return "Joomla"
        
        except Exception as e:
            logger.error(f"CMS detection failed: {e}")
        
        return None
    
    async def _scan_wordpress(self, url: str, results: Dict[str, Any]) -> None:
        """Scan WordPress installation."""
        logger.info("Scanning WordPress installation")
        
        # Check for common WordPress vulnerabilities
        paths_to_check = [
            "/wp-admin/install.php",  # Installation file
            "/wp-config.php~",  # Backup config
            "/wp-content/debug.log",  # Debug log
            "/.git/",  # Git exposed
        ]
        
        try:
            async with aiohttp.ClientSession() as session:
                for path in paths_to_check:
                    test_url = url.rstrip("/") + path
                    async with session.get(test_url) as response:
                        if response.status == 200:
                            results["vulnerabilities"].append({
                                "type": "Information Disclosure",
                                "severity": "MEDIUM",
                                "description": f"Sensitive file accessible: {path}",
                            })
        except Exception as e:
            logger.debug(f"WordPress scan error: {e}")
    
    async def _scan_joomla(self, url: str, results: Dict[str, Any]) -> None:
        """Scan Joomla installation."""
        logger.info("Scanning Joomla installation")
        # Joomla-specific checks
        pass
    
    async def _scan_drupal(self, url: str, results: Dict[str, Any]) -> None:
        """Scan Drupal installation."""
        logger.info("Scanning Drupal installation")
        # Drupal-specific checks
        pass
