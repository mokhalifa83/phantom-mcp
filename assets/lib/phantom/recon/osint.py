"""
👻 PHANTOM - OSINT Gatherer

Open Source Intelligence gathering from public sources.
"""

import asyncio
from typing import Dict, List, Any
import aiohttp
from bs4 import BeautifulSoup
import re

from phantom.logger import get_logger
from phantom.config import PhantomConfig

logger = get_logger("phantom.recon.osint")


class OSINTGatherer:
    """Gather OSINT from various public sources."""
    
    def __init__(self, config: PhantomConfig):
        """
        Initialize OSINT gatherer.
        
        Args:
            config: PHANTOM configuration
        """
        self.config = config
        logger.info("OSINT gatherer initialized")
    
    async def gather(
        self,
        target: str,
        search_emails: bool = True,
        search_breaches: bool = True,
        search_social: bool = False,
    ) -> Dict[str, Any]:
        """
        Gather OSINT about target.
        
        Args:
            target: Domain, company, or person to investigate
            search_emails: Search for email addresses
            search_breaches: Check for data breaches
            search_social: Search social media (requires API keys)
            
        Returns:
            OSINT findings
        """
        logger.info(f"Starting OSINT gathering for {target}")
        
        results = {
            "target": target,
            "emails": [],
            "breaches": [],
            "social_media": {},
            "whois": {},
            "dns_records": [],
        }
        
        tasks = []
        
        # Email search
        if search_emails:
            tasks.append(self._search_emails(target, results))
        
        # Data breach check (using Have I Been Pwned API)
        if search_breaches:
            tasks.append(self._check_breaches(target, results))
        
        # WHOIS lookup
        tasks.append(self._whois_lookup(target, results))
        
        # DNS records
        tasks.append(self._get_dns_records(target, results))
        
        # Run all tasks
        await asyncio.gather(*tasks, return_exceptions=True)
        
        logger.info(f"OSINT gathering completed for {target}")
        return results
    
    async def _search_emails(self, target: str, results: Dict[str, Any]) -> None:
        """
        Search for email addresses associated with target.
        
        Args:
            target: Target domain or company
            results: Results dictionary to update
        """
        logger.info(f"Searching for email addresses for {target}")
        
        emails = set()
        email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        
        # Search via web scraping (example with Google - in reality, use proper APIs)
        try:
            async with aiohttp.ClientSession() as session:
                # Hunter.io API could be used here with API key
                # For demo, we'll use a placeholder
                results["emails"] = [
                    f"info@{target}",
                    f"contact@{target}",
                    f"admin@{target}",
                ]
                logger.info(f"Found {len(results['emails'])} potential email addresses")
        
        except Exception as e:
            logger.error(f"Email search failed: {e}")
    
    async def _check_breaches(self, target: str, results: Dict[str, Any]) -> None:
        """
        Check for data breaches (HIBP API).
        
        Args:
            target: Domain to check
            results: Results dictionary to update
        """
        logger.info(f"Checking for data breaches for {target}")
        
        try:
            # Have I Been Pwned API
            url = f"https://haveibeenpwned.com/api/v3/breaches"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    if response.status == 200:
                        all_breaches = await response.json()
                        
                        # Filter breaches for this domain
                        domain_breaches = [
                            breach for breach in all_breaches
                            if target.lower() in breach.get("Domain", "").lower()
                        ]
                        
                        results["breaches"] = [
                            {
                                "name": breach.get("Name"),
                                "date": breach.get("BreachDate"),
                                "compromised_data": breach.get("DataClasses", []),
                            }
                            for breach in domain_breaches
                        ]
                        
                        logger.info(f"Found {len(results['breaches'])} breaches")
        
        except Exception as e:
            logger.error(f"Breach check failed: {e}")
    
    async def _whois_lookup(self, target: str, results: Dict[str, Any]) -> None:
        """
        Perform WHOIS lookup.
        
        Args:
            target: Domain to lookup
            results: Results dictionary to update
        """
        logger.info(f"Performing WHOIS lookup for {target}")
        
        try:
            import whois
            
            # Remove protocol if present
            domain = target.replace("http://", "").replace("https://", "").split("/")[0]
            
            w = whois.whois(domain)
            
            results["whois"] = {
                "registrar": w.registrar,
                "creation_date": str(w.creation_date) if w.creation_date else None,
                "expiration_date": str(w.expiration_date) if w.expiration_date else None,
                "name_servers": w.name_servers if w.name_servers else [],
                "org": w.org if hasattr(w, "org") else None,
            }
            
            logger.info("WHOIS lookup completed")
        
        except Exception as e:
            logger.error(f"WHOIS lookup failed: {e}")
    
    async def _get_dns_records(self, target: str, results: Dict[str, Any]) -> None:
        """
        Get DNS records for target.
        
        Args:
            target: Domain to query
            results: Results dictionary to update
        """
        logger.info(f"Querying DNS records for {target}")
        
        try:
            import dns.resolver
            
            # Remove protocol if present
            domain = target.replace("http://", "").replace("https://", "").split("/")[0]
            
            record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA"]
            dns_records = {}
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    dns_records[record_type] = [str(rdata) for rdata in answers]
                except Exception:
                    pass
            
            results["dns_records"] = dns_records
            logger.info(f"DNS lookup completed, found {len(dns_records)} record types")
        
        except Exception as e:
            logger.error(f"DNS lookup failed: {e}")
    
    async def search_github(self, target: str) -> List[Dict[str, Any]]:
        """
        Search GitHub for potential leaks.
        
        Args:
            target: Domain or company to search for
            
        Returns:
            List of potential findings
        """
        logger.info(f"Searching GitHub for {target}")
        
        # This would require GitHub API token
        # Placeholder implementation
        return []
    
    async def search_paste_sites(self, target: str) -> List[Dict[str, Any]]:
        """
        Search paste sites for leaks.
        
        Args:
            target: Target to search for
            
        Returns:
            List of potential leaks
        """
        logger.info(f"Searching paste sites for {target}")
        
        # This would check sites like Pastebin, etc.
        # Placeholder implementation
        return []
