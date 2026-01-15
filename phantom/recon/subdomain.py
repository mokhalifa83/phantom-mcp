"""
👻 PHANTOM - Subdomain Enumerator

Discover subdomains using multiple techniques.
"""

import asyncio
from typing import List, Set, Optional
import aiohttp
import dns.resolver
import dns.asyncresolver
from bs4 import BeautifulSoup

from phantom.logger import get_logger
from phantom.config import PhantomConfig

logger = get_logger("phantom.recon.subdomain")


class SubdomainEnumerator:
    """Subdomain enumeration using multiple techniques."""
    
    def __init__(self, config: PhantomConfig):
        """
        Initialize subdomain enumerator.
        
        Args:
            config: PHANTOM configuration
        """
        self.config = config
        self.dns_servers = config.scan.dns_servers
        self.found_subdomains: Set[str] = set()
        logger.info("Subdomain enumerator initialized")
    
    async def enumerate(
        self,
        domain: str,
        wordlist: Optional[str] = None,
        use_dns: bool = True,
        use_cert_transparency: bool = True,
    ) -> List[str]:
        """
        Enumerate subdomains for target domain.
        
        Args:
            domain: Target domain
            wordlist: Path to subdomain wordlist
            use_dns: Use DNS brute-forcing
            use_cert_transparency: Use certificate transparency logs
            
        Returns:
            List of discovered subdomains
        """
        logger.info(f"Starting subdomain enumeration for {domain}")
        
        self.found_subdomains = set()
        tasks = []
        
        # DNS brute-forcing
        if use_dns:
            tasks.append(self._dns_bruteforce(domain, wordlist))
        
        # Certificate transparency
        if use_cert_transparency:
            tasks.append(self._cert_transparency(domain))
        
        # Run all techniques concurrently
        await asyncio.gather(*tasks, return_exceptions=True)
        
        subdomains = sorted(list(self.found_subdomains))
        logger.info(f"Found {len(subdomains)} subdomains for {domain}")
        
        return subdomains
    
    async def _dns_bruteforce(self, domain: str, wordlist: Optional[str] = None) -> None:
        """
        Brute-force subdomains using DNS queries.
        
        Args:
            domain: Target domain
            wordlist: Path to wordlist
        """
        logger.info(f"Starting DNS brute-force for {domain}")
        
        # Default subdomain list if no wordlist provided
        default_subdomains = [
            "www", "mail", "ftp", "admin", "test", "dev", "staging", "api",
            "app", "web", "portal", "blog", "shop", "store", "vpn", "remote",
            "secure", "cdn", "static", "media", "assets", "files", "docs",
            "support", "help", "forum", "community", "chat", "beta", "demo",
        ]
        
        # Load wordlist if provided
        if wordlist:
            try:
                with open(wordlist, "r") as f:
                    subdomains_to_test = [line.strip() for line in f if line.strip()]
            except FileNotFoundError:
                logger.warning(f"Wordlist not found: {wordlist}, using defaults")
                subdomains_to_test = default_subdomains
        else:
            subdomains_to_test = default_subdomains
        
        # Create DNS resolver
        resolver = dns.asyncresolver.Resolver()
        resolver.nameservers = self.dns_servers
        
        # Test each subdomain
        tasks = []
        for subdomain in subdomains_to_test:
            full_domain = f"{subdomain}.{domain}"
            tasks.append(self._check_subdomain(resolver, full_domain))
        
        # Run checks concurrently
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _check_subdomain(self, resolver: dns.asyncresolver.Resolver, subdomain: str) -> None:
        """
        Check if subdomain exists via DNS query.
        
        Args:
            resolver: DNS resolver
            subdomain: Subdomain to check
        """
        try:
            # Query A record
            await resolver.resolve(subdomain, "A")
            self.found_subdomains.add(subdomain)
            logger.debug(f"Found subdomain: {subdomain}")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
            # Subdomain doesn't exist or no A record
            pass
        except Exception as e:
            logger.debug(f"DNS query failed for {subdomain}: {e}")
    
    async def _cert_transparency(self, domain: str) -> None:
        """
        Discover subdomains using Certificate Transparency logs.
        
        Args:
            domain: Target domain
        """
        logger.info(f"Querying certificate transparency logs for {domain}")
        
        # Use crt.sh API
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        for entry in data:
                            name_value = entry.get("name_value", "")
                            # Split by newlines (multiple names in one entry)
                            for subdomain in name_value.split("\n"):
                                subdomain = subdomain.strip()
                                # Filter out wildcards and invalid entries
                                if subdomain and "*" not in subdomain and subdomain.endswith(domain):
                                    self.found_subdomains.add(subdomain)
                        
                        logger.info(f"Certificate transparency found {len(data)} certificate entries")
        
        except asyncio.TimeoutError:
            logger.warning("Certificate transparency query timed out")
        except Exception as e:
            logger.error(f"Certificate transparency query failed: {e}")
    
    async def verify_subdomain(self, subdomain: str) -> bool:
        """
        Verify subdomain is accessible via HTTP/HTTPS.
        
        Args:
            subdomain: Subdomain to verify
            
        Returns:
            True if subdomain is accessible
        """
        for scheme in ["https", "http"]:
            url = f"{scheme}://{subdomain}"
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        url,
                        timeout=aiohttp.ClientTimeout(total=5),
                        allow_redirects=True
                    ) as response:
                        if response.status < 500:
                            logger.debug(f"Verified {url} - Status: {response.status}")
                            return True
            except Exception:
                continue
        
        return False
    
    async def enumerate_with_verification(self, domain: str) -> List[dict]:
        """
        Enumerate and verify subdomains.
        
        Args:
            domain: Target domain
            
        Returns:
            List of verified subdomains with details
        """
        # Find subdomains
        subdomains = await self.enumerate(domain)
        
        # Verify each subdomain
        verified = []
        for subdomain in subdomains:
            is_active = await self.verify_subdomain(subdomain)
            verified.append({
                "subdomain": subdomain,
                "active": is_active,
            })
        
        return verified
