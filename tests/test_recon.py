"""
👻 PHANTOM MCP - Reconnaissance Tests
"""

import pytest
from phantom.recon.scanner import PortScanner
from phantom.recon.subdomain import SubdomainEnumerator
from phantom.config import PhantomConfig


class TestPortScanner:
    """Test port scanner functionality."""
    
    @pytest.fixture
    def scanner(self):
        """Create scanner instance."""
        config = PhantomConfig()
        return PortScanner(config)
    
    def test_scanner_initialization(self, scanner):
        """Test scanner initializes correctly."""
        assert scanner is not None
        assert scanner.nm is not None


class TestSubdomainEnumerator:
    """Test subdomain enumerator."""
    
    @pytest.fixture
    def enumerator(self):
        """Create enumerator instance."""
        config = PhantomConfig()
        return SubdomainEnumerator(config)
    
    def test_enumerator_initialization(self, enumerator):
        """Test enumerator initializes correctly."""
        assert enumerator is not None
