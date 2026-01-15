"""
👻 PHANTOM MCP - Server Tests
"""

import pytest
from phantom.server import PhantomServer


class TestPhantomServer:
    """Test PHANTOM MCP server."""
    
    def test_server_initialization(self):
        """Test server initializes correctly."""
        server = PhantomServer()
        assert server is not None
        assert server.server is not None
    
    def test_server_config_loaded(self):
        """Test configuration is loaded."""
        server = PhantomServer()
        assert server.config is not None
    
    def test_logger_initialized(self):
        """Test logger is initialized."""
        server = PhantomServer()
        assert server.logger is not None
