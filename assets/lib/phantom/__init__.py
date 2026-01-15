"""
👻 PHANTOM MCP - Advanced AI-powered Penetration Testing MCP Server

Strike from the shadows.

A comprehensive Model Context Protocol server for ethical penetration testing,
vulnerability assessment, and security analysis powered by AI.

⚠️ WARNING: This tool is for AUTHORIZED security testing only.
Unauthorized access to computer systems is illegal.
"""

__version__ = "0.1.0"
__author__ = "PHANTOM Team"
__license__ = "MIT"

# Legal notice
LEGAL_NOTICE = """
⚠️ PHANTOM MCP - LEGAL NOTICE ⚠️

This software is intended for authorized security testing and educational
purposes only. You must comply with all applicable laws and regulations.

By using this software, you agree to:
1. Only test systems you own or have explicit written permission to test
2. Comply with all applicable laws and regulations
3. Take full responsibility for your actions
4. Not use this tool for malicious purposes

The authors and contributors assume no liability for misuse of this software.
"""

# ASCII Logo
PHANTOM_LOGO = """
██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝

👻 Strike from the shadows - v{version}
""".format(version=__version__)


# Export main components
# Export key constants
__all__ = [
    "__version__",
    "__author__",
    "__license__",
    "LEGAL_NOTICE",
    "PHANTOM_LOGO",
]
