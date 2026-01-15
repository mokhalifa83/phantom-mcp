#!/usr/bin/env python3
"""
👻 PHANTOM MCP Setup Script

Strike from the shadows - Advanced AI-powered penetration testing MCP server
"""

from pathlib import Path
from setuptools import setup, find_packages

# Read the contents of README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding="utf-8")

# Read requirements
requirements = []
with open("requirements.txt", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if line and not line.startswith("#") and not line.startswith("="):
            # Extract just the package name and version constraint
            if ">=" in line or "==" in line or "<=" in line:
                requirements.append(line)

setup(
    name="phantom-mcp",
    version="0.1.0",
    author="PHANTOM Team",
    author_email="team@phantom-mcp.dev",
    description="👻 Advanced AI-powered penetration testing MCP server - Strike from the shadows",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/phantom-mcp",
    project_urls={
        "Bug Tracker": "https://github.com/yourusername/phantom-mcp/issues",
        "Documentation": "https://phantom-mcp.dev/docs",
        "Source Code": "https://github.com/yourusername/phantom-mcp",
    },
    packages=find_packages(exclude=["tests", "tests.*"]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: System :: Networking",
        "Topic :: System :: Systems Administration",
        "Typing :: Typed",
    ],
    python_requires=">=3.10",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.4.3",
            "pytest-asyncio>=0.21.1",
            "pytest-cov>=4.1.0",
            "black>=23.12.0",
            "mypy>=1.7.0",
            "ruff>=0.1.7",
        ],
        "full": [
            "shodan>=1.31.0",
            "censys>=2.2.0",
            "pwntools>=4.11.0",
            "scapy>=2.5.0",
            "weasyprint>=60.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "phantom=phantom.server:main",
        ],
    },
    include_package_data=True,
    package_data={
        "phantom": [
            "reporting/templates/*.jinja2",
            "reporting/templates/*.html",
        ],
    },
    zip_safe=False,
    keywords=[
        "mcp",
        "security",
        "penetration-testing",
        "pentest",
        "vulnerability-scanner",
        "ethical-hacking",
        "security-tools",
        "ai-security",
    ],
)
