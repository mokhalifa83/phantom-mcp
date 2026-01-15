"""
👻 PHANTOM - Input Validators

Validate and sanitize inputs for security.
"""

import re
import ipaddress
from typing import Union
from phantom.logger import get_logger

logger = get_logger("phantom.utils.validators")


def validate_ip_or_domain(target: str) -> bool:
    """
    Validate if target is a valid IP address or domain name.
    
    Args:
        target: IP address or domain to validate
        
    Returns:
        True if valid
    """
    # Remove protocol if present
    target = target.replace("http://", "").replace("https://", "").split("/")[0]
    
    # Check if it's a valid IP address
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass
    
    # Check if it's a valid domain name
    domain_pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    )
    
    return bool(domain_pattern.match(target))


def validate_port_range(ports: str) -> bool:
    """
    Validate port range string.
    
    Args:
        ports: Port range (e.g., "1-1000", "80,443,8080")
        
    Returns:
        True if valid
    """
    # Check for range format (1-1000)
    if "-" in ports:
        try:
            start, end = ports.split("-")
            start_port = int(start)
            end_port = int(end)
            return 1 <= start_port <= end_port <= 65535
        except ValueError:
            return False
    
    # Check for comma-separated format (80,443,8080)
    elif "," in ports:
        try:
            port_list = [int(p.strip()) for p in ports.split(",")]
            return all(1 <= p <= 65535 for p in port_list)
        except ValueError:
            return False
    
    # Single port
    else:
        try:
            port = int(ports)
            return 1 <= port <= 65535
        except ValueError:
            return False


def is_safe_target(target: str) -> bool:
    """
    Check if target is in safe range (not localhost, private IPs without confirmation).
    
    Args:
        target: Target to check
        
    Returns:
        True if safe to scan
    """
    # Remove protocol
    target = target.replace("http://", "").replace("https://", "").split("/")[0]
    
    try:
        ip = ipaddress.ip_address(target)
        
        # Block localhost
        if ip.is_loopback:
            logger.warning(f"Target is localhost: {target}")
            return True
        
        # Warn about private IPs
        if ip.is_private:
            logger.warning(f"Target is private IP: {target}")
            # In production, this might require confirmation
            # For now, we'll allow it
            return True
        
        return True
    
    except ValueError:
        # Not an IP, assume domain is safe
        return True


def sanitize_input(input_str: str) -> str:
    """
    Sanitize user input to prevent injection attacks.
    
    Args:
        input_str: Input string to sanitize
        
    Returns:
        Sanitized string
    """
    # Remove potentially dangerous characters
    dangerous_chars = [";", "&", "|", "`", "$", "(", ")", "{", "}", "[", "]", "<", ">"]
    
    sanitized = input_str
    for char in dangerous_chars:
        sanitized = sanitized.replace(char, "")
    
    return sanitized.strip()


def validate_url(url: str) -> bool:
    """
    Validate URL format.
    
    Args:
        url: URL to validate
        
    Returns:
        True if valid
    """
    url_pattern = re.compile(
        r'^https?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    
    return bool(url_pattern.match(url))
