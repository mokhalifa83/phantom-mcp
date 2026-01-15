"""
👻 PHANTOM MCP - Logging System

Professional logging with PHANTOM branding and colors.
"""

import logging
import sys
from pathlib import Path
from typing import Optional
from datetime import datetime

from colorama import init, Fore, Back, Style
from rich.console import Console
from rich.logging import RichHandler

# Initialize colorama
init(autoreset=True)

# PHANTOM colors
PHANTOM_PURPLE = Fore.MAGENTA
PHANTOM_BLUE = Fore.CYAN
PHANTOM_GREEN = Fore.GREEN
PHANTOM_RED = Fore.RED
PHANTOM_YELLOW = Fore.YELLOW


class PhantomFormatter(logging.Formatter):
    """
    Custom formatter with PHANTOM branding and colors.
    """
    
    # Log level colors
    COLORS = {
        "DEBUG": Fore.CYAN,
        "INFO": Fore.GREEN,
        "WARNING": Fore.YELLOW,
        "ERROR": Fore.RED,
        "CRITICAL": Fore.RED + Back.WHITE + Style.BRIGHT,
    }
    
    # Emoji indicators
    EMOJIS = {
        "DEBUG": "🔍",
        "INFO": "ℹ️ ",
        "WARNING": "⚠️ ",
        "ERROR": "❌",
        "CRITICAL": "💀",
    }
    
    def format(self, record: logging.LogRecord) -> str:
        """
        Format log record with colors and emoji.
        
        Args:
            record: Log record to format
            
        Returns:
            Formatted log message
        """
        # Get color and emoji for this level
        color = self.COLORS.get(record.levelname, "")
        emoji = self.EMOJIS.get(record.levelname, "")
        
        # Format timestamp
        timestamp = datetime.fromtimestamp(record.created).strftime("%H:%M:%S")
        
        # Format the message
        formatted = (
            f"{PHANTOM_PURPLE}👻 {Style.RESET_ALL}"
            f"{Fore.WHITE}{timestamp}{Style.RESET_ALL} "
            f"{color}{emoji} {record.levelname:8s}{Style.RESET_ALL} "
            f"{PHANTOM_BLUE}[{record.name}]{Style.RESET_ALL} "
            f"{record.getMessage()}"
        )
        
        # Add exception info if present
        if record.exc_info:
            formatted += "\n" + self.formatException(record.exc_info)
        
        return formatted


class PhantomLogger:
    """
    PHANTOM-branded logger with file and console output.
    """
    
    def __init__(
        self,
        name: str = "phantom",
        level: str = "INFO",
        log_file: Optional[Path] = None,
        use_rich: bool = False,
    ):
        """
        Initialize PHANTOM logger.
        
        Args:
            name: Logger name
            level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            log_file: Path to log file (optional)
            use_rich: Use Rich library for enhanced console output
        """
        self.name = name
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, level.upper()))
        self.logger.handlers.clear()
        
        # Console handler
        if use_rich:
            console_handler = RichHandler(
                rich_tracebacks=True,
                show_time=False,
                markup=True,
                console=Console(stderr=True),
            )
            console_handler.setFormatter(logging.Formatter("%(message)s"))
        else:
            # MCP requires logging to stderr to not interfere with stdout JSON-RPC
            console_handler = logging.StreamHandler(sys.stderr)
            console_handler.setFormatter(PhantomFormatter())
        
        self.logger.addHandler(console_handler)
        
        # File handler
        if log_file:
            log_file = Path(log_file)
            log_file.parent.mkdir(parents=True, exist_ok=True)
            
            file_handler = logging.FileHandler(log_file, encoding="utf-8")
            file_formatter = logging.Formatter(
                "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
            file_handler.setFormatter(file_formatter)
            self.logger.addHandler(file_handler)
    
    def debug(self, msg: str, *args, **kwargs) -> None:
        """Log debug message."""
        self.logger.debug(msg, *args, **kwargs)
    
    def info(self, msg: str, *args, **kwargs) -> None:
        """Log info message."""
        self.logger.info(msg, *args, **kwargs)
    
    def warning(self, msg: str, *args, **kwargs) -> None:
        """Log warning message."""
        self.logger.warning(msg, *args, **kwargs)
    
    def error(self, msg: str, *args, **kwargs) -> None:
        """Log error message."""
        self.logger.error(msg, *args, **kwargs)
    
    def critical(self, msg: str, *args, **kwargs) -> None:
        """Log critical message."""
        self.logger.critical(msg, *args, **kwargs)
    
    def exception(self, msg: str, *args, **kwargs) -> None:
        """Log exception with traceback."""
        self.logger.exception(msg, *args, **kwargs)
    
    def security_event(self, event: str, target: Optional[str] = None, **details) -> None:
        """
        Log security-relevant event.
        
        Args:
            event: Event description
            target: Target system/IP
            **details: Additional event details
        """
        msg = f"🔒 SECURITY EVENT: {event}"
        if target:
            msg += f" | Target: {target}"
        
        if details:
            detail_str = " | ".join(f"{k}={v}" for k, v in details.items())
            msg += f" | {detail_str}"
        
        self.logger.info(msg)
    
    def tool_execution(
        self,
        tool_name: str,
        target: Optional[str] = None,
        status: str = "started",
        **params,
    ) -> None:
        """
        Log tool execution.
        
        Args:
            tool_name: Name of the tool
            target: Target system/IP
            status: Execution status (started, completed, failed)
            **params: Tool parameters
        """
        emoji = {
            "started": "▶️ ",
            "completed": "✅",
            "failed": "❌",
        }.get(status, "▶️")
        
        msg = f"{emoji} Tool: {tool_name} | Status: {status}"
        if target:
            msg += f" | Target: {target}"
        
        if params:
            param_str = " | ".join(f"{k}={v}" for k, v in params.items())
            msg += f" | {param_str}"
        
        level = "error" if status == "failed" else "info"
        getattr(self.logger, level)(msg)
    
    def banner(self) -> None:
        """Print PHANTOM banner."""
        from phantom import PHANTOM_LOGO
        
        print(f"{PHANTOM_PURPLE}{PHANTOM_LOGO}{Style.RESET_ALL}", file=sys.stderr)
        self.logger.info(f"{PHANTOM_BLUE}Starting PHANTOM MCP Server...{Style.RESET_ALL}")


# Global logger instance
def get_logger(name: str = "phantom", **kwargs) -> PhantomLogger:
    """
    Get or create a PHANTOM logger.
    
    Args:
        name: Logger name
        **kwargs: Additional logger arguments
        
    Returns:
        PhantomLogger instance
    """
    return PhantomLogger(name=name, **kwargs)


# Default logger
logger = get_logger()
