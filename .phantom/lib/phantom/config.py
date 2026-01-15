"""
👻 PHANTOM MCP - Configuration Management

Handles loading and validation of YAML configuration files.
"""

import os
from pathlib import Path
from typing import Any, Dict, Optional
from dataclasses import dataclass, field

import yaml
from pydantic import BaseModel, Field, validator


class ScanConfig(BaseModel):
    """Configuration for scanning operations."""
    
    default_timeout: int = Field(default=300, ge=1, le=3600)
    default_port_range: str = Field(default="1-1000")
    max_concurrent_scans: int = Field(default=3, ge=1, le=10)
    nmap_speed: int = Field(default=3, ge=0, le=5)
    dns_servers: list[str] = Field(default=["8.8.8.8", "1.1.1.1"])


class SecurityConfig(BaseModel):
    """Security-related configuration."""
    
    safe_mode: bool = Field(default=True)
    require_confirmation: bool = Field(default=True)
    enable_auto_exploit: bool = Field(default=False)
    enable_post_exploit: bool = Field(default=False)
    enable_password_attacks: bool = Field(default=False)


class AIConfig(BaseModel):
    """AI-related configuration."""
    
    enable_ai: bool = Field(default=True)
    model: str = Field(default="claude-3-5-sonnet-20241022")
    max_tokens: int = Field(default=4096, ge=100, le=100000)
    temperature: float = Field(default=0.7, ge=0.0, le=1.0)


class LoggingConfig(BaseModel):
    """Logging configuration."""
    
    level: str = Field(default="INFO")
    file_path: str = Field(default="logs/phantom.log")
    detailed: bool = Field(default=False)
    
    @validator("level")
    def validate_level(cls, v: str) -> str:
        """Validate log level."""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in valid_levels:
            raise ValueError(f"Invalid log level. Must be one of {valid_levels}")
        return v.upper()


class ReportingConfig(BaseModel):
    """Reporting configuration."""
    
    output_dir: str = Field(default="reports")
    default_format: str = Field(default="html")
    include_screenshots: bool = Field(default=True)
    company_name: str = Field(default="PHANTOM Security")


class PhantomConfig(BaseModel):
    """Main PHANTOM configuration."""
    
    scan: ScanConfig = Field(default_factory=ScanConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    ai: AIConfig = Field(default_factory=AIConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    
    class Config:
        """Pydantic configuration."""
        extra = "allow"


class ConfigManager:
    """Manages PHANTOM configuration from files and environment variables."""
    
    def __init__(self, config_path: Optional[Path] = None):
        """
        Initialize configuration manager.
        
        Args:
            config_path: Path to configuration file. If None, uses default.
        """
        self.config_path = config_path or Path("configs/phantom.yaml")
        self._config: Optional[PhantomConfig] = None
    
    def load(self) -> PhantomConfig:
        """
        Load configuration from file and environment variables.
        
        Returns:
            Loaded configuration
            
        Raises:
            FileNotFoundError: If config file doesn't exist
            ValueError: If config is invalid
        """
        config_dict: Dict[str, Any] = {}
        
        # Load from YAML file if exists
        if self.config_path.exists():
            with open(self.config_path, "r", encoding="utf-8") as f:
                config_dict = yaml.safe_load(f) or {}
        
        # Override with environment variables
        config_dict = self._apply_env_overrides(config_dict)
        
        # Validate and create config object
        self._config = PhantomConfig(**config_dict)
        return self._config
    
    def _apply_env_overrides(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Apply environment variable overrides to configuration.
        
        Args:
            config: Base configuration dictionary
            
        Returns:
            Updated configuration dictionary
        """
        # Security settings
        if os.getenv("PHANTOM_SAFE_MODE"):
            config.setdefault("security", {})
            config["security"]["safe_mode"] = os.getenv("PHANTOM_SAFE_MODE").lower() == "true"
        
        if os.getenv("REQUIRE_AUTH_CONFIRMATION"):
            config.setdefault("security", {})
            config["security"]["require_confirmation"] = os.getenv("REQUIRE_AUTH_CONFIRMATION").lower() == "true"
        
        if os.getenv("ENABLE_AUTO_EXPLOIT"):
            config.setdefault("security", {})
            config["security"]["enable_auto_exploit"] = os.getenv("ENABLE_AUTO_EXPLOIT").lower() == "true"
        
        # Scan settings
        if os.getenv("MAX_CONCURRENT_SCANS"):
            config.setdefault("scan", {})
            config["scan"]["max_concurrent_scans"] = int(os.getenv("MAX_CONCURRENT_SCANS"))
        
        if os.getenv("SCAN_TIMEOUT"):
            config.setdefault("scan", {})
            config["scan"]["default_timeout"] = int(os.getenv("SCAN_TIMEOUT"))
        
        # Logging settings
        if os.getenv("PHANTOM_LOG_LEVEL"):
            config.setdefault("logging", {})
            config["logging"]["level"] = os.getenv("PHANTOM_LOG_LEVEL")
        
        if os.getenv("PHANTOM_LOG_FILE"):
            config.setdefault("logging", {})
            config["logging"]["file_path"] = os.getenv("PHANTOM_LOG_FILE")
        
        # AI settings
        if os.getenv("ENABLE_AI_ANALYSIS"):
            config.setdefault("ai", {})
            config["ai"]["enable_ai"] = os.getenv("ENABLE_AI_ANALYSIS").lower() == "true"
        
        # Reporting settings
        if os.getenv("REPORT_OUTPUT_DIR"):
            config.setdefault("reporting", {})
            config["reporting"]["output_dir"] = os.getenv("REPORT_OUTPUT_DIR")
        
        if os.getenv("COMPANY_NAME"):
            config.setdefault("reporting", {})
            config["reporting"]["company_name"] = os.getenv("COMPANY_NAME")
        
        return config
    
    def save(self, config: PhantomConfig, path: Optional[Path] = None) -> None:
        """
        Save configuration to file.
        
        Args:
            config: Configuration to save
            path: Path to save to. If None, uses default.
        """
        save_path = path or self.config_path
        save_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Convert to dictionary
        config_dict = config.model_dump()
        
        # Write to YAML
        with open(save_path, "w", encoding="utf-8") as f:
            yaml.dump(config_dict, f, default_flow_style=False, sort_keys=False)
    
    @property
    def config(self) -> PhantomConfig:
        """
        Get current configuration.
        
        Returns:
            Current configuration
        """
        if self._config is None:
            self._config = self.load()
        return self._config


# Global configuration instance
_config_manager = ConfigManager()
config = _config_manager.config
