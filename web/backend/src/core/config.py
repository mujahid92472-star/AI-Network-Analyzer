"""
Configuration management for AI Network Analyzer.

Supports YAML configuration files, environment variables, and sensible defaults.
"""

import os
from pathlib import Path
from typing import Optional, Any
from dataclasses import dataclass, field

# Try to import yaml, will fall back to dict-based config if not available
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


@dataclass
class ScanConfig:
    """Scanning configuration settings."""
    
    # Default ports to scan
    default_ports: str = "21-23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"
    top_ports: int = 100
    
    # Timing and performance
    timeout: float = 2.0  # seconds
    max_threads: int = 100
    scan_delay: float = 0.0  # delay between probes in seconds
    
    # Scan types enabled by default
    tcp_scan: bool = True
    udp_scan: bool = False
    service_detection: bool = True
    os_detection: bool = False
    
    # Timing templates (T0-T5, like nmap)
    # T0=paranoid, T1=sneaky, T2=polite, T3=normal, T4=aggressive, T5=insane
    timing_template: int = 3


@dataclass
class CVEConfig:
    """CVE/Vulnerability configuration settings."""
    
    # NVD API settings
    nvd_api_key: Optional[str] = field(default_factory=lambda: os.getenv("NVD_API_KEY"))
    nvd_api_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    # Rate limiting
    requests_per_minute: int = 5  # Without API key: 5 per 30 seconds
    request_delay: float = 6.0  # seconds between requests (conservative)
    
    # Caching
    cache_enabled: bool = True
    cache_ttl_hours: int = 24
    cache_directory: Path = field(default_factory=lambda: Path.cwd() / "data" / "cve_cache")
    
    # Offline database
    offline_db_path: Path = field(default_factory=lambda: Path.cwd() / "data" / "cve_offline.db")
    use_offline_fallback: bool = True


@dataclass
class AIConfig:
    """AI/Intelligence configuration settings."""
    
    # OpenAI settings
    openai_api_key: Optional[str] = field(default_factory=lambda: os.getenv("OPENAI_API_KEY"))
    openai_model: str = "gpt-4o-mini"  # Cost-effective default
    openai_max_tokens: int = 1000
    
    # Local LLM settings (Ollama)
    use_local_llm: bool = False
    ollama_host: str = "http://localhost:11434"
    ollama_model: str = "llama3.2"
    
    # Analysis settings
    enable_ai_analysis: bool = True
    include_remediation: bool = True


@dataclass
class ReportConfig:
    """Report generation configuration settings."""
    
    output_directory: Path = field(default_factory=lambda: Path.cwd() / "reports")
    default_format: str = "html"  # html, pdf, json, csv
    
    # Branding
    company_name: str = "AI Network Analyzer"
    company_logo: Optional[Path] = None
    
    # Content settings
    include_executive_summary: bool = True
    include_technical_details: bool = True
    include_remediation: bool = True
    max_cves_per_service: int = 10


@dataclass
class Config:
    """Main configuration class combining all config sections."""
    
    # Application info
    app_name: str = "AI Network Analyzer"
    version: str = "0.1.0"
    debug: bool = field(default_factory=lambda: os.getenv("DEBUG", "false").lower() == "true")
    
    # Log settings
    log_level: str = field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO"))
    log_directory: Path = field(default_factory=lambda: Path.cwd() / "logs")
    
    # Sub-configurations
    scan: ScanConfig = field(default_factory=ScanConfig)
    cve: CVEConfig = field(default_factory=CVEConfig)
    ai: AIConfig = field(default_factory=AIConfig)
    report: ReportConfig = field(default_factory=ReportConfig)
    
    @classmethod
    def from_yaml(cls, config_path: Path) -> "Config":
        """
        Load configuration from a YAML file.
        
        Args:
            config_path: Path to the YAML configuration file
        
        Returns:
            Config instance with loaded settings
        """
        if not YAML_AVAILABLE:
            raise ImportError("PyYAML is required for YAML config files. Install with: pip install pyyaml")
        
        if not config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        
        with open(config_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        
        return cls._from_dict(data)
    
    @classmethod
    def _from_dict(cls, data: dict) -> "Config":
        """Create Config from dictionary."""
        config = cls()
        
        # Update top-level settings
        for key in ["app_name", "version", "debug", "log_level"]:
            if key in data:
                setattr(config, key, data[key])
        
        if "log_directory" in data:
            config.log_directory = Path(data["log_directory"])
        
        # Update sub-configurations
        if "scan" in data:
            for key, value in data["scan"].items():
                if hasattr(config.scan, key):
                    setattr(config.scan, key, value)
        
        if "cve" in data:
            for key, value in data["cve"].items():
                if hasattr(config.cve, key):
                    if key in ["cache_directory", "offline_db_path"]:
                        value = Path(value)
                    setattr(config.cve, key, value)
        
        if "ai" in data:
            for key, value in data["ai"].items():
                if hasattr(config.ai, key):
                    setattr(config.ai, key, value)
        
        if "report" in data:
            for key, value in data["report"].items():
                if hasattr(config.report, key):
                    if key in ["output_directory", "company_logo"]:
                        value = Path(value) if value else None
                    setattr(config.report, key, value)
        
        return config
    
    def to_yaml(self, config_path: Path) -> None:
        """
        Save configuration to a YAML file.
        
        Args:
            config_path: Path to save the YAML configuration file
        """
        if not YAML_AVAILABLE:
            raise ImportError("PyYAML is required for YAML config files. Install with: pip install pyyaml")
        
        data = self._to_dict()
        
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, "w", encoding="utf-8") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)
    
    def _to_dict(self) -> dict:
        """Convert Config to dictionary for serialization."""
        def convert_value(v):
            if isinstance(v, Path):
                return str(v)
            return v
        
        return {
            "app_name": self.app_name,
            "version": self.version,
            "debug": self.debug,
            "log_level": self.log_level,
            "log_directory": str(self.log_directory),
            "scan": {k: convert_value(v) for k, v in self.scan.__dict__.items()},
            "cve": {k: convert_value(v) for k, v in self.cve.__dict__.items()},
            "ai": {k: convert_value(v) for k, v in self.ai.__dict__.items()},
            "report": {k: convert_value(v) for k, v in self.report.__dict__.items()},
        }
    
    def ensure_directories(self) -> None:
        """Create all necessary directories."""
        directories = [
            self.log_directory,
            self.cve.cache_directory,
            Path.cwd() / "data",
            Path.cwd() / "data" / "scans",  # For persistent scan storage
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)


# Global configuration instance
_config: Optional[Config] = None


def get_config(config_path: Optional[Path] = None) -> Config:
    """
    Get the global configuration instance.
    
    Args:
        config_path: Optional path to config file (only used on first call)
    
    Returns:
        Global Config instance
    """
    global _config
    
    if _config is None:
        if config_path and config_path.exists():
            _config = Config.from_yaml(config_path)
        else:
            _config = Config()
        
        _config.ensure_directories()
    
    return _config


def reset_config() -> None:
    """Reset the global configuration (mainly for testing)."""
    global _config
    _config = None
