"""
Logging infrastructure for AI Network Analyzer.

Provides structured logging with colored console output and file logging.
"""

import logging
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional

# Try to import rich for beautiful console output
try:
    from rich.logging import RichHandler
    from rich.console import Console
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


# Custom log levels
SCAN = 25  # Between INFO and WARNING
logging.addLevelName(SCAN, "SCAN")

# Global logger registry
_loggers: dict[str, logging.Logger] = {}


class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors for console output (fallback if rich not available)."""
    
    # ANSI color codes
    COLORS = {
        "DEBUG": "\033[36m",     # Cyan
        "INFO": "\033[32m",      # Green
        "SCAN": "\033[35m",      # Magenta
        "WARNING": "\033[33m",   # Yellow
        "ERROR": "\033[31m",     # Red
        "CRITICAL": "\033[1;31m" # Bold Red
    }
    RESET = "\033[0m"
    
    def format(self, record: logging.LogRecord) -> str:
        # Add color to level name
        levelname = record.levelname
        if levelname in self.COLORS:
            record.levelname = f"{self.COLORS[levelname]}{levelname}{self.RESET}"
        
        return super().format(record)


def setup_logger(
    name: str = "network_analyzer",
    level: int = logging.INFO,
    log_file: Optional[Path] = None,
    log_to_console: bool = True,
    log_to_file: bool = True
) -> logging.Logger:
    """
    Set up and configure a logger.
    
    Args:
        name: Logger name
        level: Logging level (default: INFO)
        log_file: Path to log file (default: logs/network_analyzer.log)
        log_to_console: Whether to log to console
        log_to_file: Whether to log to file
    
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    
    # Avoid duplicate handlers
    if name in _loggers:
        return _loggers[name]
    
    logger.setLevel(level)
    logger.propagate = False
    
    # Console handler
    if log_to_console:
        if RICH_AVAILABLE:
            console_handler = RichHandler(
                console=Console(stderr=True),
                show_time=True,
                show_path=False,
                rich_tracebacks=True,
                tracebacks_show_locals=True
            )
            console_handler.setFormatter(logging.Formatter("%(message)s"))
        else:
            console_handler = logging.StreamHandler(sys.stderr)
            console_handler.setFormatter(ColoredFormatter(
                "%(asctime)s │ %(levelname)-8s │ %(message)s",
                datefmt="%H:%M:%S"
            ))
        
        console_handler.setLevel(level)
        logger.addHandler(console_handler)
    
    # File handler
    if log_to_file:
        if log_file is None:
            # Default log directory
            log_dir = Path.cwd() / "logs"
            log_dir.mkdir(exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d")
            log_file = log_dir / f"network_analyzer_{timestamp}.log"
        else:
            log_file = Path(log_file)
            log_file.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)  # File gets all logs
        file_handler.setFormatter(logging.Formatter(
            "%(asctime)s │ %(levelname)-8s │ %(name)s │ %(funcName)s:%(lineno)d │ %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        ))
        logger.addHandler(file_handler)
    
    _loggers[name] = logger
    return logger


def get_logger(name: str = "network_analyzer") -> logging.Logger:
    """
    Get an existing logger or create a new one with default settings.
    
    Args:
        name: Logger name
    
    Returns:
        Logger instance
    """
    if name in _loggers:
        return _loggers[name]
    return setup_logger(name)


def log_scan(logger: logging.Logger, message: str, *args, **kwargs):
    """Log a scan-related message at SCAN level."""
    logger.log(SCAN, message, *args, **kwargs)


# Convenience function to add scan method to loggers
def _patch_logger_scan_method():
    """Add scan() method to Logger class."""
    def scan(self, message, *args, **kwargs):
        if self.isEnabledFor(SCAN):
            self._log(SCAN, message, args, **kwargs)
    
    logging.Logger.scan = scan


_patch_logger_scan_method()
