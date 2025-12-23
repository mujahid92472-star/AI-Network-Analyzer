"""
Custom exceptions for AI Network Analyzer.

Provides a hierarchy of exceptions for different error scenarios
encountered during network scanning and analysis.
"""


class NetworkAnalyzerError(Exception):
    """Base exception for all AI Network Analyzer errors."""
    
    def __init__(self, message: str, details: dict = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}
    
    def __str__(self) -> str:
        if self.details:
            return f"{self.message} | Details: {self.details}"
        return self.message


class ConfigurationError(NetworkAnalyzerError):
    """Raised when there's a configuration-related error."""
    pass


class ScanError(NetworkAnalyzerError):
    """Base exception for scanning-related errors."""
    pass


class NetworkScanError(ScanError):
    """Raised when network discovery fails."""
    pass


class PortScanError(ScanError):
    """Raised when port scanning fails."""
    pass


class ServiceDetectionError(ScanError):
    """Raised when service detection fails."""
    pass


class CVELookupError(NetworkAnalyzerError):
    """Raised when CVE lookup fails."""
    pass


class NVDAPIError(CVELookupError):
    """Raised when NVD API request fails."""
    
    def __init__(self, message: str, status_code: int = None, details: dict = None):
        super().__init__(message, details)
        self.status_code = status_code


class OfflineDBError(CVELookupError):
    """Raised when offline CVE database operations fail."""
    pass


class ReportGenerationError(NetworkAnalyzerError):
    """Raised when report generation fails."""
    pass


class InsufficientPrivilegesError(NetworkAnalyzerError):
    """Raised when operation requires elevated privileges."""
    
    def __init__(self, operation: str):
        message = f"Operation '{operation}' requires elevated privileges (run as administrator/root)"
        super().__init__(message, {"operation": operation})


class TargetUnreachableError(ScanError):
    """Raised when target host is unreachable."""
    
    def __init__(self, target: str, reason: str = None):
        message = f"Target '{target}' is unreachable"
        if reason:
            message += f": {reason}"
        super().__init__(message, {"target": target, "reason": reason})


class InvalidTargetError(ScanError):
    """Raised when target specification is invalid."""
    
    def __init__(self, target: str, reason: str = None):
        message = f"Invalid target specification: '{target}'"
        if reason:
            message += f" - {reason}"
        super().__init__(message, {"target": target, "reason": reason})


class RateLimitError(CVELookupError):
    """Raised when API rate limit is exceeded."""
    
    def __init__(self, retry_after: int = None):
        message = "API rate limit exceeded"
        if retry_after:
            message += f". Retry after {retry_after} seconds"
        super().__init__(message, {"retry_after": retry_after})
        self.retry_after = retry_after
