"""
Network Scanner Module - Host discovery and network mapping.

This module provides network scanning capabilities using nmap
for discovering hosts, identifying live systems, and mapping
network topology.
"""

from .network_scanner import (
    NetworkScanner,
    DiscoveredHost,
    ScanResult,
    DiscoveryMethod
)

from .port_scanner import (
    PortScanner,
    PortInfo,
    HostScanResult,
    PortScanResult,
    ScanType,
    TimingTemplate,
    PortPresets
)

from .service_detector import (
    ServiceDetector,
    ServiceInfo,
    HostServiceInfo,
    CPEInfo,
    SSLInfo,
    OSInfo
)

__all__ = [
    # Network Discovery
    "NetworkScanner",
    "DiscoveredHost",
    "ScanResult",
    "DiscoveryMethod",
    # Port Scanning
    "PortScanner",
    "PortInfo",
    "HostScanResult",
    "PortScanResult",
    "ScanType",
    "TimingTemplate",
    "PortPresets",
    # Service Detection
    "ServiceDetector",
    "ServiceInfo",
    "HostServiceInfo",
    "CPEInfo",
    "SSLInfo",
    "OSInfo"
]
