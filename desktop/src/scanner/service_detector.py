"""
Service Detector - Enhanced service detection and fingerprinting.

Provides deep service detection capabilities including:
- Version detection
- CPE extraction for CVE matching
- SSL/TLS certificate analysis
- OS fingerprinting
- Banner grabbing
"""

import os
import re
import shutil
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from src.core import get_logger, get_config
from src.core.exceptions import (
    ServiceDetectionError,
    InsufficientPrivilegesError,
)


@dataclass
class CPEInfo:
    """Common Platform Enumeration (CPE) information."""
    
    cpe_string: str  # Full CPE string: cpe:/a:vendor:product:version
    part: str = ""   # a=application, o=os, h=hardware
    vendor: str = ""
    product: str = ""
    version: str = ""
    update: str = ""
    edition: str = ""
    language: str = ""
    
    @classmethod
    def from_string(cls, cpe_string: str) -> "CPEInfo":
        """Parse CPE string into components."""
        info = cls(cpe_string=cpe_string)
        
        # CPE 2.2 format: cpe:/part:vendor:product:version:update:edition:language
        # CPE 2.3 format: cpe:2.3:part:vendor:product:version:update:edition:sw_edition:target_sw:target_hw:other
        
        if cpe_string.startswith("cpe:2.3:"):
            # CPE 2.3 format
            parts = cpe_string.split(":")
            if len(parts) >= 5:
                info.part = parts[2] if len(parts) > 2 else ""
                info.vendor = parts[3] if len(parts) > 3 else ""
                info.product = parts[4] if len(parts) > 4 else ""
                info.version = parts[5] if len(parts) > 5 and parts[5] != "*" else ""
                info.update = parts[6] if len(parts) > 6 and parts[6] != "*" else ""
        elif cpe_string.startswith("cpe:/"):
            # CPE 2.2 format
            cpe_body = cpe_string[5:]  # Remove "cpe:/"
            parts = cpe_body.split(":")
            if len(parts) >= 1:
                info.part = parts[0] if parts[0] else ""
                info.vendor = parts[1] if len(parts) > 1 else ""
                info.product = parts[2] if len(parts) > 2 else ""
                info.version = parts[3] if len(parts) > 3 else ""
                info.update = parts[4] if len(parts) > 4 else ""
        
        return info
    
    def to_dict(self) -> dict:
        return {
            "cpe_string": self.cpe_string,
            "part": self.part,
            "vendor": self.vendor,
            "product": self.product,
            "version": self.version,
            "update": self.update
        }
    
    def __str__(self) -> str:
        return f"{self.vendor} {self.product} {self.version}".strip()


@dataclass
class SSLInfo:
    """SSL/TLS certificate information."""
    
    enabled: bool = False
    protocol: str = ""  # TLSv1.2, TLSv1.3, etc.
    cipher: str = ""
    issuer: str = ""
    subject: str = ""
    valid_from: Optional[str] = None
    valid_until: Optional[str] = None
    expired: bool = False
    self_signed: bool = False
    common_name: str = ""
    alt_names: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            "enabled": self.enabled,
            "protocol": self.protocol,
            "cipher": self.cipher,
            "issuer": self.issuer,
            "subject": self.subject,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "expired": self.expired,
            "self_signed": self.self_signed,
            "common_name": self.common_name,
            "alt_names": self.alt_names
        }


@dataclass
class ServiceInfo:
    """Detailed service information from detection."""
    
    port: int
    protocol: str = "tcp"
    state: str = "open"
    
    # Service identification
    service_name: str = ""
    product: str = ""
    version: str = ""
    extra_info: str = ""
    
    # Fingerprinting
    fingerprint: str = ""
    confidence: int = 0  # 0-100
    
    # CPE for vulnerability matching
    cpes: list[CPEInfo] = field(default_factory=list)
    
    # Banner and scripts
    banner: str = ""
    scripts: dict = field(default_factory=dict)
    
    # SSL/TLS info
    ssl: Optional[SSLInfo] = None
    
    # Detected hostname from service
    hostname: str = ""
    
    @property
    def full_version(self) -> str:
        """Get full version string."""
        parts = []
        if self.product:
            parts.append(self.product)
        if self.version:
            parts.append(self.version)
        if self.extra_info:
            parts.append(f"({self.extra_info})")
        return " ".join(parts)
    
    @property
    def has_cpe(self) -> bool:
        """Check if service has CPE identifiers."""
        return len(self.cpes) > 0
    
    def to_dict(self) -> dict:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "service_name": self.service_name,
            "product": self.product,
            "version": self.version,
            "extra_info": self.extra_info,
            "full_version": self.full_version,
            "fingerprint": self.fingerprint,
            "confidence": self.confidence,
            "cpes": [cpe.to_dict() for cpe in self.cpes],
            "banner": self.banner,
            "scripts": self.scripts,
            "ssl": self.ssl.to_dict() if self.ssl else None,
            "hostname": self.hostname
        }


@dataclass
class OSInfo:
    """Operating system detection information."""
    
    name: str = ""
    family: str = ""  # Windows, Linux, macOS, etc.
    vendor: str = ""
    version: str = ""
    accuracy: int = 0  # 0-100
    cpes: list[CPEInfo] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "family": self.family,
            "vendor": self.vendor,
            "version": self.version,
            "accuracy": self.accuracy,
            "cpes": [cpe.to_dict() for cpe in self.cpes]
        }


@dataclass
class HostServiceInfo:
    """Complete service information for a host."""
    
    ip_address: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    vendor: Optional[str] = None
    
    services: list[ServiceInfo] = field(default_factory=list)
    os_info: Optional[OSInfo] = None
    
    # All CPEs from this host (for CVE lookup)
    all_cpes: list[CPEInfo] = field(default_factory=list)
    
    scan_time: float = 0.0
    scanned_at: datetime = field(default_factory=datetime.now)
    
    @property
    def open_services(self) -> list[ServiceInfo]:
        """Get only open services."""
        return [s for s in self.services if s.state == "open"]
    
    @property
    def services_with_cpe(self) -> list[ServiceInfo]:
        """Get services that have CPE identifiers."""
        return [s for s in self.services if s.has_cpe]
    
    def collect_all_cpes(self):
        """Collect all CPEs from services and OS into all_cpes list."""
        self.all_cpes = []
        
        # Service CPEs
        for service in self.services:
            self.all_cpes.extend(service.cpes)
        
        # OS CPEs
        if self.os_info:
            self.all_cpes.extend(self.os_info.cpes)
    
    def to_dict(self) -> dict:
        self.collect_all_cpes()
        return {
            "ip_address": self.ip_address,
            "hostname": self.hostname,
            "mac_address": self.mac_address,
            "vendor": self.vendor,
            "services": [s.to_dict() for s in self.services],
            "os_info": self.os_info.to_dict() if self.os_info else None,
            "all_cpes": [cpe.to_dict() for cpe in self.all_cpes],
            "open_services_count": len(self.open_services),
            "cpe_count": len(self.all_cpes),
            "scan_time": self.scan_time,
            "scanned_at": self.scanned_at.isoformat()
        }


class ServiceDetector:
    """
    Enhanced service detection using nmap.
    
    Provides deep service fingerprinting, CPE extraction,
    SSL/TLS analysis, and OS detection.
    """
    
    # NSE scripts for enhanced detection
    DEFAULT_SCRIPTS = [
        "banner",
        "ssl-cert",
        "ssl-enum-ciphers",
        "http-title",
        "http-server-header",
    ]
    
    def __init__(self, nmap_path: Optional[str] = None):
        """Initialize the service detector."""
        self.logger = get_logger("service_detector")
        self.config = get_config()
        self.console = Console()
        
        self.nmap_path = nmap_path or self._find_nmap()
        
        if not self.nmap_path:
            raise ServiceDetectionError("Nmap not found")
        
        self._init_nmap_scanner()
        self.logger.info(f"Service detector initialized with nmap at: {self.nmap_path}")
    
    def _find_nmap(self) -> Optional[str]:
        """Find nmap executable."""
        nmap_in_path = shutil.which("nmap")
        if nmap_in_path:
            return nmap_in_path
        
        common_paths = [
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe",
            "/usr/bin/nmap",
            "/usr/local/bin/nmap",
        ]
        
        for path in common_paths:
            if os.path.isfile(path):
                return path
        
        return None
    
    def _init_nmap_scanner(self):
        """Initialize nmap scanner."""
        if not NMAP_AVAILABLE:
            raise ServiceDetectionError("python-nmap not installed")
        
        try:
            if self.nmap_path and shutil.which("nmap") != self.nmap_path:
                nmap_dir = os.path.dirname(self.nmap_path)
                os.environ["PATH"] = nmap_dir + os.pathsep + os.environ.get("PATH", "")
            
            self.scanner = nmap.PortScanner()
            self.scanner.nmap_version()
            
        except nmap.PortScannerError as e:
            raise ServiceDetectionError(f"Failed to initialize nmap: {e}")
    
    def detect_services(
        self,
        target: str,
        ports: Optional[str] = None,
        os_detection: bool = False,
        ssl_scripts: bool = True,
        intensity: int = 7,
        timing: int = 3,
        show_progress: bool = True
    ) -> list[HostServiceInfo]:
        """
        Perform detailed service detection on target.
        
        Args:
            target: IP, hostname, or CIDR range
            ports: Port specification (e.g., "22,80,443" or "1-1000")
            os_detection: Enable OS detection (requires privileges)
            ssl_scripts: Run SSL/TLS scripts
            intensity: Version detection intensity (0-9)
            timing: Timing template (0-5)
            show_progress: Show progress spinner
        
        Returns:
            List of HostServiceInfo with detected services
        """
        self.logger.info(f"Starting service detection on {target}")
        
        # Build arguments
        args = [
            "-sV",  # Version detection
            f"--version-intensity {intensity}",
            f"-T{timing}",
            "-v"
        ]
        
        # OS detection
        if os_detection:
            args.append("-O")
        
        # SSL scripts
        if ssl_scripts:
            args.append("--script=banner,ssl-cert,http-title,http-server-header")
        
        args_str = " ".join(args)
        
        results: list[HostServiceInfo] = []
        
        try:
            if show_progress:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TaskProgressColumn(),
                    console=self.console,
                    transient=True
                ) as progress:
                    task = progress.add_task(
                        f"[cyan]Detecting services on {target}...",
                        total=None
                    )
                    
                    if ports:
                        self.scanner.scan(hosts=target, ports=ports, arguments=args_str)
                    else:
                        self.scanner.scan(hosts=target, arguments=f"{args_str} --top-ports 100")
                    
                    progress.update(task, completed=True)
            else:
                if ports:
                    self.scanner.scan(hosts=target, ports=ports, arguments=args_str)
                else:
                    self.scanner.scan(hosts=target, arguments=f"{args_str} --top-ports 100")
            
            # Parse results
            scan_time = float(self.scanner.scanstats().get('elapsed', 0))
            
            for host_ip in self.scanner.all_hosts():
                host_result = self._parse_host_services(host_ip, self.scanner[host_ip])
                host_result.scan_time = scan_time
                host_result.collect_all_cpes()
                results.append(host_result)
                
                self.logger.info(
                    f"Host {host_ip}: {len(host_result.open_services)} services, "
                    f"{len(host_result.all_cpes)} CPEs"
                )
            
            return results
            
        except nmap.PortScannerError as e:
            if "root" in str(e).lower() or "permission" in str(e).lower():
                raise InsufficientPrivilegesError("OS detection")
            raise ServiceDetectionError(f"Service detection failed: {e}")
    
    def _parse_host_services(self, host_ip: str, host_data: dict) -> HostServiceInfo:
        """Parse host data into HostServiceInfo."""
        # Get hostname
        hostnames = host_data.get('hostnames', [])
        hostname = hostnames[0]['name'] if hostnames and hostnames[0].get('name') else None
        
        # Get MAC and vendor
        mac_address = host_data.get('addresses', {}).get('mac')
        vendor = None
        if mac_address and 'vendor' in host_data:
            vendor = host_data['vendor'].get(mac_address)
        
        host_info = HostServiceInfo(
            ip_address=host_ip,
            hostname=hostname,
            mac_address=mac_address,
            vendor=vendor
        )
        
        # Parse services
        for protocol in ['tcp', 'udp']:
            if protocol in host_data:
                for port_num, port_data in host_data[protocol].items():
                    service = self._parse_service(int(port_num), protocol, port_data)
                    host_info.services.append(service)
        
        # Parse OS detection
        if 'osmatch' in host_data and host_data['osmatch']:
            host_info.os_info = self._parse_os_info(host_data['osmatch'])
        
        return host_info
    
    def _parse_service(self, port: int, protocol: str, port_data: dict) -> ServiceInfo:
        """Parse port data into ServiceInfo."""
        service = ServiceInfo(
            port=port,
            protocol=protocol,
            state=port_data.get('state', 'unknown'),
            service_name=port_data.get('name', ''),
            product=port_data.get('product', ''),
            version=port_data.get('version', ''),
            extra_info=port_data.get('extrainfo', ''),
            confidence=int(port_data.get('conf', 0)) * 10  # Scale to 0-100
        )
        
        # Parse CPEs
        cpe_data = port_data.get('cpe', [])
        if isinstance(cpe_data, str):
            cpe_data = [cpe_data]
        
        for cpe_string in cpe_data:
            if cpe_string:
                service.cpes.append(CPEInfo.from_string(cpe_string))
        
        # Parse scripts
        if 'script' in port_data:
            service.scripts = port_data['script']
            
            # Extract banner
            if 'banner' in port_data['script']:
                service.banner = port_data['script']['banner']
            
            # Parse SSL certificate
            if 'ssl-cert' in port_data['script']:
                service.ssl = self._parse_ssl_info(port_data['script']['ssl-cert'])
        
        return service
    
    def _parse_ssl_info(self, ssl_script_output: str) -> SSLInfo:
        """Parse SSL certificate information from nmap script output."""
        ssl_info = SSLInfo(enabled=True)
        
        # Parse subject
        subject_match = re.search(r'Subject: (.+?)(?=\n|$)', ssl_script_output)
        if subject_match:
            ssl_info.subject = subject_match.group(1).strip()
            # Extract common name
            cn_match = re.search(r'commonName=([^/\n]+)', ssl_info.subject)
            if cn_match:
                ssl_info.common_name = cn_match.group(1).strip()
        
        # Parse issuer
        issuer_match = re.search(r'Issuer: (.+?)(?=\n|$)', ssl_script_output)
        if issuer_match:
            ssl_info.issuer = issuer_match.group(1).strip()
        
        # Check self-signed
        if ssl_info.issuer and ssl_info.subject:
            ssl_info.self_signed = ssl_info.issuer == ssl_info.subject
        
        # Parse validity
        not_before = re.search(r'Not valid before:\s*(.+?)(?=\n|$)', ssl_script_output)
        if not_before:
            ssl_info.valid_from = not_before.group(1).strip()
        
        not_after = re.search(r'Not valid after:\s*(.+?)(?=\n|$)', ssl_script_output)
        if not_after:
            ssl_info.valid_until = not_after.group(1).strip()
        
        # Parse alternative names
        alt_names = re.search(r'Subject Alternative Name:\s*(.+?)(?=\n\S|\Z)', ssl_script_output, re.DOTALL)
        if alt_names:
            names = re.findall(r'DNS:([^\s,]+)', alt_names.group(1))
            ssl_info.alt_names = names
        
        return ssl_info
    
    def _parse_os_info(self, osmatch_data: list) -> OSInfo:
        """Parse OS detection data."""
        if not osmatch_data:
            return None
        
        # Use the best match (first one)
        best_match = osmatch_data[0]
        
        os_info = OSInfo(
            name=best_match.get('name', ''),
            accuracy=int(best_match.get('accuracy', 0))
        )
        
        # Parse OS class for family/vendor
        if 'osclass' in best_match and best_match['osclass']:
            osclass = best_match['osclass'][0]
            os_info.family = osclass.get('osfamily', '')
            os_info.vendor = osclass.get('vendor', '')
            os_info.version = osclass.get('osgen', '')
            
            # Parse OS CPE
            if 'cpe' in osclass:
                cpe_data = osclass['cpe']
                if isinstance(cpe_data, str):
                    cpe_data = [cpe_data]
                for cpe_string in cpe_data:
                    if cpe_string:
                        os_info.cpes.append(CPEInfo.from_string(cpe_string))
        
        return os_info
    
    def print_results(self, results: list[HostServiceInfo]):
        """Print service detection results."""
        for host in results:
            # Host header
            header = f"[bold cyan]{host.ip_address}[/bold cyan]"
            if host.hostname:
                header += f" ({host.hostname})"
            
            self.console.print(Panel(header, expand=False))
            
            # OS info
            if host.os_info:
                self.console.print(
                    f"  [dim]OS:[/dim] {host.os_info.name} "
                    f"({host.os_info.accuracy}% accuracy)"
                )
            
            # Services table
            if host.open_services:
                table = Table(show_header=True, header_style="bold magenta", box=None)
                table.add_column("Port", style="cyan", width=12)
                table.add_column("Service", width=15)
                table.add_column("Product/Version", width=35)
                table.add_column("CPE", style="dim", width=40)
                
                for svc in sorted(host.open_services, key=lambda s: s.port):
                    cpe_str = svc.cpes[0].cpe_string[:40] if svc.cpes else "-"
                    table.add_row(
                        f"{svc.port}/{svc.protocol}",
                        svc.service_name,
                        svc.full_version[:35],
                        cpe_str
                    )
                
                self.console.print(table)
            
            # CPE summary
            if host.all_cpes:
                self.console.print(f"\n  [green]✓[/green] {len(host.all_cpes)} CPE(s) extracted for CVE lookup")
            else:
                self.console.print("\n  [yellow]⚠[/yellow] No CPEs found - CVE lookup may be limited")
            
            self.console.print()
