"""
Port Scanner - TCP, UDP, and SYN port scanning using nmap.

Provides comprehensive port scanning capabilities with multiple
scan types, timing profiles, and banner grabbing.
"""

import os
import shutil
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional, Callable
from datetime import datetime

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.console import Console
from rich.table import Table

from src.core import get_logger, get_config
from src.core.exceptions import (
    PortScanError,
    InsufficientPrivilegesError,
    InvalidTargetError,
    TargetUnreachableError
)


class ScanType(Enum):
    """Port scan types available."""
    
    TCP_CONNECT = auto()  # -sT: Full TCP connect (no privileges needed)
    TCP_SYN = auto()      # -sS: SYN stealth scan (requires privileges)
    UDP = auto()          # -sU: UDP scan (slow, requires privileges)
    TCP_ACK = auto()      # -sA: ACK scan (firewall detection)
    TCP_FIN = auto()      # -sF: FIN scan (stealthier)
    XMAS = auto()         # -sX: Xmas scan (FIN, PSH, URG flags)
    NULL = auto()         # -sN: Null scan (no flags)
    COMPREHENSIVE = auto()  # Combined TCP + top UDP


class TimingTemplate(Enum):
    """Nmap timing templates."""
    
    PARANOID = 0    # T0: Very slow, IDS evasion
    SNEAKY = 1      # T1: Slow, IDS evasion
    POLITE = 2      # T2: Slower, less bandwidth
    NORMAL = 3      # T3: Default
    AGGRESSIVE = 4  # T4: Faster, assumes good network
    INSANE = 5      # T5: Fastest, may miss ports


# Predefined port lists
class PortPresets:
    """Common port presets for quick scanning."""
    
    # Top 20 most common ports
    TOP_20 = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"
    
    # Top 100 most common ports (nmap default)
    TOP_100 = "--top-ports 100"
    
    # Top 1000 most common ports
    TOP_1000 = "--top-ports 1000"
    
    # Web services
    WEB = "80,443,8080,8443,8000,8888,3000,5000,9000"
    
    # Database services
    DATABASE = "1433,1521,3306,5432,6379,27017,9042,7199"
    
    # Remote access
    REMOTE_ACCESS = "22,23,3389,5900,5901,5902"
    
    # Mail services
    MAIL = "25,110,143,465,587,993,995"
    
    # File sharing
    FILE_SHARE = "21,22,139,445,873,2049"
    
    # All ports
    ALL = "1-65535"


@dataclass
class PortInfo:
    """Information about a single port."""
    
    port: int
    protocol: str = "tcp"  # tcp or udp
    state: str = "unknown"  # open, closed, filtered, open|filtered
    service: str = ""
    version: str = ""
    product: str = ""
    extra_info: str = ""
    cpe: list[str] = field(default_factory=list)
    scripts: dict = field(default_factory=dict)
    banner: str = ""
    
    def __str__(self) -> str:
        service_str = self.service
        if self.version:
            service_str += f" {self.version}"
        return f"{self.port}/{self.protocol} {self.state} {service_str}"
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service,
            "version": self.version,
            "product": self.product,
            "extra_info": self.extra_info,
            "cpe": self.cpe,
            "scripts": self.scripts,
            "banner": self.banner
        }


@dataclass
class HostScanResult:
    """Results from scanning a single host."""
    
    ip_address: str
    hostname: Optional[str] = None
    state: str = "up"
    ports: list[PortInfo] = field(default_factory=list)
    os_matches: list[dict] = field(default_factory=list)
    mac_address: Optional[str] = None
    vendor: Optional[str] = None
    
    @property
    def open_ports(self) -> list[PortInfo]:
        """Get only open ports."""
        return [p for p in self.ports if p.state == "open"]
    
    @property
    def filtered_ports(self) -> list[PortInfo]:
        """Get filtered ports."""
        return [p for p in self.ports if "filtered" in p.state]
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "ip_address": self.ip_address,
            "hostname": self.hostname,
            "state": self.state,
            "ports": [p.to_dict() for p in self.ports],
            "open_ports_count": len(self.open_ports),
            "os_matches": self.os_matches,
            "mac_address": self.mac_address,
            "vendor": self.vendor
        }


@dataclass
class PortScanResult:
    """Complete results from a port scan."""
    
    target: str
    hosts: list[HostScanResult] = field(default_factory=list)
    scan_type: str = ""
    ports_scanned: str = ""
    scan_arguments: str = ""
    scan_time: float = 0.0
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    errors: list[str] = field(default_factory=list)
    
    @property
    def total_open_ports(self) -> int:
        """Get total number of open ports across all hosts."""
        return sum(len(h.open_ports) for h in self.hosts)
    
    @property
    def hosts_with_open_ports(self) -> list[HostScanResult]:
        """Get hosts that have at least one open port."""
        return [h for h in self.hosts if h.open_ports]
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "target": self.target,
            "hosts": [h.to_dict() for h in self.hosts],
            "hosts_scanned": len(self.hosts),
            "total_open_ports": self.total_open_ports,
            "scan_type": self.scan_type,
            "ports_scanned": self.ports_scanned,
            "scan_arguments": self.scan_arguments,
            "scan_time": self.scan_time,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "errors": self.errors
        }


class PortScanner:
    """
    Port scanner using nmap for comprehensive port scanning.
    
    Supports multiple scan types including TCP Connect, SYN stealth,
    UDP, and various evasion techniques.
    """
    
    def __init__(self, nmap_path: Optional[str] = None):
        """
        Initialize the port scanner.
        
        Args:
            nmap_path: Optional path to nmap executable
        """
        self.logger = get_logger("port_scanner")
        self.config = get_config()
        self.console = Console()
        
        # Find nmap executable
        self.nmap_path = nmap_path or self._find_nmap()
        
        if not self.nmap_path:
            raise PortScanError(
                "Nmap not found. Please install nmap and ensure it's in PATH."
            )
        
        self._init_nmap_scanner()
        self.logger.info(f"Port scanner initialized with nmap at: {self.nmap_path}")
    
    def _find_nmap(self) -> Optional[str]:
        """Find nmap executable."""
        nmap_in_path = shutil.which("nmap")
        if nmap_in_path:
            return nmap_in_path
        
        # Check common paths
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
        """Initialize the nmap PortScanner."""
        if not NMAP_AVAILABLE:
            raise PortScanError("python-nmap not installed")
        
        try:
            if self.nmap_path and shutil.which("nmap") != self.nmap_path:
                nmap_dir = os.path.dirname(self.nmap_path)
                os.environ["PATH"] = nmap_dir + os.pathsep + os.environ.get("PATH", "")
            
            self.scanner = nmap.PortScanner()
            self.scanner.nmap_version()
            
        except nmap.PortScannerError as e:
            raise PortScanError(f"Failed to initialize nmap: {e}")
    
    def _get_scan_args(
        self,
        scan_type: ScanType,
        timing: TimingTemplate = TimingTemplate.NORMAL,
        service_detection: bool = True,
        os_detection: bool = False,
        script_scan: bool = False,
        aggressive: bool = False
    ) -> str:
        """
        Build nmap arguments for the scan type.
        
        Args:
            scan_type: Type of port scan
            timing: Timing template (T0-T5)
            service_detection: Enable service/version detection (-sV)
            os_detection: Enable OS detection (-O)
            script_scan: Enable default scripts (-sC)
            aggressive: Enable aggressive scan (-A)
        
        Returns:
            Nmap argument string
        """
        # Scan type arguments
        scan_type_args = {
            ScanType.TCP_CONNECT: "-sT",
            ScanType.TCP_SYN: "-sS",
            ScanType.UDP: "-sU",
            ScanType.TCP_ACK: "-sA",
            ScanType.TCP_FIN: "-sF",
            ScanType.XMAS: "-sX",
            ScanType.NULL: "-sN",
            ScanType.COMPREHENSIVE: "-sS -sU --top-ports 100",
        }
        
        args = [scan_type_args.get(scan_type, "-sT")]
        
        # Timing
        args.append(f"-T{timing.value}")
        
        # Aggressive scan includes -sV, -O, -sC, and traceroute
        if aggressive:
            args.append("-A")
        else:
            if service_detection:
                args.append("-sV")
            if os_detection:
                args.append("-O")
            if script_scan:
                args.append("-sC")
        
        # Verbose output
        args.append("-v")
        
        return " ".join(args)
    
    def scan_ports(
        self,
        target: str,
        ports: Optional[str] = None,
        scan_type: ScanType = ScanType.TCP_CONNECT,
        timing: TimingTemplate = TimingTemplate.NORMAL,
        service_detection: bool = True,
        os_detection: bool = False,
        script_scan: bool = False,
        show_progress: bool = True
    ) -> PortScanResult:
        """
        Scan ports on target host(s).
        
        Args:
            target: IP, hostname, or CIDR range
            ports: Port specification (e.g., "22,80,443" or "1-1000" or None for default)
            scan_type: Type of scan to perform
            timing: Timing template
            service_detection: Enable service/version detection
            os_detection: Enable OS detection (requires privileges)
            script_scan: Enable default NSE scripts
            show_progress: Show progress spinner
        
        Returns:
            PortScanResult with all findings
        
        Raises:
            PortScanError: If scan fails
            InsufficientPrivilegesError: If scan requires elevated privileges
        """
        self.logger.info(f"Starting {scan_type.name} scan on {target}")
        
        # Build scan arguments
        args = self._get_scan_args(
            scan_type=scan_type,
            timing=timing,
            service_detection=service_detection,
            os_detection=os_detection,
            script_scan=script_scan
        )
        
        # Handle port specification
        port_arg = ""
        if ports:
            if ports.startswith("--top-ports"):
                args += f" {ports}"
                port_arg = ports
            else:
                port_arg = ports
        else:
            # Default to top 100 ports
            args += " --top-ports 100"
            port_arg = "top 100"
        
        # Create result object
        result = PortScanResult(
            target=target,
            scan_type=scan_type.name,
            ports_scanned=port_arg,
            scan_arguments=args
        )
        
        try:
            # Execute scan with progress indicator
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
                        f"[cyan]Scanning {target}...",
                        total=None
                    )
                    
                    # Run the scan
                    if ports and not ports.startswith("--"):
                        self.scanner.scan(hosts=target, ports=ports, arguments=args)
                    else:
                        self.scanner.scan(hosts=target, arguments=args)
                    
                    progress.update(task, completed=True)
            else:
                if ports and not ports.startswith("--"):
                    self.scanner.scan(hosts=target, ports=ports, arguments=args)
                else:
                    self.scanner.scan(hosts=target, arguments=args)
            
            # Parse results
            result.completed_at = datetime.now()
            
            # Get scan stats
            try:
                stats = self.scanner.scanstats()
                result.scan_time = float(stats.get('elapsed', 0))
            except Exception:
                pass
            
            # Process each host
            for host_ip in self.scanner.all_hosts():
                host_data = self.scanner[host_ip]
                host_result = self._parse_host_result(host_ip, host_data)
                result.hosts.append(host_result)
                
                self.logger.debug(
                    f"Host {host_ip}: {len(host_result.open_ports)} open ports"
                )
            
            self.logger.info(
                f"Scan complete: {len(result.hosts)} host(s), "
                f"{result.total_open_ports} open port(s) in {result.scan_time:.2f}s"
            )
            
            return result
            
        except nmap.PortScannerError as e:
            error_msg = str(e).lower()
            
            if "requires root" in error_msg or "permission" in error_msg:
                raise InsufficientPrivilegesError(f"{scan_type.name} scan")
            
            raise PortScanError(f"Port scan failed: {e}")
    
    def _parse_host_result(self, host_ip: str, host_data: dict) -> HostScanResult:
        """Parse nmap host result into HostScanResult."""
        # Get hostname
        hostnames = host_data.get('hostnames', [])
        hostname = hostnames[0]['name'] if hostnames and hostnames[0].get('name') else None
        
        # Get state
        state = host_data.get('status', {}).get('state', 'up')
        
        # Get MAC and vendor
        mac_address = host_data.get('addresses', {}).get('mac')
        vendor = None
        if mac_address and 'vendor' in host_data:
            vendor = host_data['vendor'].get(mac_address)
        
        # Create result
        host_result = HostScanResult(
            ip_address=host_ip,
            hostname=hostname,
            state=state,
            mac_address=mac_address,
            vendor=vendor
        )
        
        # Parse ports for each protocol
        for protocol in ['tcp', 'udp']:
            if protocol in host_data:
                for port_num, port_data in host_data[protocol].items():
                    port_info = PortInfo(
                        port=int(port_num),
                        protocol=protocol,
                        state=port_data.get('state', 'unknown'),
                        service=port_data.get('name', ''),
                        version=port_data.get('version', ''),
                        product=port_data.get('product', ''),
                        extra_info=port_data.get('extrainfo', ''),
                        cpe=port_data.get('cpe', []) if isinstance(port_data.get('cpe'), list) else [port_data.get('cpe', '')] if port_data.get('cpe') else []
                    )
                    
                    # Get script results
                    if 'script' in port_data:
                        port_info.scripts = port_data['script']
                        # Banner is often in banner script
                        if 'banner' in port_data['script']:
                            port_info.banner = port_data['script']['banner']
                    
                    host_result.ports.append(port_info)
        
        # Parse OS detection results
        if 'osmatch' in host_data:
            for os_match in host_data['osmatch'][:3]:  # Top 3 matches
                host_result.os_matches.append({
                    'name': os_match.get('name', ''),
                    'accuracy': os_match.get('accuracy', '0'),
                    'osclass': os_match.get('osclass', [])
                })
        
        return host_result
    
    def quick_scan(
        self,
        target: str,
        show_progress: bool = True
    ) -> PortScanResult:
        """
        Perform a quick scan of top 100 ports.
        
        Args:
            target: Target to scan
            show_progress: Show progress
        
        Returns:
            PortScanResult
        """
        return self.scan_ports(
            target=target,
            ports=None,  # Uses --top-ports 100
            scan_type=ScanType.TCP_CONNECT,
            timing=TimingTemplate.AGGRESSIVE,
            service_detection=True,
            show_progress=show_progress
        )
    
    def full_scan(
        self,
        target: str,
        show_progress: bool = True
    ) -> PortScanResult:
        """
        Perform a comprehensive scan with service detection.
        
        Args:
            target: Target to scan
            show_progress: Show progress
        
        Returns:
            PortScanResult
        """
        return self.scan_ports(
            target=target,
            ports=PortPresets.TOP_1000,
            scan_type=ScanType.TCP_SYN,
            timing=TimingTemplate.NORMAL,
            service_detection=True,
            os_detection=True,
            show_progress=show_progress
        )
    
    def stealth_scan(
        self,
        target: str,
        ports: str = PortPresets.TOP_20,
        show_progress: bool = True
    ) -> PortScanResult:
        """
        Perform a stealthy SYN scan.
        
        Args:
            target: Target to scan
            ports: Ports to scan
            show_progress: Show progress
        
        Returns:
            PortScanResult
        """
        return self.scan_ports(
            target=target,
            ports=ports,
            scan_type=ScanType.TCP_SYN,
            timing=TimingTemplate.SNEAKY,
            service_detection=False,  # Skip version detection for stealth
            show_progress=show_progress
        )
    
    def print_results(self, result: PortScanResult):
        """
        Print scan results to console.
        
        Args:
            result: PortScanResult to display
        """
        self.console.print()
        self.console.print(f"[bold cyan]Port Scan Results for {result.target}[/bold cyan]")
        self.console.print(
            f"Scan Type: {result.scan_type} | Ports: {result.ports_scanned} | "
            f"Time: {result.scan_time:.2f}s"
        )
        self.console.print(
            f"Hosts: {len(result.hosts)} | "
            f"Open Ports: [green]{result.total_open_ports}[/green]"
        )
        self.console.print()
        
        if not result.hosts:
            self.console.print("[yellow]No hosts responded to scan.[/yellow]")
            return
        
        for host in result.hosts:
            if not host.open_ports and not host.filtered_ports:
                continue
            
            # Host header
            host_str = f"[bold]{host.ip_address}[/bold]"
            if host.hostname:
                host_str += f" ({host.hostname})"
            if host.mac_address:
                host_str += f" [{host.mac_address}]"
            if host.vendor:
                host_str += f" - {host.vendor}"
            
            self.console.print(host_str)
            
            # OS detection results
            if host.os_matches:
                top_os = host.os_matches[0]
                self.console.print(
                    f"  OS: {top_os['name']} ({top_os['accuracy']}% accuracy)",
                    style="dim"
                )
            
            # Port table
            if host.open_ports:
                table = Table(show_header=True, header_style="bold magenta", box=None)
                table.add_column("Port", style="cyan", width=8)
                table.add_column("State", width=10)
                table.add_column("Service", width=15)
                table.add_column("Version", width=30)
                table.add_column("Info", style="dim")
                
                for port in sorted(host.open_ports, key=lambda p: p.port):
                    state_style = "green" if port.state == "open" else "yellow"
                    version = port.version or port.product or ""
                    
                    table.add_row(
                        f"{port.port}/{port.protocol}",
                        f"[{state_style}]{port.state}[/{state_style}]",
                        port.service,
                        version[:30],
                        port.extra_info[:20] if port.extra_info else ""
                    )
                
                self.console.print(table)
            
            self.console.print()
        
        # Print errors
        if result.errors:
            self.console.print("[yellow]Warnings/Errors:[/yellow]")
            for error in result.errors:
                self.console.print(f"  • {error}")
