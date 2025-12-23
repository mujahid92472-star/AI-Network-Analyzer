"""
Network Scanner - Host discovery and network mapping using nmap.

Provides multiple discovery methods:
- ARP scan (fastest for local networks)
- ICMP ping sweep (works across subnets)
- TCP SYN discovery (stealthier, works when ICMP blocked)
"""

import os
import shutil
from dataclasses import dataclass, field
from enum import Enum, auto
from ipaddress import IPv4Network, IPv4Address, ip_network, ip_address
from typing import Optional, Callable
from datetime import datetime
import threading

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
    NetworkScanError,
    InsufficientPrivilegesError,
    InvalidTargetError,
    TargetUnreachableError
)


class DiscoveryMethod(Enum):
    """Host discovery methods available for scanning."""
    
    ARP = auto()       # -PR: ARP scan (local network only, fastest)
    ICMP_ECHO = auto() # -PE: ICMP echo request (ping)
    ICMP_TIMESTAMP = auto()  # -PP: ICMP timestamp request
    TCP_SYN = auto()   # -PS: TCP SYN to specified ports
    TCP_ACK = auto()   # -PA: TCP ACK to specified ports
    UDP = auto()       # -PU: UDP to specified ports
    SCTP = auto()      # -PY: SCTP INIT to specified ports
    AUTO = auto()      # Let scanner choose best method


@dataclass
class DiscoveredHost:
    """Represents a discovered host on the network."""
    
    ip_address: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    vendor: Optional[str] = None
    status: str = "up"
    discovery_method: Optional[str] = None
    response_time: Optional[float] = None  # in milliseconds
    os_guess: Optional[str] = None
    discovered_at: datetime = field(default_factory=datetime.now)
    
    def __str__(self) -> str:
        parts = [f"{self.ip_address}"]
        if self.hostname and self.hostname != self.ip_address:
            parts.append(f"({self.hostname})")
        if self.mac_address:
            parts.append(f"[{self.mac_address}]")
        if self.vendor:
            parts.append(f"- {self.vendor}")
        return " ".join(parts)
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "ip_address": self.ip_address,
            "hostname": self.hostname,
            "mac_address": self.mac_address,
            "vendor": self.vendor,
            "status": self.status,
            "discovery_method": self.discovery_method,
            "response_time": self.response_time,
            "os_guess": self.os_guess,
            "discovered_at": self.discovered_at.isoformat()
        }


@dataclass
class ScanResult:
    """Results from a network scan."""
    
    target: str
    hosts_discovered: list[DiscoveredHost] = field(default_factory=list)
    hosts_up: int = 0
    hosts_down: int = 0
    hosts_total: int = 0
    scan_time: float = 0.0  # seconds
    scan_method: str = ""
    scan_arguments: str = ""
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    errors: list[str] = field(default_factory=list)
    
    def __str__(self) -> str:
        return f"ScanResult({self.target}): {self.hosts_up} hosts up, {self.hosts_down} down"
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "target": self.target,
            "hosts_discovered": [h.to_dict() for h in self.hosts_discovered],
            "hosts_up": self.hosts_up,
            "hosts_down": self.hosts_down,
            "hosts_total": self.hosts_total,
            "scan_time": self.scan_time,
            "scan_method": self.scan_method,
            "scan_arguments": self.scan_arguments,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "errors": self.errors
        }


class NetworkScanner:
    """
    Network scanner using nmap for host discovery.
    
    Supports multiple discovery methods and provides
    progress feedback during scans.
    """
    
    # Default ports for TCP/UDP discovery
    DEFAULT_TCP_PORTS = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,3306,3389,8080"
    DEFAULT_UDP_PORTS = "53,67,68,69,123,135,137,138,139,161,162,445,500,514,520,631,1434,1900,4500,5353"
    
    def __init__(self, nmap_path: Optional[str] = None):
        """
        Initialize the network scanner.
        
        Args:
            nmap_path: Optional path to nmap executable. If not provided,
                      will search in common locations.
        """
        self.logger = get_logger("network_scanner")
        self.config = get_config()
        self.console = Console()
        self._progress_callback: Optional[Callable[[str, int, int], None]] = None
        
        # Find nmap executable
        self.nmap_path = nmap_path or self._find_nmap()
        
        if not self.nmap_path:
            raise NetworkScanError(
                "Nmap not found. Please install nmap and ensure it's in PATH "
                "or provide the path to the executable.",
                {"searched_paths": self._get_common_nmap_paths()}
            )
        
        # Initialize python-nmap with custom path if needed
        self._init_nmap_scanner()
        
        self.logger.info(f"Network scanner initialized with nmap at: {self.nmap_path}")
    
    def _find_nmap(self) -> Optional[str]:
        """Find nmap executable in PATH or common locations."""
        # First check PATH
        nmap_in_path = shutil.which("nmap")
        if nmap_in_path:
            return nmap_in_path
        
        # Check common installation paths
        for path in self._get_common_nmap_paths():
            if os.path.isfile(path):
                return path
        
        return None
    
    def _get_common_nmap_paths(self) -> list[str]:
        """Get common nmap installation paths by OS."""
        paths = []
        
        if os.name == 'nt':  # Windows
            paths.extend([
                r"C:\Program Files (x86)\Nmap\nmap.exe",
                r"C:\Program Files\Nmap\nmap.exe",
                os.path.expandvars(r"%LOCALAPPDATA%\Programs\Nmap\nmap.exe"),
            ])
        else:  # Unix-like
            paths.extend([
                "/usr/bin/nmap",
                "/usr/local/bin/nmap",
                "/opt/homebrew/bin/nmap",  # macOS Homebrew
            ])
        
        return paths
    
    def _init_nmap_scanner(self):
        """Initialize the nmap PortScanner with custom path if needed."""
        if not NMAP_AVAILABLE:
            raise NetworkScanError(
                "python-nmap library not installed. Install with: pip install python-nmap"
            )
        
        try:
            # python-nmap uses nmap from PATH by default
            # We can set it via environment variable or pass path to scan method
            if self.nmap_path and shutil.which("nmap") != self.nmap_path:
                # Temporarily modify PATH to include nmap directory
                nmap_dir = os.path.dirname(self.nmap_path)
                os.environ["PATH"] = nmap_dir + os.pathsep + os.environ.get("PATH", "")
            
            self.scanner = nmap.PortScanner()
            
            # Verify it works
            self.scanner.nmap_version()
            
        except nmap.PortScannerError as e:
            raise NetworkScanError(f"Failed to initialize nmap: {e}")
    
    def set_progress_callback(self, callback: Callable[[str, int, int], None]):
        """
        Set a callback for progress updates.
        
        Args:
            callback: Function that receives (message, current, total)
        """
        self._progress_callback = callback
    
    def _validate_target(self, target: str) -> str:
        """
        Validate and normalize the target specification.
        
        Args:
            target: IP, hostname, or CIDR notation
        
        Returns:
            Normalized target string
        
        Raises:
            InvalidTargetError: If target is invalid
        """
        target = target.strip()
        
        if not target:
            raise InvalidTargetError(target, "Target cannot be empty")
        
        # Check if it's a CIDR notation
        if "/" in target:
            try:
                network = ip_network(target, strict=False)
                return str(network)
            except ValueError as e:
                raise InvalidTargetError(target, f"Invalid CIDR notation: {e}")
        
        # Check if it's an IP address
        try:
            ip_address(target)
            return target
        except ValueError:
            pass
        
        # Assume it's a hostname - let nmap resolve it
        return target
    
    def _get_discovery_args(
        self,
        method: DiscoveryMethod,
        tcp_ports: Optional[str] = None,
        udp_ports: Optional[str] = None
    ) -> str:
        """
        Get nmap arguments for the specified discovery method.
        
        Args:
            method: Discovery method to use
            tcp_ports: Optional TCP ports for TCP discovery
            udp_ports: Optional UDP ports for UDP discovery
        
        Returns:
            Nmap argument string
        """
        args_map = {
            DiscoveryMethod.ARP: "-PR",
            DiscoveryMethod.ICMP_ECHO: "-PE",
            DiscoveryMethod.ICMP_TIMESTAMP: "-PP",
            DiscoveryMethod.TCP_SYN: f"-PS{tcp_ports or self.DEFAULT_TCP_PORTS}",
            DiscoveryMethod.TCP_ACK: f"-PA{tcp_ports or self.DEFAULT_TCP_PORTS}",
            DiscoveryMethod.UDP: f"-PU{udp_ports or self.DEFAULT_UDP_PORTS}",
            DiscoveryMethod.SCTP: "-PY",
            DiscoveryMethod.AUTO: "-PE -PS22,80,443 -PA80,443",  # Combined approach
        }
        
        return args_map.get(method, "-PE")
    
    def discover_hosts(
        self,
        target: str,
        method: DiscoveryMethod = DiscoveryMethod.AUTO,
        timing: int = 3,
        resolve_hostnames: bool = True,
        tcp_ports: Optional[str] = None,
        udp_ports: Optional[str] = None,
        show_progress: bool = True
    ) -> ScanResult:
        """
        Discover live hosts on the network.
        
        Args:
            target: IP, hostname, or CIDR range to scan
            method: Discovery method to use
            timing: Timing template (0-5, higher = faster but noisier)
            resolve_hostnames: Whether to resolve hostnames via DNS
            tcp_ports: Custom TCP ports for TCP-based discovery
            udp_ports: Custom UDP ports for UDP-based discovery
            show_progress: Whether to show progress in console
        
        Returns:
            ScanResult with discovered hosts
        
        Raises:
            NetworkScanError: If scan fails
            InvalidTargetError: If target is invalid
        """
        # Validate target
        normalized_target = self._validate_target(target)
        
        self.logger.info(f"Starting host discovery on {normalized_target} using {method.name}")
        
        # Build scan arguments
        discovery_args = self._get_discovery_args(method, tcp_ports, udp_ports)
        
        # Base arguments: host discovery only (-sn), no port scan
        args = f"-sn {discovery_args} -T{timing}"
        
        if resolve_hostnames:
            args += " -R"  # Always resolve
        else:
            args += " -n"  # Never resolve
        
        # Add verbose for more details
        args += " -v"
        
        # Create result object
        result = ScanResult(
            target=normalized_target,
            scan_method=method.name,
            scan_arguments=args
        )
        
        try:
            # Execute scan with progress
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
                        f"[cyan]Scanning {normalized_target}...",
                        total=None  # Indeterminate
                    )
                    
                    # Run scan
                    self.scanner.scan(
                        hosts=normalized_target,
                        arguments=args
                    )
                    
                    progress.update(task, completed=True)
            else:
                self.scanner.scan(hosts=normalized_target, arguments=args)
            
            # Process results
            result.completed_at = datetime.now()
            
            # Get scan stats
            scan_info = self.scanner.scaninfo()
            if 'error' in scan_info:
                result.errors.extend(scan_info['error'])
            
            # Parse scan stats from scanstats
            try:
                stats = self.scanner.scanstats()
                result.hosts_up = int(stats.get('uphosts', 0))
                result.hosts_down = int(stats.get('downhosts', 0))
                result.hosts_total = int(stats.get('totalhosts', 0))
                result.scan_time = float(stats.get('elapsed', 0))
            except Exception as e:
                self.logger.warning(f"Could not parse scan stats: {e}")
            
            # Extract host information
            for host_ip in self.scanner.all_hosts():
                host_data = self.scanner[host_ip]
                
                # Get hostname
                hostnames = host_data.get('hostnames', [])
                hostname = None
                if hostnames and hostnames[0].get('name'):
                    hostname = hostnames[0]['name']
                
                # Get MAC and vendor (only available on local network)
                mac_address = None
                vendor = None
                if 'mac' in host_data.get('addresses', {}):
                    mac_address = host_data['addresses']['mac']
                if 'vendor' in host_data:
                    vendor_dict = host_data['vendor']
                    if vendor_dict and mac_address:
                        vendor = vendor_dict.get(mac_address, None)
                
                # Get status
                status = host_data.get('status', {}).get('state', 'up')
                reason = host_data.get('status', {}).get('reason', '')
                
                # Create discovered host
                discovered = DiscoveredHost(
                    ip_address=host_ip,
                    hostname=hostname,
                    mac_address=mac_address,
                    vendor=vendor,
                    status=status,
                    discovery_method=reason
                )
                
                result.hosts_discovered.append(discovered)
                self.logger.debug(f"Discovered host: {discovered}")
            
            self.logger.info(
                f"Discovery complete: {result.hosts_up} hosts up, "
                f"{result.hosts_down} down in {result.scan_time:.2f}s"
            )
            
            return result
            
        except nmap.PortScannerError as e:
            error_msg = str(e)
            
            # Check for common errors
            if "requires root" in error_msg.lower() or "permission" in error_msg.lower():
                raise InsufficientPrivilegesError("ARP/SYN scan")
            
            raise NetworkScanError(f"Nmap scan failed: {error_msg}")
            
        except Exception as e:
            self.logger.error(f"Unexpected error during scan: {e}")
            raise NetworkScanError(f"Scan failed: {e}")
    
    def quick_scan(self, target: str, show_progress: bool = True) -> ScanResult:
        """
        Perform a quick host discovery using ping sweep.
        
        Args:
            target: IP, hostname, or CIDR range
            show_progress: Whether to show progress
        
        Returns:
            ScanResult with discovered hosts
        """
        return self.discover_hosts(
            target=target,
            method=DiscoveryMethod.ICMP_ECHO,
            timing=4,  # Aggressive timing
            resolve_hostnames=True,
            show_progress=show_progress
        )
    
    def arp_scan(self, target: str, show_progress: bool = True) -> ScanResult:
        """
        Perform ARP-based discovery (local network only).
        
        This is the fastest and most reliable method for local networks,
        but only works within the same subnet.
        
        Args:
            target: IP, hostname, or CIDR range (should be local network)
            show_progress: Whether to show progress
        
        Returns:
            ScanResult with discovered hosts
        """
        return self.discover_hosts(
            target=target,
            method=DiscoveryMethod.ARP,
            timing=4,
            resolve_hostnames=True,
            show_progress=show_progress
        )
    
    def stealth_scan(
        self,
        target: str,
        tcp_ports: str = "22,80,443",
        show_progress: bool = True
    ) -> ScanResult:
        """
        Perform TCP SYN-based discovery (stealthier, works when ICMP blocked).
        
        Args:
            target: IP, hostname, or CIDR range
            tcp_ports: TCP ports to probe for discovery
            show_progress: Whether to show progress
        
        Returns:
            ScanResult with discovered hosts
        """
        return self.discover_hosts(
            target=target,
            method=DiscoveryMethod.TCP_SYN,
            timing=3,  # Normal timing for stealth
            resolve_hostnames=True,
            tcp_ports=tcp_ports,
            show_progress=show_progress
        )
    
    def print_results(self, result: ScanResult):
        """
        Print scan results to console in a formatted table.
        
        Args:
            result: ScanResult to display
        """
        # Summary
        self.console.print()
        self.console.print(f"[bold cyan]Scan Results for {result.target}[/bold cyan]")
        self.console.print(f"Method: {result.scan_method} | Time: {result.scan_time:.2f}s")
        self.console.print(
            f"Hosts: [green]{result.hosts_up} up[/green], "
            f"[red]{result.hosts_down} down[/red], "
            f"{result.hosts_total} total"
        )
        self.console.print()
        
        if not result.hosts_discovered:
            self.console.print("[yellow]No hosts discovered.[/yellow]")
            return
        
        # Create table
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("IP Address", style="cyan")
        table.add_column("Hostname")
        table.add_column("MAC Address", style="dim")
        table.add_column("Vendor")
        table.add_column("Status", justify="center")
        table.add_column("Method", style="dim")
        
        for host in result.hosts_discovered:
            status_style = "green" if host.status == "up" else "red"
            table.add_row(
                host.ip_address,
                host.hostname or "-",
                host.mac_address or "-",
                host.vendor or "-",
                f"[{status_style}]{host.status}[/{status_style}]",
                host.discovery_method or "-"
            )
        
        self.console.print(table)
        
        # Print errors if any
        if result.errors:
            self.console.print()
            self.console.print("[yellow]Warnings/Errors:[/yellow]")
            for error in result.errors:
                self.console.print(f"  • {error}")
