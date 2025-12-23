"""
Console Reporter - Rich CLI output for security scan results.

Provides beautiful, color-coded terminal output with:
- Severity color coding (🔴 Critical, 🟠 High, 🟡 Medium, 🟢 Low, ⚪ Info)
- Progress bars for long-running scans
- Live tables for real-time results
- Tree view for network topology
- Summary statistics panels
"""

from dataclasses import dataclass
from typing import Optional
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TaskProgressColumn, TimeElapsedColumn
from rich.layout import Layout
from rich.live import Live
from rich.text import Text
from rich.style import Style
from rich import box

from src.core import get_logger


# Severity color mapping
SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "orange1",
    "MEDIUM": "yellow",
    "LOW": "blue",
    "INFO": "dim white",
    "NONE": "dim"
}

SEVERITY_ICONS = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🟢",
    "INFO": "⚪",
    "NONE": "⚫"
}


@dataclass
class ScanStatistics:
    """Statistics from a security scan."""
    
    total_hosts: int = 0
    hosts_up: int = 0
    total_ports: int = 0
    open_ports: int = 0
    total_services: int = 0
    total_cves: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    scan_duration: float = 0.0
    
    @property
    def risk_score(self) -> float:
        """Calculate overall risk score (0-100)."""
        if self.total_cves == 0:
            return 0.0
        score = (
            self.critical_count * 40 +
            self.high_count * 20 +
            self.medium_count * 10 +
            self.low_count * 5
        )
        return min(100.0, score)
    
    @property
    def risk_level(self) -> str:
        """Get risk level from score."""
        score = self.risk_score
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        elif score >= 20:
            return "LOW"
        else:
            return "INFO"


class ConsoleReporter:
    """
    Rich console reporter for security scan results.
    
    Provides color-coded, professional terminal output with
    severity indicators, progress bars, and summary statistics.
    """
    
    def __init__(self, console: Optional[Console] = None):
        """
        Initialize the console reporter.
        
        Args:
            console: Optional Rich Console instance
        """
        self.console = console or Console()
        self.logger = get_logger("console_reporter")
    
    # =========================================================================
    # Progress Indicators
    # =========================================================================
    
    def create_progress(self) -> Progress:
        """Create a progress bar for long-running operations."""
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=self.console,
            transient=True
        )
    
    def print_scan_start(self, target: str, scan_type: str = "scan"):
        """Print scan start message."""
        self.console.print()
        self.console.print(Panel(
            f"[bold cyan]Starting {scan_type}[/bold cyan]\n"
            f"Target: [bold]{target}[/bold]",
            title="🔍 Scan Initiated",
            expand=False
        ))
        self.console.print()
    
    # =========================================================================
    # Host Discovery Output
    # =========================================================================
    
    def print_discovered_hosts(self, hosts: list, show_tree: bool = True):
        """
        Print discovered hosts with tree view.
        
        Args:
            hosts: List of discovered hosts (dict with ip, hostname, mac, etc.)
            show_tree: Whether to show tree view
        """
        if not hosts:
            self.console.print("[yellow]No hosts discovered.[/yellow]")
            return
        
        if show_tree:
            tree = Tree("🌐 [bold]Network Topology[/bold]")
            
            for host in hosts:
                ip = host.get("ip_address", host.get("ip", "Unknown"))
                hostname = host.get("hostname", "")
                mac = host.get("mac_address", "")
                vendor = host.get("vendor", "")
                
                # Build host label
                label = f"[cyan]{ip}[/cyan]"
                if hostname:
                    label += f" ({hostname})"
                
                host_branch = tree.add(label)
                
                if mac:
                    host_branch.add(f"[dim]MAC: {mac}[/dim]")
                if vendor:
                    host_branch.add(f"[dim]Vendor: {vendor}[/dim]")
            
            self.console.print(tree)
        else:
            # Table view
            table = Table(
                title="Discovered Hosts",
                show_header=True,
                header_style="bold magenta",
                box=box.ROUNDED
            )
            table.add_column("IP Address", style="cyan")
            table.add_column("Hostname")
            table.add_column("MAC Address", style="dim")
            table.add_column("Vendor")
            
            for host in hosts:
                table.add_row(
                    host.get("ip_address", host.get("ip", "")),
                    host.get("hostname", ""),
                    host.get("mac_address", ""),
                    host.get("vendor", "")
                )
            
            self.console.print(table)
    
    # =========================================================================
    # Port Scan Output
    # =========================================================================
    
    def print_port_scan_results(self, host: str, ports: list):
        """
        Print port scan results with color-coded states.
        
        Args:
            host: Target host IP/hostname
            ports: List of port info dictionaries
        """
        if not ports:
            self.console.print(f"[yellow]No open ports found on {host}[/yellow]")
            return
        
        self.console.print(Panel(f"[bold]{host}[/bold]", expand=False))
        
        table = Table(
            show_header=True,
            header_style="bold magenta",
            box=box.SIMPLE
        )
        table.add_column("Port", style="cyan", width=10)
        table.add_column("State", width=10)
        table.add_column("Service", width=15)
        table.add_column("Version", width=35)
        table.add_column("Info", style="dim", width=20)
        
        for port in ports:
            port_num = port.get("port", 0)
            protocol = port.get("protocol", "tcp")
            state = port.get("state", "unknown")
            service = port.get("service", "")
            version = port.get("version", port.get("product", ""))
            extra_info = port.get("extra_info", "")
            
            # Color code by state
            if state == "open":
                state_text = "[green]open[/green]"
            elif state == "filtered":
                state_text = "[yellow]filtered[/yellow]"
            elif state == "closed":
                state_text = "[red]closed[/red]"
            else:
                state_text = f"[dim]{state}[/dim]"
            
            table.add_row(
                f"{port_num}/{protocol}",
                state_text,
                service,
                version[:35] if version else "",
                extra_info[:20] if extra_info else ""
            )
        
        self.console.print(table)
        self.console.print()
    
    # =========================================================================
    # Vulnerability Output
    # =========================================================================
    
    def print_vulnerability_header(self, host: str, risk_score: float, risk_level: str):
        """Print vulnerability scan header for a host."""
        risk_color = SEVERITY_COLORS.get(risk_level, "white")
        risk_icon = SEVERITY_ICONS.get(risk_level, "⚪")
        
        self.console.print(Panel(
            f"[bold]{host}[/bold]\n"
            f"Risk Score: [{risk_color}]{risk_score:.1f}/100[/{risk_color}] "
            f"{risk_icon} [{risk_color}]{risk_level}[/{risk_color}]",
            expand=False
        ))
    
    def print_vulnerability(self, cve: dict, indent: int = 2):
        """
        Print a single CVE with color-coded severity.
        
        Args:
            cve: CVE dictionary with id, severity, score, description
            indent: Indentation spaces
        """
        cve_id = cve.get("cve_id", "Unknown")
        severity = cve.get("severity", "NONE")
        score = cve.get("base_score", 0.0)
        description = cve.get("description", "")[:100]
        
        color = SEVERITY_COLORS.get(severity, "dim")
        icon = SEVERITY_ICONS.get(severity, "⚪")
        
        prefix = " " * indent
        self.console.print(
            f"{prefix}[{color}]{icon} {cve_id}[/{color}] "
            f"[dim](CVSS: {score})[/dim] "
            f"{description}..."
        )
    
    def print_vulnerabilities_table(self, vulnerabilities: list, title: str = "Vulnerabilities"):
        """
        Print vulnerabilities in a table format.
        
        Args:
            vulnerabilities: List of CVE dictionaries
            title: Table title
        """
        if not vulnerabilities:
            self.console.print("[green]✓ No known vulnerabilities found.[/green]")
            return
        
        table = Table(
            title=title,
            show_header=True,
            header_style="bold magenta",
            box=box.ROUNDED
        )
        table.add_column("CVE ID", style="cyan", width=18)
        table.add_column("Severity", width=10)
        table.add_column("Score", justify="right", width=6)
        table.add_column("Description", width=50)
        
        for cve in vulnerabilities[:20]:  # Limit to 20
            cve_id = cve.get("cve_id", "Unknown")
            severity = cve.get("severity", "NONE")
            score = cve.get("base_score", 0.0)
            description = cve.get("description", "")[:50]
            
            color = SEVERITY_COLORS.get(severity, "dim")
            icon = SEVERITY_ICONS.get(severity, "⚪")
            
            table.add_row(
                cve_id,
                f"[{color}]{icon} {severity}[/{color}]",
                f"{score:.1f}",
                description + "..." if description else ""
            )
        
        self.console.print(table)
        
        if len(vulnerabilities) > 20:
            self.console.print(f"[dim]... and {len(vulnerabilities) - 20} more[/dim]")
    
    def print_vulnerable_services(self, services: list):
        """
        Print vulnerable services summary.
        
        Args:
            services: List of vulnerable service info
        """
        if not services:
            return
        
        table = Table(
            title="Vulnerable Services",
            show_header=True,
            header_style="bold magenta",
            box=box.ROUNDED
        )
        table.add_column("Port", style="cyan", width=10)
        table.add_column("Service", width=15)
        table.add_column("Version", width=25)
        table.add_column("CVEs", justify="right", width=6)
        table.add_column("Crit", justify="right", style="red", width=5)
        table.add_column("High", justify="right", style="orange1", width=5)
        table.add_column("Max Score", justify="right", width=8)
        
        for svc in services:
            table.add_row(
                f"{svc.get('port', 0)}/{svc.get('protocol', 'tcp')}",
                svc.get("service_name", ""),
                svc.get("version", "")[:25],
                str(svc.get("cve_count", 0)),
                str(svc.get("critical_count", 0)),
                str(svc.get("high_count", 0)),
                f"{svc.get('max_score', 0.0):.1f}"
            )
        
        self.console.print(table)
    
    # =========================================================================
    # Summary Statistics
    # =========================================================================
    
    def print_summary_statistics(self, stats: ScanStatistics):
        """
        Print summary statistics panel.
        
        Args:
            stats: ScanStatistics object
        """
        risk_color = SEVERITY_COLORS.get(stats.risk_level, "white")
        risk_icon = SEVERITY_ICONS.get(stats.risk_level, "⚪")
        
        # Build summary text
        summary = Text()
        summary.append("Scan Summary\n\n", style="bold underline")
        
        # Hosts
        summary.append(f"Hosts:     ", style="dim")
        summary.append(f"{stats.hosts_up}/{stats.total_hosts} up\n")
        
        # Ports
        summary.append(f"Ports:     ", style="dim")
        summary.append(f"{stats.open_ports} open\n")
        
        # Services
        summary.append(f"Services:  ", style="dim")
        summary.append(f"{stats.total_services} detected\n")
        
        # CVEs
        summary.append(f"CVEs:      ", style="dim")
        summary.append(f"{stats.total_cves} found\n\n")
        
        # Severity breakdown
        summary.append("Severity Breakdown:\n", style="bold")
        summary.append(f"  {SEVERITY_ICONS['CRITICAL']} Critical: ", style="red")
        summary.append(f"{stats.critical_count}\n", style="red")
        summary.append(f"  {SEVERITY_ICONS['HIGH']} High:     ", style="orange1")
        summary.append(f"{stats.high_count}\n", style="orange1")
        summary.append(f"  {SEVERITY_ICONS['MEDIUM']} Medium:   ", style="yellow")
        summary.append(f"{stats.medium_count}\n", style="yellow")
        summary.append(f"  {SEVERITY_ICONS['LOW']} Low:      ", style="blue")
        summary.append(f"{stats.low_count}\n\n", style="blue")
        
        # Risk score
        summary.append(f"Risk Score: ", style="bold")
        summary.append(f"{stats.risk_score:.1f}/100 ", style=risk_color)
        summary.append(f"{risk_icon} {stats.risk_level}\n", style=risk_color)
        
        # Duration
        if stats.scan_duration > 0:
            summary.append(f"\nDuration:  ", style="dim")
            summary.append(f"{stats.scan_duration:.1f}s")
        
        self.console.print(Panel(
            summary,
            title="📊 Scan Statistics",
            border_style="cyan",
            expand=False
        ))
    
    def print_severity_legend(self):
        """Print severity color legend."""
        legend = Text()
        legend.append("Severity Legend: ")
        legend.append(f"{SEVERITY_ICONS['CRITICAL']} Critical ", style="red")
        legend.append(f"{SEVERITY_ICONS['HIGH']} High ", style="orange1")
        legend.append(f"{SEVERITY_ICONS['MEDIUM']} Medium ", style="yellow")
        legend.append(f"{SEVERITY_ICONS['LOW']} Low ", style="blue")
        legend.append(f"{SEVERITY_ICONS['INFO']} Info", style="dim")
        
        self.console.print(legend)
        self.console.print()
    
    # =========================================================================
    # Completion Messages
    # =========================================================================
    
    def print_success(self, message: str):
        """Print success message."""
        self.console.print(f"[green]✓[/green] {message}")
    
    def print_warning(self, message: str):
        """Print warning message."""
        self.console.print(f"[yellow]⚠[/yellow] {message}")
    
    def print_error(self, message: str):
        """Print error message."""
        self.console.print(f"[red]✗[/red] {message}")
    
    def print_scan_complete(
        self,
        stats: Optional[ScanStatistics] = None,
        output_file: Optional[str] = None
    ):
        """Print scan completion message with optional stats."""
        self.console.print()
        
        if stats:
            self.print_summary_statistics(stats)
        
        if output_file:
            self.print_success(f"Results saved to: {output_file}")
        
        self.console.print()
