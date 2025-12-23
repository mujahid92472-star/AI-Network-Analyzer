"""
AI Network Analyzer - CLI Entry Point

Main command-line interface for network scanning and vulnerability analysis.
"""

import sys
from pathlib import Path
from typing import Optional

# Load environment variables from .env file
from dotenv import load_dotenv
load_dotenv()

import click
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from src.core import get_config, setup_logger, get_logger, Config

# Initialize console for rich output
console = Console()


def print_banner():
    """Print the application banner."""
    banner_text = Text()
    banner_text.append("🛡️  ", style="bold blue")
    banner_text.append("AI Network Analyzer", style="bold white")
    banner_text.append(" v0.1.0\n", style="dim")
    banner_text.append("   Intelligent Network Security Scanner", style="italic cyan")
    
    console.print(Panel(
        banner_text,
        border_style="blue",
        padding=(0, 2)
    ))


@click.group()
@click.option(
    "--config", "-c",
    type=click.Path(exists=True, path_type=Path),
    help="Path to configuration file (YAML)"
)
@click.option(
    "--debug/--no-debug",
    default=False,
    help="Enable debug mode"
)
@click.option(
    "--quiet/--no-quiet", "-q",
    default=False,
    help="Suppress banner and non-essential output"
)
@click.pass_context
def cli(ctx: click.Context, config: Optional[Path], debug: bool, quiet: bool):
    """
    AI Network Analyzer - Intelligent Network Security Scanner
    
    Scan networks, identify vulnerabilities, and get AI-powered threat intelligence.
    
    Examples:
    
        # Scan a single host
        python -m src.main scan --target 192.168.1.1
        
        # Scan a network range
        python -m src.main scan --target 192.168.1.0/24
        
        # Generate a report
        python -m src.main report --format html --output report.html
    """
    # Initialize context
    ctx.ensure_object(dict)
    
    # Load configuration
    app_config = get_config(config)
    if debug:
        app_config.debug = True
        app_config.log_level = "DEBUG"
    
    ctx.obj["config"] = app_config
    ctx.obj["quiet"] = quiet
    
    # Setup logger
    import logging
    log_level = logging.DEBUG if debug else getattr(logging, app_config.log_level.upper())
    logger = setup_logger(level=log_level, log_to_console=not quiet)
    ctx.obj["logger"] = logger
    
    # Print banner unless quiet mode
    if not quiet:
        print_banner()


@cli.command()
@click.option(
    "--target", "-t",
    required=True,
    help="Target to scan (IP, hostname, or CIDR range)"
)
@click.option(
    "--ports", "-p",
    default=None,
    help="Ports to scan (e.g., '22,80,443' or '1-1000')"
)
@click.option(
    "--top-ports",
    type=int,
    default=None,
    help="Scan top N most common ports"
)
@click.option(
    "--scan-type", "-s",
    type=click.Choice(["tcp", "syn", "udp", "full"]),
    default="tcp",
    help="Type of scan to perform"
)
@click.option(
    "--timing", "-T",
    type=click.IntRange(0, 5),
    default=3,
    help="Timing template (0=paranoid, 5=insane)"
)
@click.option(
    "--service-detection/--no-service-detection",
    default=True,
    help="Enable service version detection"
)
@click.option(
    "--os-detection/--no-os-detection",
    default=False,
    help="Enable OS detection (requires privileges)"
)
@click.option(
    "--cve-lookup/--no-cve-lookup",
    default=True,
    help="Look up CVEs for detected services"
)
@click.option(
    "--output", "-o",
    type=click.Path(path_type=Path),
    help="Output file for results"
)
@click.option(
    "--format", "-f",
    type=click.Choice(["json", "html", "csv", "console"]),
    default="console",
    help="Output format"
)
@click.pass_context
def scan(
    ctx: click.Context,
    target: str,
    ports: Optional[str],
    top_ports: Optional[int],
    scan_type: str,
    timing: int,
    service_detection: bool,
    os_detection: bool,
    cve_lookup: bool,
    output: Optional[Path],
    format: str
):
    """
    Scan a target for open ports and vulnerabilities.
    
    Examples:
    
        # Basic scan of a host
        python -m src.main scan -t 192.168.1.1
        
        # Scan specific ports
        python -m src.main scan -t 192.168.1.1 -p 22,80,443
        
        # Fast scan of top 100 ports
        python -m src.main scan -t 192.168.1.1 --top-ports 100
        
        # Full scan with OS detection
        python -m src.main scan -t 192.168.1.0/24 -s full --os-detection
    """
    import json
    from src.scanner import PortScanner, ScanType, TimingTemplate, PortPresets
    from src.core.exceptions import PortScanError, InsufficientPrivilegesError
    
    config: Config = ctx.obj["config"]
    logger = ctx.obj["logger"]
    quiet = ctx.obj.get("quiet", False)
    
    # Map CLI options to ScanType enum
    scan_type_map = {
        "tcp": ScanType.TCP_CONNECT,
        "syn": ScanType.TCP_SYN,
        "udp": ScanType.UDP,
        "full": ScanType.COMPREHENSIVE,
    }
    selected_scan_type = scan_type_map.get(scan_type, ScanType.TCP_CONNECT)
    
    # Map timing to TimingTemplate
    timing_template = TimingTemplate(timing)
    
    # Determine ports to scan
    port_spec = ports
    if top_ports:
        port_spec = f"--top-ports {top_ports}"
    
    logger.info(f"Starting {scan_type} scan of target: {target}")
    
    # Print configuration
    if not quiet:
        console.print(f"\n[bold cyan]Scan Configuration:[/bold cyan]")
        console.print(f"  • Target: [bold]{target}[/bold]")
        console.print(f"  • Ports: {port_spec or 'top 100'}")
        console.print(f"  • Scan Type: {scan_type}")
        console.print(f"  • Timing Template: T{timing}")
        console.print(f"  • Service Detection: {'✓' if service_detection else '✗'}")
        console.print(f"  • OS Detection: {'✓' if os_detection else '✗'}")
        console.print(f"  • CVE Lookup: {'✓' if cve_lookup else '✗'} (Phase 2)")
        console.print()
    
    try:
        # Initialize scanner
        scanner = PortScanner()
        
        # Run scan
        result = scanner.scan_ports(
            target=target,
            ports=port_spec,
            scan_type=selected_scan_type,
            timing=timing_template,
            service_detection=service_detection,
            os_detection=os_detection,
            show_progress=not quiet
        )
        
        # Display results
        scanner.print_results(result)
        
        # Save to file if requested
        if output:
            output_path = Path(output)
            
            if format == "json" or str(output).endswith(".json"):
                with open(output_path, "w", encoding="utf-8") as f:
                    json.dump(result.to_dict(), f, indent=2)
            else:
                # Default to JSON for now, HTML/CSV in Phase 3
                with open(output_path.with_suffix(".json"), "w", encoding="utf-8") as f:
                    json.dump(result.to_dict(), f, indent=2)
                output_path = output_path.with_suffix(".json")
            
            console.print(f"\n[green]✓[/green] Results saved to: {output_path}")
            logger.info(f"Results saved to {output_path}")
        
        # Summary
        if result.total_open_ports > 0:
            console.print(f"\n[green]✓ Found {result.total_open_ports} open port(s) on {len(result.hosts_with_open_ports)} host(s)[/green]")
        else:
            console.print("\n[yellow]⚠️ No open ports found.[/yellow]")
        
        if cve_lookup:
            console.print("[dim]CVE lookup will be available in Phase 2[/dim]")
        
    except InsufficientPrivilegesError as e:
        console.print(f"\n[red]✗ Insufficient privileges:[/red] {e.message}")
        console.print("[yellow]Tip: Try running as Administrator, or use -s tcp for unprivileged scan.[/yellow]")
        logger.error(f"Insufficient privileges: {e}")
        sys.exit(1)
        
    except PortScanError as e:
        console.print(f"\n[red]✗ Scan failed:[/red] {e.message}")
        logger.error(f"Scan failed: {e}")
        sys.exit(1)
        
    except Exception as e:
        console.print(f"\n[red]✗ Unexpected error:[/red] {e}")
        logger.exception("Unexpected error during scan")
        sys.exit(1)


@cli.command()
@click.option(
    "--target", "-t",
    required=True,
    help="Target to discover (IP, hostname, or CIDR range, e.g., 192.168.1.0/24)"
)
@click.option(
    "--method", "-m",
    type=click.Choice(["auto", "arp", "icmp", "tcp", "stealth"]),
    default="auto",
    help="Discovery method: auto (recommended), arp (local only), icmp (ping), tcp (SYN), stealth"
)
@click.option(
    "--timing", "-T",
    type=click.IntRange(0, 5),
    default=3,
    help="Timing template (0=paranoid, 5=insane)"
)
@click.option(
    "--tcp-ports",
    default="22,80,443",
    help="TCP ports for TCP-based discovery"
)
@click.option(
    "--resolve/--no-resolve", "-r",
    default=True,
    help="Resolve hostnames via DNS"
)
@click.option(
    "--output", "-o",
    type=click.Path(path_type=Path),
    help="Output file for results (JSON)"
)
@click.pass_context
def discover(
    ctx: click.Context,
    target: str,
    method: str,
    timing: int,
    tcp_ports: str,
    resolve: bool,
    output: Optional[Path]
):
    """
    Discover live hosts on a network.
    
    This performs host discovery without port scanning. Use this to find
    which hosts are online before running a full port scan.
    
    Examples:
    
        # Discover hosts on local network (auto-selects best method)
        python -m src.main discover -t 192.168.1.0/24
        
        # Use ARP scan (fastest, local network only)
        python -m src.main discover -t 192.168.1.0/24 -m arp
        
        # Use ICMP ping sweep
        python -m src.main discover -t 10.0.0.0/24 -m icmp
        
        # Stealth TCP scan (when ICMP is blocked)
        python -m src.main discover -t 192.168.1.0/24 -m stealth
        
        # Save results to JSON
        python -m src.main discover -t 192.168.1.0/24 -o hosts.json
    """
    import json
    from src.scanner import NetworkScanner, DiscoveryMethod
    from src.core.exceptions import NetworkScanError, InvalidTargetError
    
    config: Config = ctx.obj["config"]
    logger = ctx.obj["logger"]
    quiet = ctx.obj.get("quiet", False)
    
    # Map CLI method to DiscoveryMethod enum
    method_map = {
        "auto": DiscoveryMethod.AUTO,
        "arp": DiscoveryMethod.ARP,
        "icmp": DiscoveryMethod.ICMP_ECHO,
        "tcp": DiscoveryMethod.TCP_SYN,
        "stealth": DiscoveryMethod.TCP_SYN,
    }
    discovery_method = method_map.get(method, DiscoveryMethod.AUTO)
    
    logger.info(f"Starting host discovery on {target} using {method} method")
    
    try:
        # Initialize scanner
        scanner = NetworkScanner()
        
        # Print configuration
        if not quiet:
            console.print(f"\n[bold cyan]Discovery Configuration:[/bold cyan]")
            console.print(f"  • Target: [bold]{target}[/bold]")
            console.print(f"  • Method: {method}")
            console.print(f"  • Timing: T{timing}")
            console.print(f"  • Resolve Hostnames: {'✓' if resolve else '✗'}")
            console.print()
        
        # Run discovery
        result = scanner.discover_hosts(
            target=target,
            method=discovery_method,
            timing=timing,
            resolve_hostnames=resolve,
            tcp_ports=tcp_ports if method in ["tcp", "stealth"] else None,
            show_progress=not quiet
        )
        
        # Display results
        scanner.print_results(result)
        
        # Save to file if requested
        if output:
            output_path = Path(output)
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(result.to_dict(), f, indent=2)
            console.print(f"\n[green]✓[/green] Results saved to: {output_path}")
            logger.info(f"Results saved to {output_path}")
        
        # Summary
        if result.hosts_up > 0:
            console.print(f"\n[green]✓ Found {result.hosts_up} live host(s)[/green]")
        else:
            console.print("\n[yellow]⚠️ No hosts found. Try a different discovery method.[/yellow]")
        
    except InvalidTargetError as e:
        console.print(f"\n[red]✗ Invalid target:[/red] {e.message}")
        logger.error(f"Invalid target: {e}")
        sys.exit(1)
        
    except NetworkScanError as e:
        console.print(f"\n[red]✗ Scan failed:[/red] {e.message}")
        if "privileges" in str(e).lower():
            console.print("[yellow]Tip: Some scan types require administrator/root privileges.[/yellow]")
        logger.error(f"Scan failed: {e}")
        sys.exit(1)
        
    except Exception as e:
        console.print(f"\n[red]✗ Unexpected error:[/red] {e}")
        logger.exception("Unexpected error during discovery")
        sys.exit(1)


@cli.command()
@click.option(
    "--target", "-t",
    required=True,
    help="Target to scan (IP, hostname, or CIDR range)"
)
@click.option(
    "--ports", "-p",
    default=None,
    help="Ports to scan (e.g., '22,80,443' or '1-1000')"
)
@click.option(
    "--top-ports",
    type=int,
    default=None,
    help="Scan top N most common ports"
)
@click.option(
    "--os-detection/--no-os-detection", "-O",
    default=False,
    help="Enable OS detection (requires privileges)"
)
@click.option(
    "--intensity", "-i",
    type=click.IntRange(0, 9),
    default=7,
    help="Version detection intensity (0-9, higher = more accurate but slower)"
)
@click.option(
    "--timing", "-T",
    type=click.IntRange(0, 5),
    default=3,
    help="Timing template (0=paranoid, 5=insane)"
)
@click.option(
    "--output", "-o",
    type=click.Path(path_type=Path),
    help="Output file for results (JSON)"
)
@click.pass_context
def services(
    ctx: click.Context,
    target: str,
    ports: Optional[str],
    top_ports: Optional[int],
    os_detection: bool,
    intensity: int,
    timing: int,
    output: Optional[Path]
):
    """
    Perform detailed service detection with CPE extraction.
    
    This command performs deep service fingerprinting to identify:
    - Service names and versions
    - CPE identifiers (for CVE lookup)
    - SSL/TLS certificate information
    - Operating system (optional)
    
    Examples:
    
        # Basic service detection
        python -m src.main services -t 192.168.100.1
        
        # Scan specific ports with high intensity
        python -m src.main services -t 192.168.100.1 -p 22,80,443 -i 9
        
        # Include OS detection (requires admin)
        python -m src.main services -t 192.168.100.1 -O
        
        # Save results for CVE lookup
        python -m src.main services -t 192.168.100.1 -o services.json
    """
    import json
    from src.scanner import ServiceDetector
    from src.core.exceptions import ServiceDetectionError, InsufficientPrivilegesError
    
    config: Config = ctx.obj["config"]
    logger = ctx.obj["logger"]
    quiet = ctx.obj.get("quiet", False)
    
    # Determine ports to scan
    port_spec = ports
    if top_ports:
        port_spec = f"--top-ports {top_ports}"
    
    logger.info(f"Starting service detection on {target}")
    
    # Print configuration
    if not quiet:
        console.print(f"\n[bold cyan]Service Detection Configuration:[/bold cyan]")
        console.print(f"  • Target: [bold]{target}[/bold]")
        console.print(f"  • Ports: {port_spec or 'top 100'}")
        console.print(f"  • Version Intensity: {intensity}")
        console.print(f"  • Timing: T{timing}")
        console.print(f"  • OS Detection: {'✓' if os_detection else '✗'}")
        console.print()
    
    try:
        # Initialize detector
        detector = ServiceDetector()
        
        # Run detection
        results = detector.detect_services(
            target=target,
            ports=port_spec,
            os_detection=os_detection,
            intensity=intensity,
            timing=timing,
            show_progress=not quiet
        )
        
        # Display results
        detector.print_results(results)
        
        # Save to file if requested
        if output:
            output_path = Path(output)
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump([h.to_dict() for h in results], f, indent=2)
            console.print(f"\n[green]✓[/green] Results saved to: {output_path}")
            logger.info(f"Results saved to {output_path}")
        
        # Summary
        total_services = sum(len(h.open_services) for h in results)
        total_cpes = sum(len(h.all_cpes) for h in results)
        
        if total_services > 0:
            console.print(f"\n[green]✓ Detected {total_services} service(s) with {total_cpes} CPE(s)[/green]")
            if total_cpes > 0:
                console.print("[dim]CPEs are ready for CVE lookup in Phase 2[/dim]")
        else:
            console.print("\n[yellow]⚠️ No services detected.[/yellow]")
        
    except InsufficientPrivilegesError as e:
        console.print(f"\n[red]✗ Insufficient privileges:[/red] {e.message}")
        console.print("[yellow]Tip: Run as Administrator for OS detection.[/yellow]")
        logger.error(f"Insufficient privileges: {e}")
        sys.exit(1)
        
    except ServiceDetectionError as e:
        console.print(f"\n[red]✗ Detection failed:[/red] {e.message}")
        logger.error(f"Detection failed: {e}")
        sys.exit(1)
        
    except Exception as e:
        console.print(f"\n[red]✗ Unexpected error:[/red] {e}")
        logger.exception("Unexpected error during service detection")
        sys.exit(1)


@cli.command()
@click.option(
    "--target", "-t",
    default=None,
    help="Target to scan (IP, hostname, or CIDR range)"
)
@click.option(
    "--cpe", "-c",
    default=None,
    help="CPE string to look up (e.g., 'cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*')"
)
@click.option(
    "--cve",
    default=None,
    help="Look up a specific CVE ID (e.g., 'CVE-2021-44228')"
)
@click.option(
    "--input", "-i",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Input services.json file from 'services' command"
)
@click.option(
    "--max-cves",
    type=int,
    default=50,
    help="Maximum CVEs per CPE to fetch"
)
@click.option(
    "--check-exploits",
    is_flag=True,
    default=False,
    help="Check for public exploits (slower but more informative)"
)
@click.option(
    "--output", "-o",
    type=click.Path(path_type=Path),
    help="Output file for results (JSON)"
)
@click.pass_context
def vulns(
    ctx: click.Context,
    target: Optional[str],
    cpe: Optional[str],
    cve: Optional[str],
    input: Optional[Path],
    max_cves: int,
    check_exploits: bool,
    output: Optional[Path]
):
    """
    Scan for vulnerabilities using NVD (National Vulnerability Database).
    
    This command queries the NVD API to find CVEs matching detected services.
    
    Examples:
    
        # Scan a target directly (runs service detection + CVE lookup)
        python -m src.main vulns -t 192.168.100.1
        
        # Check for public exploits
        python -m src.main vulns -t 192.168.100.1 --check-exploits
        
        # Look up a specific CPE
        python -m src.main vulns -c "cpe:2.3:a:dropbear_ssh_project:dropbear_ssh:2016.73:*:*:*:*:*:*:*"
        
        # Look up a specific CVE
        python -m src.main vulns --cve CVE-2021-44228
        
        # Use previous services scan results
        python -m src.main vulns -i services.json
        
        # Save vulnerability report
        python -m src.main vulns -t 192.168.100.1 -o vulns.json
    """
    import json
    from src.vulnerability import VulnerabilityScanner, NVDAPIClient
    from src.scanner import ServiceDetector
    from src.core.exceptions import CVELookupError
    
    config: Config = ctx.obj["config"]
    logger = ctx.obj["logger"]
    quiet = ctx.obj.get("quiet", False)
    
    nvd_api_key = config.nvd_api_key if hasattr(config, "nvd_api_key") else None
    vuln_scanner = VulnerabilityScanner(api_key=nvd_api_key)
    
    # Initialize exploit checker if requested
    exploit_checker = None
    if check_exploits:
        from src.intelligence import ExploitChecker
        exploit_checker = ExploitChecker()
        if not quiet:
            console.print("[dim]Exploit checking enabled (this may take longer)...[/dim]\n")
    
    try:
        # Validate input options
        if not any([target, cpe, cve, input]):
            console.print("[red]Error: Must specify one of: --target, --cpe, --cve, or --input[/red]")
            sys.exit(1)

        # Option 1: Look up specific CVE
        if cve:
            if not quiet:
                console.print(f"\n[bold cyan]CVE Lookup:[/bold cyan] {cve}\n")
            
            cve_info = vuln_scanner.lookup_cve(cve)
            
            if cve_info:
                vuln_scanner._print_cve(cve_info, indent=0)
                
                # Check for exploits
                if check_exploits and exploit_checker:
                    console.print(f"\n[bold]Exploit Information:[/bold]")
                    exploit_info = exploit_checker.check_cve(cve)
                    
                    if exploit_info.in_kev_catalog:
                        console.print(f"  [red]⚠ CISA KEV:[/red] Listed in Known Exploited Vulnerabilities catalog")
                    if exploit_info.exploit_available:
                        console.print(f"  [orange1]🎯 Exploit:[/orange1] Public exploit available")
                        if exploit_info.exploit_url:
                            console.print(f"     URL: {exploit_info.exploit_url}")
                    console.print(f"  [bold]Weaponization:[/bold] {exploit_info.weaponization_likelihood}")
                    if exploit_info.notes:
                        console.print(f"  [dim]{exploit_info.notes}[/dim]")
                
                if output:
                    with open(output, "w", encoding="utf-8") as f:
                        json.dump(cve_info.to_dict(), f, indent=2)
                    console.print(f"\n[green]✓[/green] Saved to: {output}")
            else:
                console.print(f"[yellow]CVE {cve} not found[/yellow]")
            
            vuln_scanner.close()
            return
        
        # Option 2: Look up specific CPE
        if cpe:
            logger.info(f"Looking up CVEs for CPE: {cpe}")
            console.print(f"\n[bold cyan]CPE Lookup:[/bold cyan] {cpe}\n")
            
            cves = vuln_scanner.lookup_cpe(cpe, max_results=max_cves)
            
            console.print(f"Found [bold]{len(cves)}[/bold] CVEs\n")
            
            # Sort by severity
            from src.vulnerability.nvd_client import Severity
            cves.sort(key=lambda c: (c.severity.value, c.base_score), reverse=True)
            
            for cve_info in cves[:20]:  # Show top 20
                severity_colors = {
                    Severity.CRITICAL: "red",
                    Severity.HIGH: "orange1",
                    Severity.MEDIUM: "yellow",
                    Severity.LOW: "blue",
                    Severity.NONE: "dim"
                }
                color = severity_colors.get(cve_info.severity, "white")
                
                console.print(
                    f"  [{color}]● {cve_info.cve_id}[/{color}] "
                    f"(CVSS: {cve_info.base_score}) "
                    f"{cve_info.description[:60]}..."
                )
            
            if output:
                with open(output, "w", encoding="utf-8") as f:
                    json.dump([c.to_dict() for c in cves], f, indent=2)
                console.print(f"\n[green]✓[/green] Saved {len(cves)} CVEs to: {output}")
            
            return
        
        # Option 3: Scan target
        if target:
            logger.info(f"Scanning {target} for vulnerabilities")
            
            if not quiet:
                console.print(f"\n[bold cyan]Vulnerability Scan:[/bold cyan] {target}")
                console.print("[dim]Step 1: Service detection...[/dim]")
            
            # Run service detection first
            service_detector = ServiceDetector()
            hosts = service_detector.detect_services(
                target=target,
                os_detection=False,
                show_progress=not quiet
            )
            
            if not hosts:
                console.print("[yellow]No hosts found[/yellow]")
                return
            
            if not quiet:
                console.print("[dim]Step 2: CVE lookup via NVD API...[/dim]")
            
            # Scan for vulnerabilities
            all_reports = []
            for host in hosts:
                report = vuln_scanner.scan_host(
                    host,
                    max_cves_per_cpe=max_cves,
                    show_progress=not quiet
                )
                all_reports.append(report)
                vuln_scanner.print_report(report)
            
            if output:
                with open(output, "w", encoding="utf-8") as f:
                    json.dump([r.to_dict() for r in all_reports], f, indent=2)
                console.print(f"\n[green]✓[/green] Saved reports to: {output}")
            
            return
        
        # Option 4: Load from input file
        if input:
            logger.info(f"Loading services from: {input}")
            console.print(f"\n[bold cyan]Loading services from:[/bold cyan] {input}")
            
            with open(input, "r", encoding="utf-8") as f:
                services_data = json.load(f)
            
            # Reconstruct host service info
            from src.scanner import HostServiceInfo, ServiceInfo, CPEInfo
            
            hosts = []
            for host_data in services_data:
                host = HostServiceInfo(
                    ip_address=host_data.get("ip_address", "unknown"),
                    hostname=host_data.get("hostname")
                )
                
                for svc_data in host_data.get("services", []):
                    service = ServiceInfo(
                        port=svc_data.get("port", 0),
                        protocol=svc_data.get("protocol", "tcp"),
                        service_name=svc_data.get("service_name", ""),
                        product=svc_data.get("product", ""),
                        version=svc_data.get("version", "")
                    )
                    
                    for cpe_data in svc_data.get("cpes", []):
                        if isinstance(cpe_data, dict):
                            service.cpes.append(CPEInfo.from_string(cpe_data.get("cpe_string", "")))
                        elif isinstance(cpe_data, str):
                            service.cpes.append(CPEInfo.from_string(cpe_data))
                    
                    host.services.append(service)
                
                hosts.append(host)
            
            console.print(f"Loaded {len(hosts)} host(s)\n")
            console.print("[dim]Running CVE lookup via NVD API...[/dim]\n")
            
            all_reports = []
            for host in hosts:
                report = vuln_scanner.scan_host(
                    host,
                    max_cves_per_cpe=max_cves,
                    show_progress=not quiet
                )
                all_reports.append(report)
                vuln_scanner.print_report(report)
            
            if output:
                with open(output, "w", encoding="utf-8") as f:
                    json.dump([r.to_dict() for r in all_reports], f, indent=2)
                console.print(f"\n[green]✓[/green] Saved reports to: {output}")
        
        vuln_scanner.close()
        
    except CVELookupError as e:
        console.print(f"\n[red]✗ CVE lookup failed:[/red] {e.message}")
        logger.error(f"CVE lookup failed: {e}")
        sys.exit(1)
        
    except Exception as e:
        console.print(f"\n[red]✗ Unexpected error:[/red] {e}")
        logger.exception("Unexpected error during vulnerability scan")
        sys.exit(1)


@cli.command()
@click.option(
    "--input", "-i",
    type=click.Path(exists=True, path_type=Path),
    required=True,
    help="Input scan results file"
)
@click.option(
    "--format", "-f",
    type=click.Choice(["html", "pdf", "json", "csv", "md", "xml"]),
    default="html",
    help="Output report format"
)
@click.option(
    "--output", "-o",
    type=click.Path(path_type=Path),
    help="Output file path"
)
@click.pass_context
def report(ctx: click.Context, input: Path, format: str, output: Optional[Path]):
    """
    Generate a report from scan results.
    
    Examples:
    
        # Generate HTML report
        python -m src.main report -i results.json -f html -o report.html
        
        # Generate PDF report
        python -m src.main report -i results.json -f pdf -o report.pdf
    """
    import json
    from src.reporting import HTMLReporter, PDFReporter
    
    config: Config = ctx.obj["config"]
    logger = ctx.obj["logger"]
    quiet = ctx.obj.get("quiet", False)
    
    logger.info(f"Generating {format} report from {input}")
    
    # Determine output path
    if not output:
        suffix = ".html" if format == "html" else f".{format}"
        output = input.with_suffix(suffix)
    
    if not quiet:
        console.print(f"\n[bold cyan]Report Generation:[/bold cyan]")
        console.print(f"  • Input: {input}")
        console.print(f"  • Format: {format}")
        console.print(f"  • Output: {output}")
        console.print()
    
    try:
        # Load scan results
        with open(input, 'r', encoding='utf-8') as f:
            scan_results = json.load(f)
        
        # Handle list vs dict
        if isinstance(scan_results, list):
            scan_results = {"hosts": scan_results}
        
        if format == "html":
            reporter = HTMLReporter()
            reporter.generate_from_scan_results(scan_results, output)
            console.print(f"[green]✓[/green] HTML report generated: {output}")
            
        elif format == "pdf":
            reporter = PDFReporter()
            success = reporter.generate_from_scan_results(scan_results, output)
            if success:
                console.print(f"[green]✓[/green] PDF report generated: {output}")
            else:
                console.print("[red]✗[/red] PDF generation failed")
                sys.exit(1)
                
        elif format == "json":
            # Pretty-print JSON
            with open(output, 'w', encoding='utf-8') as f:
                json.dump(scan_results, f, indent=2)
            console.print(f"[green]✓[/green] JSON report saved: {output}")
            
        elif format == "csv":
            # Export vulnerabilities to CSV
            import csv
            vulns = []
            hosts = scan_results.get("hosts", [scan_results] if "ip_address" in scan_results else [])
            for host in hosts:
                for v in host.get("vulnerabilities", []):
                    vulns.append({
                        "host": host.get("ip_address", ""),
                        "cve_id": v.get("cve_id", ""),
                        "severity": v.get("severity", ""),
                        "score": v.get("base_score", 0),
                        "description": v.get("description", "")[:100]
                    })
            
            with open(output, 'w', newline='', encoding='utf-8') as f:
                if vulns:
                    writer = csv.DictWriter(f, fieldnames=vulns[0].keys())
                    writer.writeheader()
                    writer.writerows(vulns)
            console.print(f"[green]✓[/green] CSV report saved: {output}")
            
        elif format == "md":
            # Markdown export
            md_content = f"# Security Scan Report\n\n"
            md_content += f"**Generated:** {__import__('datetime').datetime.now()}\n\n"
            hosts = scan_results.get("hosts", [])
            md_content += f"## Summary\n\n- Hosts: {len(hosts)}\n\n"
            
            for host in hosts:
                md_content += f"### {host.get('ip_address', 'Unknown')}\n\n"
                for v in host.get("vulnerabilities", [])[:10]:
                    md_content += f"- **{v.get('cve_id', '')}** ({v.get('severity', '')}): {v.get('description', '')[:80]}...\n"
                md_content += "\n"
            
            with open(output, 'w', encoding='utf-8') as f:
                f.write(md_content)
            console.print(f"[green]✓[/green] Markdown report saved: {output}")
            
        elif format == "xml":
            # XML export for tool integration
            import xml.etree.ElementTree as ET
            from xml.dom import minidom
            
            root = ET.Element("security_scan_report")
            root.set("generated", __import__('datetime').datetime.now().isoformat())
            
            hosts_elem = ET.SubElement(root, "hosts")
            hosts = scan_results.get("hosts", [scan_results] if "ip_address" in scan_results else [])
            
            for host in hosts:
                host_elem = ET.SubElement(hosts_elem, "host")
                ET.SubElement(host_elem, "ip_address").text = host.get("ip_address", "")
                ET.SubElement(host_elem, "hostname").text = host.get("hostname", "")
                
                vulns_elem = ET.SubElement(host_elem, "vulnerabilities")
                for v in host.get("vulnerabilities", []):
                    vuln_elem = ET.SubElement(vulns_elem, "vulnerability")
                    ET.SubElement(vuln_elem, "cve_id").text = v.get("cve_id", "")
                    ET.SubElement(vuln_elem, "severity").text = v.get("severity", "")
                    ET.SubElement(vuln_elem, "score").text = str(v.get("base_score", 0))
                    ET.SubElement(vuln_elem, "description").text = v.get("description", "")[:200]
            
            # Pretty print XML
            rough_string = ET.tostring(root, encoding='unicode')
            reparsed = minidom.parseString(rough_string)
            
            with open(output, 'w', encoding='utf-8') as f:
                f.write(reparsed.toprettyxml(indent="  "))
            console.print(f"[green]✓[/green] XML report saved: {output}")
        
        logger.info(f"Report generated: {output}")
        
    except json.JSONDecodeError as e:
        console.print(f"[red]✗[/red] Invalid JSON input: {e}")
        sys.exit(1)
    except FileNotFoundError:
        console.print(f"[red]✗[/red] Input file not found: {input}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]✗[/red] Report generation failed: {e}")
        logger.exception("Report generation failed")
        sys.exit(1)


@cli.command()
@click.option(
    "--input", "-i",
    type=click.Path(exists=True, path_type=Path),
    required=True,
    help="Input scan results file (JSON)"
)
@click.option(
    "--api-key", "-k",
    default=None,
    help="Gemini API key (or set GEMINI_API_KEY env var)"
)
@click.option(
    "--output", "-o",
    type=click.Path(path_type=Path),
    help="Output file for AI analysis (JSON)"
)
@click.pass_context
def analyze(ctx: click.Context, input: Path, api_key: Optional[str], output: Optional[Path]):
    """
    AI-powered threat analysis using Gemini.
    
    Analyzes vulnerability scan results and provides:
    - Threat summaries
    - Risk assessments  
    - Attack scenario predictions
    - Prioritized remediation steps
    
    Examples:
    
        # Analyze with API key from environment
        export GEMINI_API_KEY=your_key
        python -m src.main analyze -i scan_results.json
        
        # Analyze with API key parameter
        python -m src.main analyze -i scan.json -k YOUR_API_KEY -o analysis.json
    """
    import json
    import os
    
    config: Config = ctx.obj["config"]
    logger = ctx.obj["logger"]
    
    # Get API key
    gemini_key = api_key or os.environ.get("GEMINI_API_KEY")
    if not gemini_key:
        console.print("[red]✗[/red] Gemini API key required!")
        console.print("  Set GEMINI_API_KEY environment variable or use --api-key option")
        console.print("  Get free key at: https://aistudio.google.com/app/apikey")
        sys.exit(1)
    
    console.print(f"\n[bold cyan]AI Threat Analysis:[/bold cyan]")
    console.print(f"  • Input: {input}")
    console.print(f"  • Model: Gemini 1.5 Flash")
    console.print()
    
    try:
        # Load scan results
        with open(input, 'r', encoding='utf-8') as f:
            scan_results = json.load(f)
        
        # Handle list vs dict
        if isinstance(scan_results, list):
            scan_results = {"hosts": scan_results}
        
        # Initialize threat analyzer
        from src.intelligence import ThreatAnalyzer
        
        with console.status("[bold green]Analyzing threats with AI..."):
            analyzer = ThreatAnalyzer(gemini_api_key=gemini_key)
            assessment = analyzer.analyze(scan_results, use_ai=True)
        
        # Display results
        console.print()
        console.print(Panel(
            f"[bold]Target:[/bold] {assessment.target}\n"
            f"[bold]Risk Score:[/bold] {assessment.overall_risk_score:.1f}/100\n"
            f"[bold]Threat Level:[/bold] [{_severity_color(assessment.threat_level.name)}]{assessment.threat_level.name}[/]\n"
            f"\n[bold]Vulnerabilities:[/bold]\n"
            f"  🔴 Critical: {assessment.critical_count}\n"
            f"  🟠 High: {assessment.high_count}\n"
            f"  🟡 Medium: {assessment.medium_count}\n"
            f"  🟢 Low: {assessment.low_count}",
            title="📊 Risk Assessment",
            expand=False
        ))
        
        if assessment.ai_threat_summary:
            console.print()
            console.print(Panel(
                assessment.ai_threat_summary,
                title="🔍 AI Threat Summary",
                expand=False
            ))
        
        if assessment.ai_attack_scenarios:
            console.print()
            console.print("[bold]⚔️ Potential Attack Scenarios:[/bold]")
            for i, scenario in enumerate(assessment.ai_attack_scenarios[:5], 1):
                console.print(f"  {i}. {scenario}")
        
        if assessment.ai_remediation_steps:
            console.print()
            console.print("[bold]🔧 Recommended Actions:[/bold]")
            for step in assessment.ai_remediation_steps[:7]:
                console.print(f"  • {step}")
        
        if assessment.ai_executive_summary:
            console.print()
            console.print(Panel(
                assessment.ai_executive_summary,
                title="📋 Executive Summary",
                expand=False
            ))
        
        # Save to file if requested
        if output:
            with open(output, 'w', encoding='utf-8') as f:
                json.dump(assessment.to_dict(), f, indent=2)
            console.print(f"\n[green]✓[/green] Analysis saved to: {output}")
        
        logger.info("AI threat analysis completed")
        
    except ImportError as e:
        console.print(f"[red]✗[/red] Missing dependency: {e}")
        console.print("  Install with: pip install google-generativeai")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]✗[/red] Analysis failed: {e}")
        logger.exception("AI analysis failed")
        sys.exit(1)


def _severity_color(severity: str) -> str:
    """Get color for severity level."""
    colors = {
        "CRITICAL": "bold red",
        "HIGH": "orange1",
        "MEDIUM": "yellow",
        "LOW": "blue",
        "MINIMAL": "green"
    }
    return colors.get(severity.upper(), "white")


@cli.command()
@click.pass_context
def version(ctx: click.Context):
    """Show version information."""
    config: Config = ctx.obj["config"]
    console.print(f"AI Network Analyzer v{config.version}")


@cli.command()
@click.option(
    "--output", "-o",
    type=click.Path(path_type=Path),
    default=Path("config.yaml"),
    help="Output configuration file path"
)
@click.pass_context
def init_config(ctx: click.Context, output: Path):
    """
    Generate a default configuration file.
    
    Example:
    
        python -m src.main init-config -o my_config.yaml
    """
    config: Config = ctx.obj["config"]
    logger = ctx.obj["logger"]
    
    try:
        config.to_yaml(output)
        console.print(f"[green]✓[/green] Configuration file created: {output}")
        logger.info(f"Configuration file created: {output}")
    except ImportError as e:
        console.print(f"[red]✗[/red] {e}")
        sys.exit(1)


@cli.command()
@click.pass_context
def check(ctx: click.Context):
    """
    Check system requirements and dependencies.
    
    Verifies that all required tools (nmap, etc.) are installed
    and accessible.
    """
    import shutil
    
    console.print("\n[bold cyan]System Check:[/bold cyan]\n")
    
    # Check Python version
    py_version = sys.version_info
    py_ok = py_version >= (3, 10)
    py_status = "[green]✓[/green]" if py_ok else "[red]✗[/red]"
    console.print(f"  {py_status} Python {py_version.major}.{py_version.minor}.{py_version.micro} (3.10+ required)")
    
    # Check for nmap
    nmap_path = shutil.which("nmap")
    nmap_ok = nmap_path is not None
    nmap_status = "[green]✓[/green]" if nmap_ok else "[red]✗[/red]"
    console.print(f"  {nmap_status} nmap {'found at ' + nmap_path if nmap_ok else 'NOT FOUND'}")
    
    # Check for optional dependencies
    console.print("\n[bold cyan]Optional Dependencies:[/bold cyan]\n")
    
    optional_deps = [
        ("rich", "Beautiful console output"),
        ("yaml", "YAML configuration files"),
        ("nmap", "Nmap Python wrapper"),
        ("httpx", "HTTP client for APIs"),
        ("jinja2", "Report templates"),
    ]
    
    for dep_name, desc in optional_deps:
        try:
            __import__(dep_name)
            console.print(f"  [green]✓[/green] {dep_name}: {desc}")
        except ImportError:
            console.print(f"  [yellow]○[/yellow] {dep_name}: {desc} (not installed)")
    
    console.print()


@cli.command()
@click.option(
    "--target", "-t",
    required=True,
    help="Target IP, hostname, or CIDR range to scan"
)
@click.option(
    "--max-cves", 
    default=20,
    help="Maximum CVEs per service (default: 20)"
)
@click.option(
    "--skip-ai/--no-skip-ai",
    default=False,
    help="Skip AI analysis"
)
@click.pass_context
def fullscan(ctx: click.Context, target: str, max_cves: int, skip_ai: bool):
    """
    Complete security scan with reports.
    
    Performs: service detection → vulnerability scan → AI analysis → reports
    All outputs are saved to a timestamped folder in results/
    
    Examples:
    
        # Full scan of a host
        python -m src.main fullscan -t 192.168.1.1
        
        # Full scan without AI analysis
        python -m src.main fullscan -t 192.168.1.0/24 --skip-ai
    """
    import json
    import os
    from datetime import datetime
    
    config: Config = ctx.obj["config"]
    logger = ctx.obj["logger"]
    quiet = ctx.obj.get("quiet", False)
    
    # Create results folder with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    results_dir = Path("results") / f"scan_{timestamp}"
    results_dir.mkdir(parents=True, exist_ok=True)
    
    console.print(f"\n[bold cyan]🛡️ Full Security Scan[/bold cyan]")
    console.print(f"  Target: [bold]{target}[/bold]")
    console.print(f"  Output: [dim]{results_dir}[/dim]\n")
    
    try:
        # Step 1: Service Detection
        console.print("[bold]Step 1:[/bold] Service Detection...")
        from src.scanner import ServiceDetector
        
        detector = ServiceDetector()
        hosts = detector.detect_services(
            target=target, 
            os_detection=False,
            intensity=7,
            show_progress=not quiet
        )
        
        # Check if host is reachable (has services or responded)
        if not hosts:
            console.print(f"  [red]✗[/red] No hosts found")
            console.print(f"\n[yellow]⚠ Target '{target}' may be:[/yellow]")
            console.print(f"  • Offline or powered off")
            console.print(f"  • Behind a firewall blocking scans")
            console.print(f"  • Network unreachable")
            console.print(f"\n[dim]Tip: Verify the host is online with 'ping {target}'[/dim]")
            sys.exit(1)
        
        # Check if any host has open services
        total_services = sum(len(h.services) for h in hosts)
        if total_services == 0:
            console.print(f"  [yellow]⚠[/yellow] Host responded but no open ports found")
            console.print(f"\n[yellow]⚠ Target '{target}' appears to be:[/yellow]")
            console.print(f"  • Online but heavily firewalled (all ports filtered)")
            console.print(f"  • Running no network services")
            console.print(f"  • Blocking nmap scans")
            console.print(f"\n[dim]Tip: Try running nmap directly: nmap -Pn -sV {target}[/dim]")
            
            # Save empty results and exit gracefully
            services_file = results_dir / "services.json"
            with open(services_file, "w", encoding="utf-8") as f:
                json.dump([h.to_dict() for h in hosts], f, indent=2)
            
            console.print(f"\n[dim]Results saved to: {results_dir}[/dim]")
            sys.exit(0)
        
        services_file = results_dir / "services.json"
        with open(services_file, "w", encoding="utf-8") as f:
            json.dump([h.to_dict() for h in hosts], f, indent=2)
        console.print(f"  [green]✓[/green] Found {len(hosts)} host(s) with {total_services} service(s)")
        
        # Step 2: Vulnerability Scan
        console.print("[bold]Step 2:[/bold] Vulnerability Scan...")
        from src.vulnerability import VulnerabilityScanner
        
        vuln_scanner = VulnerabilityScanner()
        all_reports = []
        
        for host in hosts:
            report = vuln_scanner.scan_host(
                host,
                max_cves_per_cpe=max_cves,
                show_progress=not quiet
            )
            all_reports.append(report)
        
        vuln_file = results_dir / "vulnerabilities.json"
        with open(vuln_file, "w", encoding="utf-8") as f:
            json.dump([r.to_dict() for r in all_reports], f, indent=2)
        
        total_cves = sum(r.total_cves for r in all_reports)
        console.print(f"  [green]✓[/green] Found {total_cves} CVEs")
        vuln_scanner.close()
        
        # Step 3: AI Analysis
        ai_data = {}
        if not skip_ai:
            console.print("[bold]Step 3:[/bold] AI Threat Analysis...")
            gemini_key = os.environ.get("GEMINI_API_KEY")
            
            if gemini_key:
                try:
                    from src.intelligence import ThreatAnalyzer
                    
                    analyzer = ThreatAnalyzer(gemini_api_key=gemini_key)
                    with open(vuln_file, "r", encoding="utf-8") as f:
                        vuln_data = json.load(f)
                    
                    assessment = analyzer.analyze({"hosts": vuln_data}, use_ai=True)
                    
                    ai_file = results_dir / "ai_analysis.json"
                    with open(ai_file, "w", encoding="utf-8") as f:
                        json.dump(assessment.to_dict(), f, indent=2)
                    
                    ai_data = assessment.to_dict()
                    console.print(f"  [green]✓[/green] AI analysis complete")
                except Exception as e:
                    console.print(f"  [yellow]⚠[/yellow] AI analysis failed: {e}")
            else:
                console.print("  [yellow]⚠[/yellow] GEMINI_API_KEY not set, skipping AI")
        else:
            console.print("[bold]Step 3:[/bold] AI Analysis [dim](skipped)[/dim]")
        
        # Step 4: Generate Reports
        console.print("[bold]Step 4:[/bold] Generating Reports...")
        from src.reporting import HTMLReporter, PDFReporter
        
        # Prepare report data with AI analysis
        with open(vuln_file, "r", encoding="utf-8") as f:
            vuln_data = json.load(f)
        
        # Always wrap in dict with hosts key
        report_input = {"hosts": vuln_data}
        
        # Add AI data to report if available
        if ai_data:
            report_input["ai_threat_summary"] = ai_data.get("ai_threat_summary", "")
            report_input["ai_executive_summary"] = ai_data.get("ai_executive_summary", "")
            report_input["ai_attack_scenarios"] = ai_data.get("ai_attack_scenarios", [])
            report_input["ai_remediation_steps"] = ai_data.get("ai_remediation_steps", [])
        
        # Generate HTML
        html_reporter = HTMLReporter()
        html_file = results_dir / "report.html"
        html_reporter.generate_from_scan_results(report_input, html_file)
        console.print(f"  [green]✓[/green] HTML report: {html_file}")
        
        # Generate PDF
        try:
            pdf_reporter = PDFReporter()
            pdf_file = results_dir / "report.pdf"
            pdf_reporter.generate_from_scan_results(report_input, pdf_file)
            console.print(f"  [green]✓[/green] PDF report: {pdf_file}")
        except Exception as e:
            console.print(f"  [yellow]⚠[/yellow] PDF generation failed: {e}")
        
        # Summary
        console.print(f"\n[bold green]✓ Scan Complete![/bold green]")
        console.print(f"\n[bold]Results saved to:[/bold] {results_dir}")
        console.print(f"  • services.json - Service detection results")
        console.print(f"  • vulnerabilities.json - CVE findings ({total_cves} CVEs)")
        if ai_data:
            console.print(f"  • ai_analysis.json - AI threat analysis")
        console.print(f"  • report.html - Interactive HTML report")
        console.print(f"  • report.pdf - PDF report")
        
        console.print(f"\n[dim]Open report:[/dim] start {html_file}")
        
    except Exception as e:
        console.print(f"\n[red]✗ Scan failed:[/red] {e}")
        logger.exception("Full scan failed")
        sys.exit(1)


def main():
    """Main entry point."""
    cli(obj={})


if __name__ == "__main__":
    main()
