"""
HTML Report Generator - Professional HTML security reports.

Generates beautiful HTML reports with:
- Executive summary
- Detailed vulnerability findings
- Interactive Chart.js visualizations
- Severity color coding
- Remediation recommendations
- Print-friendly styling
"""

import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional, Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from src.core import get_logger


@dataclass
class ReportData:
    """Data structure for HTML report generation."""
    
    # Report metadata
    title: str = "Security Scan Report"
    generated_at: datetime = field(default_factory=datetime.now)
    scan_duration: float = 0.0
    
    # Target information
    targets: list[str] = field(default_factory=list)
    
    # Summary statistics
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
    
    # Risk assessment
    risk_score: float = 0.0
    risk_level: str = "LOW"
    
    # Detailed findings
    hosts: list[dict] = field(default_factory=list)
    vulnerabilities: list[dict] = field(default_factory=list)
    
    # Recommendations
    recommendations: list[str] = field(default_factory=list)
    
    # AI Analysis
    ai_threat_summary: str = ""
    ai_risk_assessment: str = ""
    ai_executive_summary: str = ""
    ai_attack_scenarios: list[str] = field(default_factory=list)
    ai_remediation_steps: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        """Convert to dictionary for template rendering."""
        return {
            "title": self.title,
            "generated_at": self.generated_at.strftime("%Y-%m-%d %H:%M:%S"),
            "generated_date": self.generated_at.strftime("%B %d, %Y"),
            "scan_duration": f"{self.scan_duration:.1f}s" if self.scan_duration else "N/A",
            "targets": self.targets,
            "total_hosts": self.total_hosts,
            "hosts_up": self.hosts_up,
            "total_ports": self.total_ports,
            "open_ports": self.open_ports,
            "total_services": self.total_services,
            "total_cves": self.total_cves,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "hosts": self.hosts,
            "vulnerabilities": self.vulnerabilities[:100],
            "recommendations": self.recommendations,
            # AI Analysis
            "ai_threat_summary": self.ai_threat_summary,
            "ai_risk_assessment": self.ai_risk_assessment,
            "ai_executive_summary": self.ai_executive_summary,
            "ai_attack_scenarios": self.ai_attack_scenarios,
            "ai_remediation_steps": self.ai_remediation_steps
        }


class HTMLReporter:
    """
    HTML report generator using Jinja2 templates.
    
    Creates professional, print-friendly HTML security reports with
    interactive charts and detailed vulnerability findings.
    """
    
    # Default template directory (relative to this file)
    TEMPLATE_DIR = Path(__file__).parent / "templates"
    
    def __init__(self, template_dir: Optional[Path] = None):
        """
        Initialize the HTML reporter.
        
        Args:
            template_dir: Optional custom template directory
        """
        self.logger = get_logger("html_reporter")
        self.template_dir = template_dir or self.TEMPLATE_DIR
        
        # Ensure templates exist
        self._ensure_templates()
        
        # Setup Jinja2 environment
        self.env = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            autoescape=select_autoescape(['html', 'xml']),
            trim_blocks=True,
            lstrip_blocks=True
        )
        
        # Add custom filters
        self.env.filters["severity_color"] = self._severity_color
        self.env.filters["severity_icon"] = self._severity_icon
        self.env.filters["markdown_bold"] = self._markdown_bold
        
        self.logger.info("HTML reporter initialized")
    
    @staticmethod
    def _markdown_bold(text: str) -> str:
        """Convert markdown **bold** to HTML <strong>bold</strong>."""
        import re
        if not text:
            return text
        # Replace **text** with <strong>text</strong>
        return re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
    
    def _ensure_templates(self):
        """Ensure template files exist, create defaults if not."""
        self.template_dir.mkdir(parents=True, exist_ok=True)
        
        # Check for main template
        report_template = self.template_dir / "report.html"
        if not report_template.exists():
            self._create_default_template(report_template)
    
    def _create_default_template(self, path: Path):
        """Create the default HTML template."""
        template_content = self._get_default_template()
        with open(path, 'w', encoding='utf-8') as f:
            f.write(template_content)
        self.logger.info(f"Created default template at: {path}")
    
    @staticmethod
    def _severity_color(severity: str) -> str:
        """Get CSS color for severity level."""
        colors = {
            "CRITICAL": "#dc3545",
            "HIGH": "#fd7e14",
            "MEDIUM": "#ffc107",
            "LOW": "#0d6efd",
            "INFO": "#6c757d",
            "NONE": "#adb5bd"
        }
        return colors.get(severity.upper() if severity else "NONE", "#adb5bd")
    
    @staticmethod
    def _severity_icon(severity: str) -> str:
        """Get icon for severity level."""
        icons = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🟢",
            "INFO": "⚪",
            "NONE": "⚫"
        }
        return icons.get(severity.upper() if severity else "NONE", "⚪")
    
    def generate(
        self,
        data: ReportData,
        output_path: Optional[Path] = None,
        template_name: str = "report.html"
    ) -> str:
        """
        Generate an HTML report.
        
        Args:
            data: ReportData object with scan results
            output_path: Optional path to save the report
            template_name: Name of the template file
        
        Returns:
            Generated HTML string
        """
        self.logger.info("Generating HTML report")
        
        # Load template
        template = self.env.get_template(template_name)
        
        # Render HTML
        html_content = template.render(**data.to_dict())
        
        # Save if output path provided
        if output_path:
            output_path = Path(output_path)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            self.logger.info(f"Report saved to: {output_path}")
        
        return html_content
    
    def generate_from_scan_results(
        self,
        scan_results: dict,
        output_path: Optional[Path] = None
    ) -> str:
        """
        Generate HTML report from raw scan results.
        
        Args:
            scan_results: Dictionary with scan results
            output_path: Optional path to save the report
        
        Returns:
            Generated HTML string
        """
        # Convert scan results to ReportData
        data = self._convert_scan_results(scan_results)
        return self.generate(data, output_path)
    
    def _convert_scan_results(self, results: dict) -> ReportData:
        """Convert raw scan results to ReportData."""
        data = ReportData()
        
        # Extract metadata
        data.title = results.get("title", "Security Scan Report")
        data.scan_duration = results.get("scan_time", 0.0)
        
        if "scanned_at" in results:
            try:
                data.generated_at = datetime.fromisoformat(results["scanned_at"])
            except (ValueError, TypeError):
                pass
        
        # Process hosts - handle both list of hosts and single result
        hosts = results.get("hosts", [])
        if isinstance(results, list):
            hosts = results
        
        data.total_hosts = len(hosts)
        data.hosts = hosts
        data.targets = [h.get("ip_address", h.get("target", "")) for h in hosts]
        
        # Track unique ports
        seen_ports = set()
        
        # Aggregate statistics
        for host in hosts:
            # Count this host as "up"
            data.hosts_up += 1
            
            # Handle vulnerable_services from vuln_scan output
            vuln_services = host.get("vulnerable_services", [])
            for vs in vuln_services:
                # Count unique ports
                port_key = f"{vs.get('port', 0)}/{vs.get('protocol', 'tcp')}"
                if port_key not in seen_ports:
                    seen_ports.add(port_key)
                    data.open_ports += 1
                    data.total_services += 1
                
                # Count CVEs by severity
                for cve in vs.get("cves", []):
                    data.total_cves += 1
                    severity = cve.get("severity", "NONE")
                    if severity == "CRITICAL":
                        data.critical_count += 1
                    elif severity == "HIGH":
                        data.high_count += 1
                    elif severity == "MEDIUM":
                        data.medium_count += 1
                    elif severity == "LOW":
                        data.low_count += 1
                    
                    data.vulnerabilities.append(cve)
            
            # Also handle regular services if present
            services = host.get("services", host.get("open_services", []))
            if services and not vuln_services:
                data.total_services += len(services)
                for svc in services:
                    port_key = f"{svc.get('port', 0)}/{svc.get('protocol', 'tcp')}"
                    if port_key not in seen_ports:
                        seen_ports.add(port_key)
                        data.open_ports += 1
            
            # Handle direct vulnerabilities list
            vulns = host.get("vulnerabilities", [])
            for cve in vulns:
                data.total_cves += 1
                severity = cve.get("severity", "NONE")
                if severity == "CRITICAL":
                    data.critical_count += 1
                elif severity == "HIGH":
                    data.high_count += 1
                elif severity == "MEDIUM":
                    data.medium_count += 1
                elif severity == "LOW":
                    data.low_count += 1
                
                data.vulnerabilities.append(cve)
        
        # Calculate risk
        if data.total_cves > 0:
            data.risk_score = min(100.0, (
                data.critical_count * 40 +
                data.high_count * 20 +
                data.medium_count * 10 +
                data.low_count * 5
            ))
        
        if data.risk_score >= 80:
            data.risk_level = "CRITICAL"
        elif data.risk_score >= 60:
            data.risk_level = "HIGH"
        elif data.risk_score >= 40:
            data.risk_level = "MEDIUM"
        elif data.risk_score >= 20:
            data.risk_level = "LOW"
        else:
            data.risk_level = "MINIMAL"
        
        # Generate recommendations
        data.recommendations = self._generate_recommendations(data)
        
        # Extract AI analysis if present
        if isinstance(results, dict):
            data.ai_threat_summary = results.get("ai_threat_summary", "")
            data.ai_risk_assessment = results.get("ai_risk_assessment", "")
            data.ai_executive_summary = results.get("ai_executive_summary", "")
            data.ai_attack_scenarios = results.get("ai_attack_scenarios", [])
            data.ai_remediation_steps = results.get("ai_remediation_steps", [])
        
        return data
    
    def _generate_recommendations(self, data: ReportData) -> list[str]:
        """Generate basic remediation recommendations."""
        recommendations = []
        
        if data.critical_count > 0:
            recommendations.append(
                f"🔴 URGENT: Address {data.critical_count} critical vulnerabilities immediately. "
                "These pose severe risk and may allow remote code execution or complete system compromise."
            )
        
        if data.high_count > 0:
            recommendations.append(
                f"🟠 HIGH PRIORITY: Remediate {data.high_count} high severity vulnerabilities. "
                "Schedule patches within the next 1-2 weeks."
            )
        
        if data.medium_count > 0:
            recommendations.append(
                f"🟡 MEDIUM PRIORITY: Plan to address {data.medium_count} medium severity issues. "
                "Include in your next maintenance window."
            )
        
        if data.open_ports > 10:
            recommendations.append(
                f"🔒 HARDENING: Consider reducing attack surface by closing unnecessary ports. "
                f"Found {data.open_ports} open ports."
            )
        
        if not recommendations:
            recommendations.append(
                "✅ No critical issues found. Continue regular security monitoring and patching."
            )
        
        return recommendations
    
    def _get_default_template(self) -> str:
        """Return the default HTML template."""
        return '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {
            --critical: #dc3545;
            --high: #fd7e14;
            --medium: #ffc107;
            --low: #0d6efd;
            --info: #6c757d;
        }
        
        * { box-sizing: border-box; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f8f9fa;
        }
        
        .header {
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: white;
            padding: 40px;
            border-radius: 10px;
            margin-bottom: 30px;
        }
        
        .header h1 { margin: 0 0 10px 0; font-size: 2.5em; }
        .header .meta { opacity: 0.8; font-size: 0.9em; }
        
        .card {
            background: white;
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.08);
        }
        
        .card h2 {
            margin-top: 0;
            color: #1a1a2e;
            border-bottom: 2px solid #e9ecef;
            padding-bottom: 10px;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.08);
        }
        
        .stat-card .number { font-size: 2.5em; font-weight: bold; }
        .stat-card .label { color: #6c757d; font-size: 0.9em; }
        .stat-card.critical .number { color: var(--critical); }
        .stat-card.high .number { color: var(--high); }
        .stat-card.medium .number { color: var(--medium); }
        .stat-card.low .number { color: var(--low); }
        
        .risk-badge {
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            color: white;
            font-weight: bold;
        }
        .risk-badge.critical { background: var(--critical); }
        .risk-badge.high { background: var(--high); }
        .risk-badge.medium { background: var(--medium); }
        .risk-badge.low { background: var(--low); }
        .risk-badge.minimal { background: #28a745; }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }
        
        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #e9ecef;
        }
        
        th {
            background: #f8f9fa;
            font-weight: 600;
            color: #495057;
        }
        
        tr:hover { background: #f8f9fa; }
        
        .severity-badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 500;
        }
        .severity-badge.critical { background: #fce4e4; color: var(--critical); }
        .severity-badge.high { background: #fff3e0; color: #e65100; }
        .severity-badge.medium { background: #fff8e1; color: #f57f17; }
        .severity-badge.low { background: #e3f2fd; color: var(--low); }
        
        .recommendation {
            padding: 15px;
            margin: 10px 0;
            border-radius: 8px;
            background: #f8f9fa;
            border-left: 4px solid var(--info);
        }
        
        .chart-container {
            max-width: 400px;
            margin: 0 auto;
        }
        
        @media print {
            body { background: white; }
            .card { box-shadow: none; border: 1px solid #ddd; }
            .no-print { display: none; }
        }
        
        @media (max-width: 768px) {
            .header { padding: 20px; }
            .header h1 { font-size: 1.8em; }
            .stats-grid { grid-template-columns: repeat(2, 1fr); }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ {{ title }}</h1>
        <div class="meta">
            Generated: {{ generated_at }} | 
            Targets: {{ targets|join(', ') if targets else 'N/A' }} |
            Duration: {{ scan_duration }}
        </div>
    </div>
    
    <!-- Executive Summary -->
    <div class="card">
        <h2>📊 Executive Summary</h2>
        <div class="stats-grid">
            <div class="stat-card">
                <div class="number">{{ hosts_up }}</div>
                <div class="label">Hosts Scanned</div>
            </div>
            <div class="stat-card">
                <div class="number">{{ open_ports }}</div>
                <div class="label">Open Ports</div>
            </div>
            <div class="stat-card">
                <div class="number">{{ total_services }}</div>
                <div class="label">Services</div>
            </div>
            <div class="stat-card">
                <div class="number">{{ total_cves }}</div>
                <div class="label">Vulnerabilities</div>
            </div>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card critical">
                <div class="number">{{ critical_count }}</div>
                <div class="label">🔴 Critical</div>
            </div>
            <div class="stat-card high">
                <div class="number">{{ high_count }}</div>
                <div class="label">🟠 High</div>
            </div>
            <div class="stat-card medium">
                <div class="number">{{ medium_count }}</div>
                <div class="label">🟡 Medium</div>
            </div>
            <div class="stat-card low">
                <div class="number">{{ low_count }}</div>
                <div class="label">🟢 Low</div>
            </div>
        </div>
        
        <p style="text-align: center">
            <strong>Risk Score:</strong> {{ "%.1f"|format(risk_score) }}/100
            <span class="risk-badge {{ risk_level|lower }}">{{ risk_level }}</span>
        </p>
    </div>
    
    <!-- Severity Chart -->
    {% if total_cves > 0 %}
    <div class="card">
        <h2>📈 Severity Distribution</h2>
        <div class="chart-container">
            <canvas id="severityChart"></canvas>
        </div>
    </div>
    {% endif %}
    
    <!-- Vulnerabilities Table -->
    {% if vulnerabilities %}
    <div class="card">
        <h2>🔍 Vulnerability Findings</h2>
        <table>
            <thead>
                <tr>
                    <th>CVE ID</th>
                    <th>Severity</th>
                    <th>Score</th>
                    <th>Description</th>
                </tr>
            </thead>
            <tbody>
                {% for cve in vulnerabilities[:50] %}
                <tr>
                    <td><a href="https://nvd.nist.gov/vuln/detail/{{ cve.cve_id }}" target="_blank">{{ cve.cve_id }}</a></td>
                    <td>
                        <span class="severity-badge {{ cve.severity|lower if cve.severity else 'low' }}">
                            {{ cve.severity|severity_icon }} {{ cve.severity or 'N/A' }}
                        </span>
                    </td>
                    <td>{{ "%.1f"|format(cve.base_score) if cve.base_score else 'N/A' }}</td>
                    <td>{{ cve.description[:100] if cve.description else 'No description available' }}...</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        {% if vulnerabilities|length > 50 %}
        <p style="text-align: center; color: #6c757d;">
            Showing 50 of {{ vulnerabilities|length }} vulnerabilities
        </p>
        {% endif %}
    </div>
    {% endif %}
    
    <!-- Recommendations -->
    {% if recommendations %}
    <div class="card">
        <h2>💡 Recommendations</h2>
        {% for rec in recommendations %}
        <div class="recommendation">{{ rec }}</div>
        {% endfor %}
    </div>
    {% endif %}
    
    <!-- Host Details -->
    {% if hosts %}
    <div class="card">
        <h2>🖥️ Host Details</h2>
        {% for host in hosts %}
        <h3>{{ host.ip_address or host.target or 'Unknown Host' }}</h3>
        {% if host.hostname %}
        <p><strong>Hostname:</strong> {{ host.hostname }}</p>
        {% endif %}
        
        {% if host.services or host.open_services %}
        <table>
            <thead>
                <tr>
                    <th>Port</th>
                    <th>Service</th>
                    <th>Version</th>
                </tr>
            </thead>
            <tbody>
                {% for svc in (host.services or host.open_services)[:20] %}
                <tr>
                    <td>{{ svc.port }}/{{ svc.protocol or 'tcp' }}</td>
                    <td>{{ svc.service_name or svc.service or 'unknown' }}</td>
                    <td>{{ svc.version or svc.product or '' }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        {% endif %}
        {% endfor %}
    </div>
    {% endif %}
    
    <!-- Footer -->
    <div style="text-align: center; padding: 30px; color: #6c757d;">
        <p>Generated by AI Network Analyzer | {{ generated_date }}</p>
        <p class="no-print">
            <a href="javascript:window.print()">🖨️ Print Report</a>
        </p>
    </div>
    
    <!-- Chart.js Script -->
    {% if total_cves > 0 %}
    <script>
        const ctx = document.getElementById('severityChart').getContext('2d');
        new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    data: [{{ critical_count }}, {{ high_count }}, {{ medium_count }}, {{ low_count }}],
                    backgroundColor: ['#dc3545', '#fd7e14', '#ffc107', '#0d6efd'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { position: 'bottom' }
                }
            }
        });
    </script>
    {% endif %}
</body>
</html>'''
