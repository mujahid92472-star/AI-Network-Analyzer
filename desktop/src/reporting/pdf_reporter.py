"""
PDF Report Generator - Convert HTML reports to PDF.

Uses xhtml2pdf for pure-Python PDF generation without system dependencies.
Creates professional PDF reports with:
- Cover page
- Table of contents
- Page numbers and headers
- Print-optimized styling
"""

import io
from pathlib import Path
from typing import Optional
from datetime import datetime

try:
    from xhtml2pdf import pisa
    XHTML2PDF_AVAILABLE = True
except ImportError:
    XHTML2PDF_AVAILABLE = False

import re
from src.core import get_logger
from src.reporting.html_reporter import HTMLReporter, ReportData


class PDFReporter:
    """
    PDF report generator using xhtml2pdf.
    
    Converts HTML reports to PDF format with cover page,
    table of contents, and professional formatting.
    """
    
    def __init__(self):
        """Initialize the PDF reporter."""
        self.logger = get_logger("pdf_reporter")
        self.html_reporter = HTMLReporter()
        
        if not XHTML2PDF_AVAILABLE:
            self.logger.warning("xhtml2pdf not installed. Install with: pip install xhtml2pdf")
    
    def generate(
        self,
        data: ReportData,
        output_path: Path,
        include_cover: bool = True
    ) -> bool:
        """
        Generate a PDF report.
        
        Args:
            data: ReportData object with scan results
            output_path: Path to save the PDF
            include_cover: Whether to include cover page
        
        Returns:
            True if successful, False otherwise
        """
        if not XHTML2PDF_AVAILABLE:
            self.logger.error("xhtml2pdf not available")
            return False
        
        self.logger.info("Generating PDF report")
        
        # Generate HTML content with PDF-specific styling
        html_content = self._generate_pdf_html(data, include_cover)
        
        # Convert to PDF
        try:
            output_path = Path(output_path)
            with open(output_path, 'wb') as f:
                pisa_status = pisa.CreatePDF(
                    html_content,
                    dest=f,
                    encoding='utf-8'
                )
            
            if pisa_status.err:
                self.logger.error(f"PDF generation error: {pisa_status.err}")
                return False
            
            self.logger.info(f"PDF report saved to: {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"PDF generation failed: {e}")
            return False
    
    def generate_from_html(
        self,
        html_content: str,
        output_path: Path
    ) -> bool:
        """
        Convert existing HTML to PDF.
        
        Args:
            html_content: HTML string
            output_path: Path to save the PDF
        
        Returns:
            True if successful
        """
        if not XHTML2PDF_AVAILABLE:
            self.logger.error("xhtml2pdf not available")
            return False
        
        try:
            output_path = Path(output_path)
            with open(output_path, 'wb') as f:
                pisa_status = pisa.CreatePDF(
                    html_content,
                    dest=f,
                    encoding='utf-8'
                )
            
            return not pisa_status.err
            
        except Exception as e:
            self.logger.error(f"PDF conversion failed: {e}")
            return False
    
    def generate_from_scan_results(
        self,
        scan_results: dict,
        output_path: Path
    ) -> bool:
        """
        Generate PDF from raw scan results.
        
        Args:
            scan_results: Dictionary with scan results
            output_path: Path to save the PDF
        
        Returns:
            True if successful
        """
        data = self.html_reporter._convert_scan_results(scan_results)
        return self.generate(data, output_path)
    
    def _format_markdown(self, text: str) -> str:
        """Convert markdown bold (**text**) to HTML strong tags."""
        if not text:
            return text
        return re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
    
    def _generate_pdf_html(self, data: ReportData, include_cover: bool = True) -> str:
        """Generate HTML optimized for PDF conversion."""
        
        targets_str = ", ".join(data.targets) if data.targets else "N/A"
        
        # Build host details section (matching HTML format) - will be placed at end
        hosts_html = ""
        if data.hosts:
            hosts_sections = []
            for host in data.hosts[:10]:
                ip = host.get("ip_address", host.get("target", "Unknown"))
                hostname = host.get("hostname", "")
                services = host.get("vulnerable_services", host.get("services", []))
                
                if services:
                    svc_rows = []
                    for svc in services[:15]:
                        port = svc.get("port", "")
                        protocol = svc.get("protocol", "tcp")
                        service_name = svc.get("service_name", svc.get("service", "unknown"))
                        product = svc.get("product", svc.get("version", ""))
                        cve_count = svc.get("cve_count", len(svc.get("cves", [])))
                        svc_rows.append(f'<tr><td>{port}/{protocol}</td><td>{service_name}</td><td>{product}</td><td>{cve_count}</td></tr>')
                    
                    host_section = f'''
            <h3>{ip}{f" ({hostname})" if hostname else ""}</h3>
            <table>
                <tr><th>Port</th><th>Service</th><th>Product</th><th>CVEs</th></tr>
                {"".join(svc_rows)}
            </table>
            '''
                    hosts_sections.append(host_section)
            
            if hosts_sections:
                hosts_html = f'''
            <h2>🖥️ Host Details</h2>
            {"".join(hosts_sections)}
            '''
        
        # Build vulnerability table
        vuln_table = ""
        if data.vulnerabilities:
            vuln_rows = []
            for v in data.vulnerabilities[:50]:
                cve_id = v.get("cve_id", "")
                severity = v.get("severity", "").upper()
                severity_class = severity.lower() if severity else "low"
                score = v.get("base_score", 0)
                desc = v.get("description", "")[:60] + "..." if len(v.get("description", "")) > 60 else v.get("description", "")
                vuln_rows.append(f'<tr><td>{cve_id}</td><td class="severity-{severity_class}">{severity}</td><td>{score:.1f}</td><td>{desc}</td></tr>')
            
            vuln_table = f'''
            <h2>🔍 Vulnerability Findings ({len(data.vulnerabilities)} CVEs)</h2>
            <table>
                <tr><th>CVE ID</th><th>Severity</th><th>Score</th><th>Description</th></tr>
                {"".join(vuln_rows)}
            </table>
            '''
        
        # Build recommendations
        rec_html = ""
        if data.recommendations:
            rec_items = "".join(f'<div class="recommendation">✓ {r}</div>' for r in data.recommendations[:10])
            rec_html = f'<h2>🔧 Recommendations</h2>{rec_items}'
        
        # Build AI analysis section with markdown bold conversion
        ai_html = ""
        if data.ai_threat_summary:
            ai_html = f'''
            <h2>🤖 AI Threat Analysis</h2>
            <div class="ai-box">
                <h3>Threat Summary</h3>
                <p>{self._format_markdown(data.ai_threat_summary)}</p>
            </div>
            '''
            if data.ai_executive_summary:
                ai_html += f'''
                <div class="ai-box">
                    <h3>Executive Summary</h3>
                    <p>{self._format_markdown(data.ai_executive_summary)}</p>
                </div>
                '''
            if data.ai_attack_scenarios:
                scenarios = "".join(f'<li>{self._format_markdown(s)}</li>' for s in data.ai_attack_scenarios[:5])
                ai_html += f'''
                <div class="ai-box attack">
                    <h3>⚔️ Attack Scenarios</h3>
                    <ul>{scenarios}</ul>
                </div>
                '''
            if data.ai_remediation_steps:
                steps = "".join(f'<li>{self._format_markdown(s)}</li>' for s in data.ai_remediation_steps[:7])
                ai_html += f'''
                <div class="ai-box remediation">
                    <h3>🔧 Remediation Steps</h3>
                    <ul>{steps}</ul>
                </div>
                '''
        
        return f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{data.title}</title>
    <style>
        @page {{
            size: A4;
            margin: 1.5cm;
        }}
        
        body {{
            font-family: Helvetica, Arial, sans-serif;
            font-size: 10pt;
            line-height: 1.5;
            color: #333;
        }}
        
        .header {{
            text-align: center;
            border-bottom: 3px solid #1a1a2e;
            padding-bottom: 20px;
            margin-bottom: 25px;
        }}
        
        .header h1 {{
            font-size: 24pt;
            color: #1a1a2e;
            margin: 0 0 10px 0;
        }}
        
        .header .meta {{
            color: #666;
            font-size: 10pt;
        }}
        
        .risk-badge {{
            display: inline-block;
            color: white;
            padding: 4px 15px;
            font-weight: bold;
            border-radius: 4px;
            margin-left: 10px;
        }}
        .risk-critical {{ background: #dc3545; }}
        .risk-high {{ background: #fd7e14; }}
        .risk-medium {{ background: #ffc107; color: #333; }}
        .risk-low {{ background: #0d6efd; }}
        .risk-minimal {{ background: #28a745; }}
        
        h2 {{ 
            color: #1a1a2e; 
            border-bottom: 2px solid #e9ecef; 
            padding-bottom: 8px;
            margin-top: 25px;
            margin-bottom: 15px;
            font-size: 14pt;
        }}
        
        h3 {{ color: #333; font-size: 11pt; margin: 10px 0 5px 0; }}
        
        /* Executive Summary Table */
        .summary-table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }}
        
        .summary-table td {{
            padding: 12px 15px;
            text-align: center;
            border: 1px solid #dee2e6;
            background: #f8f9fa;
        }}
        
        .summary-table .metric-value {{
            font-size: 22pt;
            font-weight: bold;
            display: block;
        }}
        
        .summary-table .metric-label {{
            font-size: 9pt;
            color: #666;
            text-transform: uppercase;
        }}
        
        .summary-table .critical {{ color: #dc3545; }}
        .summary-table .high {{ color: #fd7e14; }}
        .summary-table .medium {{ color: #eab308; }}
        .summary-table .low {{ color: #0d6efd; }}
        
        /* Regular tables */
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 10px 0;
            font-size: 9pt;
        }}
        
        th, td {{
            padding: 8px 10px;
            text-align: left;
            border: 1px solid #dee2e6;
        }}
        
        th {{ 
            background: #1a1a2e; 
            color: white;
            font-weight: bold; 
        }}
        
        tr:nth-child(even) {{ background: #f8f9fa; }}
        
        .severity-critical {{ color: #dc3545; font-weight: bold; }}
        .severity-high {{ color: #fd7e14; font-weight: bold; }}
        .severity-medium {{ color: #eab308; }}
        .severity-low {{ color: #0d6efd; }}
        
        .recommendation {{
            padding: 10px 12px;
            margin: 6px 0;
            background: #f0fdf4;
            border-left: 4px solid #22c55e;
            font-size: 9pt;
        }}
        
        .ai-box {{
            background: #f0f4ff;
            border-left: 4px solid #667eea;
            padding: 12px 15px;
            margin: 12px 0;
        }}
        
        .ai-box.attack {{
            background: #fef2f2;
            border-left-color: #ef4444;
        }}
        
        .ai-box.remediation {{
            background: #f0fdf4;
            border-left-color: #22c55e;
        }}
        
        .ai-box p {{ margin: 5px 0; font-size: 9pt; }}
        .ai-box ul {{ margin: 5px 0; padding-left: 20px; font-size: 9pt; }}
        .ai-box li {{ margin: 3px 0; }}
        
        .footer {{
            text-align: center;
            margin-top: 30px;
            padding-top: 15px;
            border-top: 1px solid #ddd;
            color: #666;
            font-size: 8pt;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Security Scan Report</h1>
        <div class="meta">
            Generated: {data.generated_at.strftime("%B %d, %Y at %H:%M")} | 
            Targets: {targets_str}
            <span class="risk-badge risk-{data.risk_level.lower()}">{data.risk_level} RISK</span>
        </div>
    </div>
    
    <h2>📊 Executive Summary</h2>
    <table class="summary-table">
        <tr>
            <td>
                <span class="metric-value">{data.hosts_up}</span>
                <span class="metric-label">Hosts Scanned</span>
            </td>
            <td>
                <span class="metric-value">{data.open_ports}</span>
                <span class="metric-label">Open Ports</span>
            </td>
            <td>
                <span class="metric-value">{data.total_services}</span>
                <span class="metric-label">Services Found</span>
            </td>
            <td>
                <span class="metric-value">{data.total_cves}</span>
                <span class="metric-label">Total CVEs</span>
            </td>
            <td>
                <span class="metric-value">{data.risk_score:.0f}/100</span>
                <span class="metric-label">Risk Score</span>
            </td>
        </tr>
    </table>
    
    <table class="summary-table">
        <tr>
            <td>
                <span class="metric-value critical">{data.critical_count}</span>
                <span class="metric-label">Critical</span>
            </td>
            <td>
                <span class="metric-value high">{data.high_count}</span>
                <span class="metric-label">High</span>
            </td>
            <td>
                <span class="metric-value medium">{data.medium_count}</span>
                <span class="metric-label">Medium</span>
            </td>
            <td>
                <span class="metric-value low">{data.low_count}</span>
                <span class="metric-label">Low</span>
            </td>
        </tr>
    </table>
    
    
    {ai_html}
    
    {vuln_table}
    
    {rec_html}
    
    {hosts_html}
    
    <div class="footer">
        <p>Generated by AI Network Analyzer | Powered by NVD & Gemini AI</p>
    </div>
</body>
</html>'''
