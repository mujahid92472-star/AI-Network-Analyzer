"""Improved PDF Report Generator for Web Backend."""

from pathlib import Path
from datetime import datetime
import re


class PDFReporter:
    """Generate professional PDF vulnerability reports."""
    
    def generate_from_scan_results(self, data: dict, output_path: Path) -> bool:
        """
        Generate a PDF report from scan results.
        
        Args:
            data: Dict containing hosts, ai_threat_summary, etc.
            output_path: Path to write PDF file
            
        Returns:
            True if successful
        """
        try:
            # First generate HTML with PDF-specific styling
            html_content = self._generate_pdf_html(data)
            
            # Try xhtml2pdf first (pure Python, works on Windows)
            try:
                from xhtml2pdf import pisa
                with open(str(output_path), 'wb') as f:
                    pisa_status = pisa.CreatePDF(html_content, dest=f, encoding='utf-8')
                
                if not pisa_status.err:
                    print(f"PDF generated successfully with xhtml2pdf: {output_path}")
                    return True
                else:
                    print(f"xhtml2pdf had errors: {pisa_status.err}")
            except ImportError:
                print("xhtml2pdf not installed, trying WeasyPrint...")
            except Exception as e:
                print(f"xhtml2pdf failed: {e}, trying WeasyPrint...")
            
            # Try WeasyPrint as fallback (needs GTK on Windows)
            try:
                from weasyprint import HTML
                HTML(string=html_content).write_pdf(str(output_path))
                print(f"PDF generated successfully with WeasyPrint: {output_path}")
                return True
            except ImportError:
                print("WeasyPrint not installed")
            except Exception as e:
                print(f"WeasyPrint failed: {e}")
            
            # Last resort: save as HTML
            html_path = output_path.with_suffix('.html')
            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            print(f"PDF generation failed, HTML saved as fallback: {html_path}")
            return False
            
        except Exception as e:
            print(f"PDF generation failed: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _format_markdown(self, text: str) -> str:
        """Convert markdown bold to HTML."""
        if not text:
            return text
        return re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
    
    def _generate_pdf_html(self, data: dict) -> str:
        """Generate PDF-optimized HTML content."""
        hosts = data.get("hosts", [])
        ai_summary = data.get("ai_threat_summary", "")
        ai_exec = data.get("ai_executive_summary", "")
        ai_scenarios = data.get("ai_attack_scenarios", [])
        ai_remediation = data.get("ai_remediation_steps", [])
        
        # Calculate statistics
        total_cves = 0
        critical = 0
        high = 0
        medium = 0
        low = 0
        all_cves = []
        host_summary = []
        
        for host in hosts:
            host_ip = host.get("ip_address", "Unknown")
            host_cve_count = 0
            host_services = []
            
            for svc in host.get("vulnerable_services", []):
                svc_cve_count = len(svc.get("cves", []))
                host_cve_count += svc_cve_count
                host_services.append({
                    "port": svc.get("port", ""),
                    "service": svc.get("service_name", ""),
                    "product": svc.get("product", ""),
                    "cve_count": svc_cve_count
                })
                
                for cve in svc.get("cves", []):
                    total_cves += 1
                    severity = str(cve.get("severity", "")).upper()
                    if severity == "CRITICAL":
                        critical += 1
                    elif severity == "HIGH":
                        high += 1
                    elif severity == "MEDIUM":
                        medium += 1
                    elif severity == "LOW":
                        low += 1
                    all_cves.append({
                        **cve,
                        "port": svc.get("port", ""),
                        "service": svc.get("service_name", ""),
                        "product": svc.get("product", ""),
                        "host": host_ip
                    })
            
            host_summary.append({
                "ip": host_ip,
                "cve_count": host_cve_count,
                "services": host_services
            })
        
        # Calculate risk level
        if critical > 0:
            risk_level = "CRITICAL"
            risk_color = "#ef4444"
        elif high > 0:
            risk_level = "HIGH"
            risk_color = "#f97316"
        elif medium > 0:
            risk_level = "MEDIUM"
            risk_color = "#eab308"
        elif low > 0:
            risk_level = "LOW"
            risk_color = "#3b82f6"
        else:
            risk_level = "MINIMAL"
            risk_color = "#22c55e"
        
        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>AI Network Analyzer - Security Report</title>
    <style>
        @page {{
            size: A4;
            margin: 15mm;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
            font-size: 10pt;
            line-height: 1.5;
            color: #1e293b;
            background: white;
        }}
        
        /* Cover Page */
        .cover {{
            page-break-after: always;
            text-align: center;
            padding-top: 100px;
        }}
        .cover-logo {{
            font-size: 48pt;
            margin-bottom: 20px;
        }}
        .cover-title {{
            font-size: 28pt;
            font-weight: bold;
            color: #0f172a;
            margin-bottom: 10px;
        }}
        .cover-subtitle {{
            font-size: 16pt;
            color: #64748b;
            margin-bottom: 60px;
        }}
        .cover-meta {{
            font-size: 12pt;
            color: #64748b;
            margin-top: 100px;
        }}
        .cover-risk {{
            display: inline-block;
            padding: 15px 40px;
            border-radius: 8px;
            font-size: 18pt;
            font-weight: bold;
            color: white;
            margin: 20px 0;
        }}
        
        /* Section Headers */
        .section {{
            margin-bottom: 20px;
            page-break-inside: avoid;
        }}
        .section-title {{
            font-size: 14pt;
            font-weight: bold;
            color: #0f172a;
            border-bottom: 2px solid #e2e8f0;
            padding-bottom: 8px;
            margin-bottom: 15px;
        }}
        
        /* Stats Grid */
        .stats-grid {{
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
        }}
        .stat-box {{
            flex: 1;
            text-align: center;
            padding: 15px;
            border-radius: 8px;
            border: 1px solid #e2e8f0;
        }}
        .stat-value {{
            font-size: 24pt;
            font-weight: bold;
        }}
        .stat-label {{
            font-size: 9pt;
            color: #64748b;
        }}
        .critical {{ color: #ef4444; }}
        .high {{ color: #f97316; }}
        .medium {{ color: #eab308; }}
        .low {{ color: #3b82f6; }}
        
        /* Host Summary */
        .host-card {{
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 12px;
            margin-bottom: 10px;
        }}
        .host-ip {{
            font-weight: bold;
            font-size: 11pt;
        }}
        .host-services {{
            margin-top: 8px;
            font-size: 9pt;
            color: #64748b;
        }}
        
        /* AI Analysis */
        .ai-box {{
            background: #f8fafc;
            border-left: 4px solid #8b5cf6;
            padding: 15px;
            margin-bottom: 15px;
        }}
        .ai-title {{
            font-weight: bold;
            margin-bottom: 8px;
            color: #8b5cf6;
        }}
        .ai-content {{
            line-height: 1.6;
        }}
        .ai-content strong {{
            color: #1e293b;
        }}
        
        /* Scenario */
        .scenario {{
            background: #fef2f2;
            border-left: 4px solid #ef4444;
            padding: 10px;
            margin: 8px 0;
            font-size: 9pt;
        }}
        
        /* Remediation */
        .step {{
            padding: 6px 0;
            border-bottom: 1px solid #f1f5f9;
        }}
        .step:before {{
            content: "✓";
            color: #22c55e;
            margin-right: 8px;
        }}
        
        /* CVE Table */
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 8pt;
            margin-top: 10px;
        }}
        th {{
            background: #f1f5f9;
            padding: 8px;
            text-align: left;
            font-weight: bold;
            border-bottom: 2px solid #e2e8f0;
        }}
        td {{
            padding: 8px;
            border-bottom: 1px solid #e2e8f0;
            vertical-align: top;
        }}
        tr:nth-child(even) {{
            background: #f8fafc;
        }}
        .badge {{
            display: inline-block;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 7pt;
            font-weight: bold;
            color: white;
        }}
        .badge-critical {{ background: #ef4444; }}
        .badge-high {{ background: #f97316; }}
        .badge-medium {{ background: #eab308; color: #1e293b; }}
        .badge-low {{ background: #3b82f6; }}
        .kev-badge {{ background: #ef4444; padding: 1px 4px; margin-left: 4px; }}
        
        .cve-desc {{
            max-width: 200px;
            overflow: hidden;
            text-overflow: ellipsis;
        }}
    </style>
</head>
<body>
    <!-- Cover Page -->
    <div class="cover">
        <div class="cover-logo">🛡️</div>
        <div class="cover-title">AI Network Analyzer</div>
        <div class="cover-subtitle">Security Assessment Report</div>
        
        <div class="cover-risk" style="background: {risk_color};">
            {risk_level} RISK
        </div>
        
        <div class="cover-meta">
            <p><strong>Total Vulnerabilities:</strong> {total_cves}</p>
            <p><strong>Hosts Scanned:</strong> {len(host_summary)}</p>
            <p><strong>Generated:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>
    </div>
    
    <!-- Executive Summary -->
    <div class="section">
        <h2 class="section-title">📊 Executive Summary</h2>
        
        <div class="stats-grid">
            <div class="stat-box">
                <div class="stat-value">{total_cves}</div>
                <div class="stat-label">Total CVEs</div>
            </div>
            <div class="stat-box">
                <div class="stat-value critical">{critical}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-box">
                <div class="stat-value high">{high}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-box">
                <div class="stat-value medium">{medium}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-box">
                <div class="stat-value low">{low}</div>
                <div class="stat-label">Low</div>
            </div>
        </div>
    </div>
'''
        
        # Host Summary
        if host_summary:
            html += '''
    <div class="section">
        <h2 class="section-title">🖥️ Scanned Hosts</h2>
'''
            for host in host_summary:
                html += f'''
        <div class="host-card">
            <div class="host-ip">{host["ip"]} - {host["cve_count"]} CVEs found</div>
            <div class="host-services">
'''
                for svc in host["services"][:5]:
                    html += f'                Port {svc["port"]}: {svc["product"]} ({svc["cve_count"]} CVEs)<br>'
                html += '''
            </div>
        </div>
'''
            html += '    </div>\n'
        
        # AI Analysis
        if ai_summary or ai_exec or ai_scenarios or ai_remediation:
            html += '''
    <div class="section">
        <h2 class="section-title">🤖 AI Threat Analysis</h2>
'''
            if ai_summary:
                html += f'''
        <div class="ai-box">
            <div class="ai-title">Threat Summary</div>
            <div class="ai-content">{self._format_markdown(ai_summary)}</div>
        </div>
'''
            
            if ai_scenarios:
                html += '        <div class="ai-box"><div class="ai-title">⚔️ Attack Scenarios</div>\n'
                for scenario in ai_scenarios[:5]:
                    html += f'            <div class="scenario">{self._format_markdown(scenario)}</div>\n'
                html += '        </div>\n'
            
            if ai_remediation:
                html += '        <div class="ai-box"><div class="ai-title">🔧 Recommended Actions</div>\n'
                for step in ai_remediation[:7]:
                    html += f'            <div class="step">{self._format_markdown(step)}</div>\n'
                html += '        </div>\n'
            
            html += '    </div>\n'
        
        # CVE Table
        if all_cves:
            html += f'''
    <div class="section">
        <h2 class="section-title">🔍 Vulnerability Details ({len(all_cves)} CVEs)</h2>
        <table>
            <thead>
                <tr>
                    <th>CVE ID</th>
                    <th>Severity</th>
                    <th>Score</th>
                    <th>Host</th>
                    <th>Port</th>
                    <th>Product</th>
                    <th>Description</th>
                </tr>
            </thead>
            <tbody>
'''
            for cve in all_cves[:100]:
                severity = str(cve.get("severity", "")).upper()
                badge_class = f"badge-{severity.lower()}" if severity else "badge-low"
                kev = '<span class="kev-badge badge">KEV</span>' if cve.get("in_kev") else ""
                desc = cve.get("description", "")[:100] + "..." if len(cve.get("description", "")) > 100 else cve.get("description", "")
                
                html += f'''
                <tr>
                    <td>{cve.get("cve_id", "")}{kev}</td>
                    <td><span class="badge {badge_class}">{severity}</span></td>
                    <td>{cve.get("base_score", "N/A")}</td>
                    <td>{cve.get("host", "")}</td>
                    <td>{cve.get("port", "")}</td>
                    <td>{cve.get("product", "")}</td>
                    <td class="cve-desc">{desc}</td>
                </tr>
'''
            
            html += '''
            </tbody>
        </table>
    </div>
'''
        
        html += '''
    <!-- Footer -->
    <div style="margin-top: 40px; text-align: center; color: #64748b; font-size: 9pt;">
        <p>Generated by AI Network Analyzer</p>
    </div>
</body>
</html>
'''
        
        return html
