"""HTML Report Generator for Web Backend - Enhanced version."""

from pathlib import Path
from datetime import datetime
import re


class HTMLReporter:
    """Generate HTML vulnerability reports with host details and recommendations."""
    
    def generate_from_scan_results(self, data: dict, output_path: Path) -> bool:
        """
        Generate an HTML report from scan results.
        
        Args:
            data: Dict containing hosts, ai_threat_summary, etc.
            output_path: Path to write HTML file
            
        Returns:
            True if successful
        """
        hosts = data.get("hosts", [])
        ai_summary = data.get("ai_threat_summary", "")
        ai_exec = data.get("ai_executive_summary", "")
        ai_scenarios = data.get("ai_attack_scenarios", [])
        ai_remediation = data.get("ai_remediation_steps", [])
        recommendations = data.get("recommendations", [])
        
        # Merge recommendations - prefer explicit recommendations, fall back to ai_remediation
        all_recommendations = recommendations if recommendations else ai_remediation
        
        # Calculate statistics and build host summary
        total_cves = 0
        critical = 0
        high = 0
        medium = 0
        low = 0
        all_cves = []
        host_details = []
        
        for host in hosts:
            host_ip = host.get("ip_address", "Unknown")
            host_cves = 0
            host_services = []
            
            for svc in host.get("vulnerable_services", []):
                svc_cves = svc.get("cves", [])
                host_cves += len(svc_cves)
                host_services.append({
                    "port": svc.get("port", ""),
                    "name": svc.get("service_name", ""),
                    "product": svc.get("product", ""),
                    "version": svc.get("version", ""),
                    "cve_count": len(svc_cves)
                })
                
                for cve in svc_cves:
                    total_cves += 1
                    severity = cve.get("severity", "").upper()
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
                        "host": host_ip,
                        "port": svc.get("port", ""),
                        "service": svc.get("service_name", ""),
                        "product": svc.get("product", "")
                    })
            
            if host_services:
                host_details.append({
                    "ip": host_ip,
                    "services": host_services,
                    "cve_count": host_cves
                })
        
        # Determine risk level
        if critical > 0:
            risk_level = "CRITICAL"
            risk_color = "#ef4444"
        elif high > 0:
            risk_level = "HIGH"
            risk_color = "#f97316"
        elif medium > 0:
            risk_level = "MEDIUM"
            risk_color = "#eab308"
        else:
            risk_level = "LOW"
            risk_color = "#3b82f6"
        
        # Generate HTML
        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Network Analyzer Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0f172a; 
            color: #e2e8f0; 
            line-height: 1.6;
            padding: 20px;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{ 
            background: linear-gradient(135deg, #1e293b, #0f172a);
            padding: 30px; 
            border-radius: 12px;
            margin-bottom: 24px;
            border: 1px solid #334155;
        }}
        h1 {{ color: #06b6d4; font-size: 28px; word-break: break-word; }}
        .subtitle {{ color: #94a3b8; margin-top: 8px; }}
        .risk-indicator {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 6px;
            font-weight: bold;
            font-size: 14px;
            margin-left: 12px;
        }}
        .stats {{ 
            display: grid; 
            grid-template-columns: repeat(5, 1fr); 
            gap: 16px; 
            margin-bottom: 24px;
        }}
        @media (max-width: 768px) {{
            .stats {{ grid-template-columns: repeat(3, 1fr); }}
            h1 {{ font-size: 22px; }}
            body {{ padding: 12px; }}
        }}
        @media (max-width: 480px) {{
            .stats {{ grid-template-columns: repeat(2, 1fr); gap: 8px; }}
            .stat {{ padding: 12px; }}
            .stat-value {{ font-size: 24px; }}
        }}
        .stat {{ 
            background: #1e293b; 
            padding: 20px; 
            border-radius: 12px;
            text-align: center;
            border: 1px solid #334155;
        }}
        .stat-value {{ font-size: 32px; font-weight: bold; }}
        .stat-label {{ color: #94a3b8; font-size: 14px; margin-top: 4px; }}
        .critical {{ color: #ef4444; }}
        .high {{ color: #f97316; }}
        .medium {{ color: #eab308; }}
        .low {{ color: #3b82f6; }}
        .section {{ 
            background: #1e293b; 
            padding: 24px; 
            border-radius: 12px;
            margin-bottom: 24px;
            border: 1px solid #334155;
            overflow: hidden;
        }}
        @media (max-width: 480px) {{
            .section {{ padding: 16px; }}
        }}
        .section-title {{ 
            font-size: 20px; 
            color: #fff;
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        
        /* Host Details */
        .host-card {{
            background: #0f172a;
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 12px;
        }}
        .host-ip {{
            font-size: 18px;
            font-weight: bold;
            color: #06b6d4;
            margin-bottom: 8px;
        }}
        .host-services {{
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
        }}
        .service-tag {{
            background: #334155;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 12px;
        }}
        .service-tag .port {{
            color: #06b6d4;
            font-weight: bold;
        }}
        .cve-count {{
            color: #ef4444;
            margin-left: 4px;
        }}
        
        /* AI Analysis */
        .ai-content {{ color: #cbd5e1; }}
        .ai-summary {{
            background: #0f172a;
            border-left: 4px solid #8b5cf6;
            padding: 16px;
            border-radius: 0 8px 8px 0;
            margin-bottom: 16px;
        }}
        .scenario {{ 
            background: rgba(239, 68, 68, 0.1);
            border-left: 4px solid #ef4444;
            padding: 12px 16px;
            margin: 8px 0;
            border-radius: 0 8px 8px 0;
        }}
        .step {{ 
            padding: 8px 0;
            border-bottom: 1px solid #334155;
            display: flex;
            gap: 8px;
        }}
        .step:last-child {{ border-bottom: none; }}
        .check {{ color: #22c55e; }}
        
        /* Recommendations */
        .recommendation {{
            background: #0f172a;
            border-left: 4px solid #22c55e;
            padding: 12px 16px;
            margin: 8px 0;
            border-radius: 0 8px 8px 0;
        }}
        
        /* Responsive table wrapper */
        .table-wrapper {{
            overflow-x: auto;
            -webkit-overflow-scrolling: touch;
        }}
        table {{ 
            width: 100%; 
            border-collapse: collapse; 
            min-width: 600px;
        }}
        th {{ 
            background: #0f172a; 
            padding: 12px 8px; 
            text-align: left;
            color: #94a3b8;
            font-size: 11px;
            text-transform: uppercase;
            white-space: nowrap;
        }}
        td {{ 
            padding: 10px 8px; 
            border-bottom: 1px solid #334155;
            font-size: 13px;
        }}
        tr:hover {{ background: rgba(6, 182, 212, 0.05); }}
        .cve-id {{ color: #06b6d4; font-weight: 500; white-space: nowrap; }}
        .badge {{ 
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 10px;
            font-weight: bold;
            white-space: nowrap;
        }}
        .badge-critical {{ background: #ef4444; color: white; }}
        .badge-high {{ background: #f97316; color: white; }}
        .badge-medium {{ background: #eab308; color: black; }}
        .badge-low {{ background: #3b82f6; color: white; }}
        .kev {{ background: #ef4444; color: white; padding: 2px 6px; border-radius: 4px; font-size: 10px; white-space: nowrap; }}
        @media print {{
            body {{ background: white; color: black; }}
            .section, .stat, header {{ border-color: #ddd; background: #f8f8f8; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ AI Network Analyzer - Security Report
                <span class="risk-indicator" style="background: {risk_color}; color: white;">{risk_level} RISK</span>
            </h1>
            <p class="subtitle">Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | Hosts: {len(host_details)} | CVEs: {total_cves}</p>
        </header>

        <div class="stats">
            <div class="stat">
                <div class="stat-value">{total_cves}</div>
                <div class="stat-label">Total CVEs</div>
            </div>
            <div class="stat">
                <div class="stat-value critical">{critical}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat">
                <div class="stat-value high">{high}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat">
                <div class="stat-value medium">{medium}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat">
                <div class="stat-value low">{low}</div>
                <div class="stat-label">Low</div>
            </div>
        </div>
'''
        
        # Host Details section
        if host_details:
            html += '''
        <div class="section">
            <h2 class="section-title">🖥️ Scanned Hosts</h2>
'''
            for host in host_details:
                html += f'''
            <div class="host-card">
                <div class="host-ip">{host["ip"]} <span style="color: #94a3b8; font-size: 14px;">({host["cve_count"]} CVEs)</span></div>
                <div class="host-services">
'''
                for svc in host["services"]:
                    html += f'''
                    <div class="service-tag">
                        <span class="port">{svc["port"]}</span> {svc["product"] or svc["name"]}
                        {f'<span class="cve-count">({svc["cve_count"]})</span>' if svc["cve_count"] > 0 else ''}
                    </div>
'''
                html += '''
                </div>
            </div>
'''
            html += '        </div>\n'
        
        # AI Analysis section
        if ai_summary or ai_exec or ai_scenarios or ai_remediation:
            html += '''
        <div class="section">
            <h2 class="section-title">🤖 AI Threat Analysis</h2>
'''
            if ai_summary:
                html += f'''
            <div class="ai-summary">
                <h3 style="color: #8b5cf6; margin-bottom: 8px;">Threat Summary</h3>
                <p class="ai-content">{self._format_markdown(ai_summary)}</p>
            </div>
'''
            if ai_exec:
                html += f'''
            <div class="ai-summary" style="border-color: #06b6d4;">
                <h3 style="color: #06b6d4; margin-bottom: 8px;">Executive Summary</h3>
                <p class="ai-content">{self._format_markdown(ai_exec)}</p>
            </div>
'''
            
            if ai_scenarios:
                html += '<h3 style="margin: 16px 0 8px; color: #ef4444;">⚔️ Attack Scenarios</h3>\n'
                for scenario in ai_scenarios[:5]:
                    html += f'            <div class="scenario">{self._format_markdown(scenario)}</div>\n'
            
            html += '        </div>\n'
        
        # Recommendations section (from recommendations or AI remediation steps)
        if all_recommendations:
            html += '''
        <div class="section">
            <h2 class="section-title">🔧 Recommendations</h2>
'''
            for i, step in enumerate(all_recommendations[:10], 1):
                html += f'''
            <div class="recommendation">
                <span class="check">✓</span> {self._format_markdown(step)}
            </div>
'''
            html += '        </div>\n'
        
        # CVE Table
        if all_cves:
            html += f'''
        <div class="section">
            <h2 class="section-title">🔍 Vulnerability Details ({len(all_cves)} CVEs)</h2>
            <div class="table-wrapper">
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
                severity = cve.get("severity", "").upper()
                badge_class = f"badge-{severity.lower()}" if severity else "badge-low"
                kev_badge = '<span class="kev">🔥 KEV</span>' if cve.get("in_kev") else ""
                desc = cve.get("description", "")[:80] + "..." if len(cve.get("description", "")) > 80 else cve.get("description", "")
                
                html += f'''
                    <tr>
                        <td>
                            <a href="https://nvd.nist.gov/vuln/detail/{cve.get("cve_id", "")}" 
                               target="_blank" class="cve-id">{cve.get("cve_id", "")}</a>
                            {kev_badge}
                        </td>
                        <td><span class="badge {badge_class}">{severity}</span></td>
                        <td>{cve.get("base_score", "N/A")}</td>
                        <td style="color: #94a3b8;">{cve.get("host", "")}</td>
                        <td>{cve.get("port", "")}</td>
                        <td>{cve.get("product", "")}</td>
                        <td style="max-width: 200px; word-break: break-word;">{desc}</td>
                    </tr>
'''
            
            html += '''
                </tbody>
            </table>
            </div>
        </div>
'''
        
        html += '''
        <footer style="text-align: center; padding: 20px; color: #64748b; font-size: 12px;">
            Generated by AI Network Analyzer | Powered by NVD & Gemini AI
        </footer>
    </div>
</body>
</html>
'''
        
        # Write file
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
        
        return True
    
    def _format_markdown(self, text: str) -> str:
        """Convert markdown bold to HTML."""
        if not text:
            return text
        return re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
