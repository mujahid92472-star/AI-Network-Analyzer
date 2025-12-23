"""
Gemini API Client - Google AI integration for threat intelligence.

Provides AI-powered security analysis using Google's Gemini API:
- Natural language threat summaries
- Remediation recommendations
- Attack scenario predictions
- Risk contextualization
"""

import os
from typing import Optional
from dataclasses import dataclass

try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False

from src.core import get_logger


@dataclass
class AIAnalysisResult:
    """Result from AI threat analysis."""
    
    threat_summary: str = ""
    risk_assessment: str = ""
    attack_scenarios: list[str] = None
    remediation_steps: list[str] = None
    priority_ranking: str = ""
    executive_summary: str = ""
    
    def __post_init__(self):
        if self.attack_scenarios is None:
            self.attack_scenarios = []
        if self.remediation_steps is None:
            self.remediation_steps = []
    
    def to_dict(self) -> dict:
        return {
            "threat_summary": self.threat_summary,
            "risk_assessment": self.risk_assessment,
            "attack_scenarios": self.attack_scenarios,
            "remediation_steps": self.remediation_steps,
            "priority_ranking": self.priority_ranking,
            "executive_summary": self.executive_summary
        }


class GeminiClient:
    """
    Google Gemini API client for AI-powered threat intelligence.
    
    Provides natural language analysis of vulnerability scan results,
    including threat summaries, remediation recommendations, and
    attack scenario predictions.
    """
    
    DEFAULT_MODEL = "gemini-flash-lite-latest"  # Try lite model with different quota
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        model_name: str = DEFAULT_MODEL
    ):
        """
        Initialize the Gemini client.
        
        Args:
            api_key: Gemini API key (or set GEMINI_API_KEY env var)
            model_name: Model to use (default: gemini-1.5-flash)
        """
        self.logger = get_logger("gemini_client")
        
        if not GEMINI_AVAILABLE:
            raise ImportError(
                "google-generativeai not installed. "
                "Install with: pip install google-generativeai"
            )
        
        # Get API key from parameter or environment
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY")
        if not self.api_key:
            raise ValueError(
                "Gemini API key required. Set GEMINI_API_KEY environment variable "
                "or pass api_key parameter."
            )
        
        # Configure Gemini
        genai.configure(api_key=self.api_key)
        self.model = genai.GenerativeModel(model_name)
        self.model_name = model_name
        
        self.logger.info(f"Gemini client initialized with model: {model_name}")
    
    def analyze_vulnerabilities(
        self,
        vulnerabilities: list[dict],
        host_info: Optional[dict] = None,
        context: str = ""
    ) -> AIAnalysisResult:
        """
        Analyze vulnerabilities and generate AI-powered insights.
        
        Makes a SINGLE API call to get all analysis in one request.
        Includes automatic retry for rate limiting.
        
        Args:
            vulnerabilities: List of CVE dictionaries
            host_info: Optional host information (IP, services, etc.)
            context: Additional context about the target
        
        Returns:
            AIAnalysisResult with threat analysis
        """
        import time
        
        if not vulnerabilities:
            return AIAnalysisResult(
                threat_summary="No vulnerabilities detected.",
                risk_assessment="LOW - No known vulnerabilities found.",
                executive_summary="The scan found no known vulnerabilities."
            )
        
        # Build comprehensive prompt for SINGLE API call
        prompt = self._build_analysis_prompt(vulnerabilities, host_info, context)
        
        # Retry logic for rate limits
        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = self.model.generate_content(prompt)
                return self._parse_analysis_response(response.text)
            except Exception as e:
                error_str = str(e)
                
                # Handle rate limit (429)
                if "429" in error_str or "quota" in error_str.lower():
                    # Extract wait time if available
                    wait_time = 20  # Default wait
                    if "retry in" in error_str.lower():
                        import re
                        match = re.search(r'(\d+\.?\d*)\s*s', error_str)
                        if match:
                            wait_time = min(float(match.group(1)) + 2, 60)
                    
                    if attempt < max_retries - 1:
                        self.logger.warning(f"Rate limited, waiting {wait_time}s before retry...")
                        time.sleep(wait_time)
                        continue
                
                self.logger.error(f"Gemini API error: {e}")
                return AIAnalysisResult(
                    threat_summary=f"AI analysis failed: {e}",
                    risk_assessment="Unable to assess - AI error"
                )
    
    def generate_threat_summary(
        self,
        scan_results: dict,
        max_vulns: int = 20
    ) -> str:
        """
        Generate a natural language threat summary.
        
        Args:
            scan_results: Full scan results dictionary
            max_vulns: Maximum vulnerabilities to analyze
        
        Returns:
            Threat summary string
        """
        # Extract key information
        hosts = scan_results.get("hosts", [])
        if isinstance(scan_results, list):
            hosts = scan_results
        
        total_vulns = 0
        critical_vulns = []
        high_vulns = []
        
        for host in hosts:
            for v in host.get("vulnerabilities", [])[:max_vulns]:
                total_vulns += 1
                severity = v.get("severity", "").upper()
                if severity == "CRITICAL":
                    critical_vulns.append(v)
                elif severity == "HIGH":
                    high_vulns.append(v)
        
        prompt = f"""You are a cybersecurity expert. Provide a brief, professional threat summary for a security scan.

Scan Results:
- Hosts scanned: {len(hosts)}
- Total vulnerabilities: {total_vulns}
- Critical vulnerabilities: {len(critical_vulns)}
- High severity vulnerabilities: {len(high_vulns)}

Top Critical Vulnerabilities:
{self._format_vulns_for_prompt(critical_vulns[:5])}

Top High Severity Vulnerabilities:
{self._format_vulns_for_prompt(high_vulns[:5])}

Write a concise 2-3 paragraph threat summary that:
1. Summarizes the overall security posture
2. Highlights the most serious risks
3. Provides actionable next steps

Keep it professional and suitable for a security report."""

        try:
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            self.logger.error(f"Failed to generate threat summary: {e}")
            return f"Unable to generate AI summary: {e}"
    
    def get_remediation_recommendations(
        self,
        cve_list: list[dict],
        prioritize: bool = True
    ) -> list[str]:
        """
        Generate prioritized remediation recommendations.
        
        Args:
            cve_list: List of CVE dictionaries
            prioritize: Whether to prioritize by severity
        
        Returns:
            List of remediation steps
        """
        if not cve_list:
            return ["No vulnerabilities require remediation."]
        
        # Sort by severity if requested
        if prioritize:
            severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            cve_list = sorted(
                cve_list,
                key=lambda x: severity_order.get(x.get("severity", "LOW").upper(), 4)
            )
        
        prompt = f"""You are a cybersecurity remediation expert. Based on these vulnerabilities, provide specific, actionable remediation steps.

Vulnerabilities:
{self._format_vulns_for_prompt(cve_list[:15])}

Provide a numbered list of 5-10 specific remediation steps, prioritized by urgency.
Focus on practical, immediately actionable steps.
Format each step on a new line starting with a number."""

        try:
            response = self.model.generate_content(prompt)
            # Parse numbered list
            lines = response.text.strip().split('\n')
            steps = [line.strip() for line in lines if line.strip() and line.strip()[0].isdigit()]
            return steps if steps else [response.text]
        except Exception as e:
            self.logger.error(f"Failed to get recommendations: {e}")
            return [f"Unable to generate recommendations: {e}"]
    
    def predict_attack_scenarios(
        self,
        vulnerabilities: list[dict],
        services: list[dict] = None
    ) -> list[str]:
        """
        Predict potential attack scenarios based on vulnerabilities.
        
        Args:
            vulnerabilities: List of CVE dictionaries
            services: Optional list of detected services
        
        Returns:
            List of attack scenario descriptions
        """
        if not vulnerabilities:
            return ["No attack scenarios identified - no vulnerabilities detected."]
        
        services_info = ""
        if services:
            services_info = "\nDetected Services:\n" + "\n".join(
                f"- Port {s.get('port')}: {s.get('service_name', 'unknown')} {s.get('version', '')}"
                for s in services[:10]
            )
        
        prompt = f"""You are a penetration testing expert. Based on these vulnerabilities and services, predict the most likely attack scenarios an attacker might use.

Vulnerabilities:
{self._format_vulns_for_prompt(vulnerabilities[:10])}
{services_info}

List 3-5 realistic attack scenarios, each on a new line starting with a dash (-).
For each scenario, briefly describe:
- The attack vector
- The potential impact
- The likelihood (High/Medium/Low)"""

        try:
            response = self.model.generate_content(prompt)
            lines = response.text.strip().split('\n')
            scenarios = [line.strip().lstrip('-').strip() for line in lines if line.strip().startswith('-')]
            return scenarios if scenarios else [response.text]
        except Exception as e:
            self.logger.error(f"Failed to predict attack scenarios: {e}")
            return [f"Unable to predict scenarios: {e}"]
    
    def _build_analysis_prompt(
        self,
        vulnerabilities: list[dict],
        host_info: Optional[dict],
        context: str
    ) -> str:
        """Build the analysis prompt for Gemini."""
        
        host_str = ""
        if host_info:
            host_str = f"""
Target Information:
- IP: {host_info.get('ip_address', 'Unknown')}
- Hostname: {host_info.get('hostname', 'Unknown')}
- Services: {len(host_info.get('services', []))} detected
"""
        
        return f"""You are a senior cybersecurity analyst. Analyze these vulnerability scan results and provide a comprehensive threat assessment.

{host_str}
{f'Context: {context}' if context else ''}

Vulnerabilities Found:
{self._format_vulns_for_prompt(vulnerabilities[:20])}

Provide your analysis in this exact format:

THREAT_SUMMARY:
[2-3 sentence overview of the threat landscape]

RISK_ASSESSMENT:
[Overall risk level: CRITICAL/HIGH/MEDIUM/LOW with justification]

ATTACK_SCENARIOS:
- [Scenario 1]
- [Scenario 2]
- [Scenario 3]

REMEDIATION_STEPS:
1. [Most urgent action]
2. [Second priority]
3. [Third priority]
4. [Additional steps]

PRIORITY_RANKING:
[Which vulnerabilities to fix first and why]

EXECUTIVE_SUMMARY:
[1 paragraph summary for non-technical stakeholders]"""
    
    def _format_vulns_for_prompt(self, vulnerabilities: list[dict]) -> str:
        """Format vulnerabilities for AI prompt."""
        if not vulnerabilities:
            return "None"
        
        lines = []
        for v in vulnerabilities:
            cve_id = v.get("cve_id", "Unknown")
            severity = v.get("severity", "Unknown")
            score = v.get("base_score", 0)
            desc = v.get("description", "No description")[:150]
            lines.append(f"- {cve_id} ({severity}, CVSS: {score}): {desc}...")
        
        return "\n".join(lines)
    
    def _parse_analysis_response(self, response_text: str) -> AIAnalysisResult:
        """Parse the structured AI response."""
        result = AIAnalysisResult()
        
        sections = {
            "THREAT_SUMMARY:": "threat_summary",
            "RISK_ASSESSMENT:": "risk_assessment",
            "PRIORITY_RANKING:": "priority_ranking",
            "EXECUTIVE_SUMMARY:": "executive_summary"
        }
        
        lines = response_text.split('\n')
        current_section = None
        current_content = []
        
        for line in lines:
            line_upper = line.strip().upper()
            
            # Check for section headers
            matched = False
            for header, attr in sections.items():
                if line_upper.startswith(header.rstrip(':')):
                    if current_section and current_content:
                        setattr(result, current_section, '\n'.join(current_content).strip())
                    current_section = attr
                    current_content = []
                    matched = True
                    break
            
            if matched:
                continue
            
            # Handle list sections
            if line_upper.startswith("ATTACK_SCENARIOS"):
                if current_section and current_content:
                    setattr(result, current_section, '\n'.join(current_content).strip())
                current_section = "attack_scenarios_list"
                current_content = []
                continue
            
            if line_upper.startswith("REMEDIATION_STEPS"):
                if current_section and current_content:
                    if current_section == "attack_scenarios_list":
                        result.attack_scenarios = [c.lstrip('-').strip() for c in current_content if c.strip()]
                    else:
                        setattr(result, current_section, '\n'.join(current_content).strip())
                current_section = "remediation_steps_list"
                current_content = []
                continue
            
            # Add content to current section
            if current_section and line.strip():
                current_content.append(line.strip())
        
        # Save final section
        if current_section and current_content:
            if current_section == "attack_scenarios_list":
                result.attack_scenarios = [c.lstrip('-').strip() for c in current_content if c.strip()]
            elif current_section == "remediation_steps_list":
                result.remediation_steps = [c.lstrip('0123456789.').strip() for c in current_content if c.strip()]
            else:
                setattr(result, current_section, '\n'.join(current_content).strip())
        
        return result
