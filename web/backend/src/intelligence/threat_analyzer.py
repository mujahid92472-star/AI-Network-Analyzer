"""
Threat Analyzer - AI-powered security threat analysis.

Combines vulnerability data with AI intelligence to provide:
- Comprehensive threat assessments
- Prioritized remediation guidance
- Attack scenario predictions
- Executive-level summaries
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from enum import Enum

from src.core import get_logger


class ThreatLevel(Enum):
    """Threat level classification."""
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    MINIMAL = 1
    
    @classmethod
    def from_score(cls, score: float) -> "ThreatLevel":
        """Convert numeric score to threat level."""
        if score >= 80:
            return cls.CRITICAL
        elif score >= 60:
            return cls.HIGH
        elif score >= 40:
            return cls.MEDIUM
        elif score >= 20:
            return cls.LOW
        else:
            return cls.MINIMAL


@dataclass
class ThreatAssessment:
    """Complete threat assessment for a target."""
    
    # Target info
    target: str = ""
    assessed_at: datetime = field(default_factory=datetime.now)
    
    # Risk metrics
    overall_risk_score: float = 0.0
    threat_level: ThreatLevel = ThreatLevel.MINIMAL
    
    # Vulnerability counts
    total_vulnerabilities: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    
    # Exploit info
    exploitable_count: int = 0
    exploit_available: list[dict] = field(default_factory=list)
    
    # AI analysis
    ai_threat_summary: str = ""
    ai_risk_assessment: str = ""
    ai_attack_scenarios: list[str] = field(default_factory=list)
    ai_remediation_steps: list[str] = field(default_factory=list)
    ai_executive_summary: str = ""
    
    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "assessed_at": self.assessed_at.isoformat(),
            "overall_risk_score": self.overall_risk_score,
            "threat_level": self.threat_level.name,
            "total_vulnerabilities": self.total_vulnerabilities,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "exploitable_count": self.exploitable_count,
            "exploit_available": self.exploit_available,
            "ai_threat_summary": self.ai_threat_summary,
            "ai_risk_assessment": self.ai_risk_assessment,
            "ai_attack_scenarios": self.ai_attack_scenarios,
            "ai_remediation_steps": self.ai_remediation_steps,
            "ai_executive_summary": self.ai_executive_summary
        }


class ThreatAnalyzer:
    """
    AI-powered threat analyzer.
    
    Combines vulnerability scan results with AI analysis to provide
    comprehensive threat assessments and remediation guidance.
    """
    
    def __init__(self, gemini_api_key: Optional[str] = None):
        """
        Initialize the threat analyzer.
        
        Args:
            gemini_api_key: Optional Gemini API key
        """
        self.logger = get_logger("threat_analyzer")
        self.gemini_client = None
        
        # Try to initialize Gemini if key provided
        if gemini_api_key:
            try:
                from src.intelligence.gemini_client import GeminiClient
                self.gemini_client = GeminiClient(api_key=gemini_api_key)
                self.logger.info("Gemini AI client initialized")
            except Exception as e:
                self.logger.warning(f"Failed to initialize Gemini: {e}")
    
    def analyze(
        self,
        scan_results: dict,
        use_ai: bool = True
    ) -> ThreatAssessment:
        """
        Perform comprehensive threat analysis.
        
        Args:
            scan_results: Vulnerability scan results
            use_ai: Whether to use AI for analysis
        
        Returns:
            ThreatAssessment object
        """
        assessment = ThreatAssessment()
        
        # Extract hosts
        hosts = scan_results.get("hosts", [])
        if isinstance(scan_results, list):
            hosts = scan_results
        
        if hosts:
            assessment.target = hosts[0].get("ip_address", "Unknown")
        
        # Aggregate vulnerabilities
        all_vulns = []
        for host in hosts:
            # Handle direct vulnerabilities key
            vulns = host.get("vulnerabilities", [])
            all_vulns.extend(vulns)
            
            # Also handle vulnerable_services format (from vuln_scan)
            for vs in host.get("vulnerable_services", []):
                vs_cves = vs.get("cves", [])
                all_vulns.extend(vs_cves)
            
            # Count by severity (from all_vulns)
        for v in all_vulns:
            assessment.total_vulnerabilities += 1
            severity = v.get("severity", "").upper()
            if severity == "CRITICAL":
                assessment.critical_count += 1
            elif severity == "HIGH":
                assessment.high_count += 1
            elif severity == "MEDIUM":
                assessment.medium_count += 1
            elif severity == "LOW":
                assessment.low_count += 1
        
        # Calculate risk score
        assessment.overall_risk_score = self._calculate_risk_score(assessment)
        assessment.threat_level = ThreatLevel.from_score(assessment.overall_risk_score)
        
        # AI analysis
        if use_ai and self.gemini_client and all_vulns:
            self.logger.info("Running AI threat analysis...")
            try:
                # Get AI analysis
                ai_result = self.gemini_client.analyze_vulnerabilities(
                    all_vulns,
                    hosts[0] if hosts else None
                )
                
                assessment.ai_threat_summary = ai_result.threat_summary
                assessment.ai_risk_assessment = ai_result.risk_assessment
                assessment.ai_attack_scenarios = ai_result.attack_scenarios
                assessment.ai_remediation_steps = ai_result.remediation_steps
                assessment.ai_executive_summary = ai_result.executive_summary
                
            except Exception as e:
                self.logger.error(f"AI analysis failed: {e}")
                assessment.ai_threat_summary = f"AI analysis unavailable: {e}"
        elif not use_ai:
            self.logger.info("AI analysis disabled, using rule-based only")
            assessment.ai_threat_summary = self._generate_rule_based_summary(assessment)
        elif not self.gemini_client:
            self.logger.warning("Gemini client not configured")
            assessment.ai_threat_summary = self._generate_rule_based_summary(assessment)
        
        return assessment
    
    def _calculate_risk_score(self, assessment: ThreatAssessment) -> float:
        """Calculate composite risk score (0-100)."""
        if assessment.total_vulnerabilities == 0:
            return 0.0
        
        score = (
            assessment.critical_count * 40 +
            assessment.high_count * 20 +
            assessment.medium_count * 10 +
            assessment.low_count * 5
        )
        
        # Add bonus for exploitable vulns
        score += assessment.exploitable_count * 10
        
        return min(100.0, score)
    
    def _generate_rule_based_summary(self, assessment: ThreatAssessment) -> str:
        """Generate summary without AI."""
        level = assessment.threat_level.name
        
        if assessment.critical_count > 0:
            return (
                f"CRITICAL: Found {assessment.critical_count} critical vulnerabilities "
                f"requiring immediate attention. Overall risk score: {assessment.overall_risk_score:.1f}/100."
            )
        elif assessment.high_count > 0:
            return (
                f"HIGH RISK: Found {assessment.high_count} high severity vulnerabilities. "
                f"Consider prioritizing remediation. Risk score: {assessment.overall_risk_score:.1f}/100."
            )
        elif assessment.medium_count > 0:
            return (
                f"MODERATE RISK: Found {assessment.medium_count} medium severity issues. "
                f"Plan remediation in next maintenance window. Risk score: {assessment.overall_risk_score:.1f}/100."
            )
        else:
            return (
                f"LOW RISK: {assessment.total_vulnerabilities} low severity findings. "
                f"Continue regular monitoring. Risk score: {assessment.overall_risk_score:.1f}/100."
            )
    
    def get_priority_actions(self, assessment: ThreatAssessment) -> list[str]:
        """Get prioritized action items."""
        actions = []
        
        if assessment.critical_count > 0:
            actions.append(
                f"🔴 IMMEDIATE: Patch {assessment.critical_count} critical vulnerabilities within 24-48 hours"
            )
        
        if assessment.high_count > 0:
            actions.append(
                f"🟠 URGENT: Address {assessment.high_count} high severity issues within 1-2 weeks"
            )
        
        if assessment.medium_count > 0:
            actions.append(
                f"🟡 PLANNED: Schedule {assessment.medium_count} medium severity fixes for next maintenance"
            )
        
        if assessment.exploitable_count > 0:
            actions.append(
                f"⚠️ EXPLOITABLE: {assessment.exploitable_count} vulnerabilities have known exploits"
            )
        
        if not actions:
            actions.append("✅ No critical actions required - continue regular monitoring")
        
        return actions
