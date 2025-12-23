"""
Intelligence Module - AI-powered threat intelligence.

This module provides AI-powered security analysis:
- Gemini API integration for threat analysis
- Natural language threat summaries
- Remediation recommendations
- Attack scenario predictions
- Exploit intelligence checking
"""

from .gemini_client import (
    GeminiClient,
    AIAnalysisResult
)

from .threat_analyzer import (
    ThreatAnalyzer,
    ThreatAssessment,
    ThreatLevel
)

from .exploit_checker import (
    ExploitChecker,
    ExploitInfo
)

__all__ = [
    "GeminiClient",
    "AIAnalysisResult",
    "ThreatAnalyzer",
    "ThreatAssessment",
    "ThreatLevel",
    "ExploitChecker",
    "ExploitInfo"
]
