"""AI threat analysis endpoints."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
import os
import sys

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

router = APIRouter()


class AnalysisRequest(BaseModel):
    """Request for AI threat analysis."""
    scan_id: str
    use_ai: bool = True


class AnalysisResponse(BaseModel):
    """Response with AI analysis results."""
    success: bool
    threat_level: str
    risk_score: float
    total_vulnerabilities: int
    threat_summary: Optional[str] = None
    executive_summary: Optional[str] = None
    attack_scenarios: list[str] = []
    remediation_steps: list[str] = []


# Store analysis results
_analysis_results: dict = {}


@router.post("/analyze", response_model=AnalysisResponse)
async def analyze_threats(request: AnalysisRequest):
    """
    Perform AI-powered threat analysis on vulnerability scan results.
    
    Requires GEMINI_API_KEY environment variable for AI features.
    """
    from api.routes.vulnerabilities import _vuln_results
    
    if request.scan_id not in _vuln_results:
        raise HTTPException(
            status_code=404, 
            detail="Vulnerability scan not found. Run a vulnerability scan first."
        )
    
    vuln_data = _vuln_results[request.scan_id]
    
    try:
        from src.intelligence import ThreatAnalyzer
        
        gemini_key = os.environ.get("GEMINI_API_KEY")
        
        if request.use_ai and not gemini_key:
            raise HTTPException(
                status_code=400, 
                detail="GEMINI_API_KEY not configured. Set it in environment or use use_ai=false"
            )
        
        analyzer = ThreatAnalyzer(gemini_api_key=gemini_key if request.use_ai else None)
        
        # Run analysis
        assessment = analyzer.analyze(
            {"hosts": vuln_data},
            use_ai=request.use_ai
        )
        
        result = assessment.to_dict()
        
        # Store results
        _analysis_results[request.scan_id] = result
        
        return AnalysisResponse(
            success=True,
            threat_level=result.get("threat_level", "UNKNOWN"),
            risk_score=result.get("risk_score", 0.0),
            total_vulnerabilities=result.get("total_vulnerabilities", 0),
            threat_summary=result.get("ai_threat_summary"),
            executive_summary=result.get("ai_executive_summary"),
            attack_scenarios=result.get("ai_attack_scenarios", []),
            remediation_steps=result.get("ai_remediation_steps", [])
        )
        
    except ImportError as e:
        raise HTTPException(status_code=500, detail=f"Module import error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis error: {str(e)}")


@router.get("/{scan_id}")
async def get_analysis(scan_id: str):
    """Get analysis results for a scan."""
    if scan_id not in _analysis_results:
        raise HTTPException(status_code=404, detail="Analysis not found for this scan")
    return {"scan_id": scan_id, "analysis": _analysis_results[scan_id]}
