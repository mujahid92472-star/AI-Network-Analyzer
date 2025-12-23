"""Report generation endpoints - Generate and download reports."""

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from typing import Optional
import os
import sys
import json
import tempfile
from datetime import datetime
from pathlib import Path

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

router = APIRouter()

# Import scan storage from live_scan
from api.routes.live_scan import _active_scans


class ReportRequest(BaseModel):
    """Request to generate a report."""
    scan_id: str
    format: str = "json"  # json, html, pdf


@router.post("/generate")
async def generate_report(request: ReportRequest):
    """
    Generate a report in the specified format.
    
    Formats: json, html, pdf
    """
    if request.scan_id not in _active_scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan = _active_scans[request.scan_id]
    if scan.status != "complete":
        raise HTTPException(status_code=400, detail="Scan not complete")
    
    if not scan.results:
        raise HTTPException(status_code=400, detail="No results available")
    
    results = scan.results
    format_type = request.format.lower()
    
    # Create temp directory for reports
    temp_dir = Path(tempfile.gettempdir()) / "network_analyzer_reports"
    temp_dir.mkdir(exist_ok=True)
    
    try:
        if format_type == "json":
            # JSON report
            filename = f"scan_{request.scan_id}.json"
            filepath = temp_dir / filename
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, default=str)
            
            return FileResponse(
                path=filepath,
                filename=filename,
                media_type="application/json"
            )
        
        elif format_type == "html":
            # HTML report using our HTMLReporter
            from src.reporting import HTMLReporter
            
            filename = f"report_{request.scan_id}.html"
            filepath = temp_dir / filename
            
            # Prepare data for reporter - handle None values
            ai_analysis = results.get("ai_analysis") or {}
            recommendations = results.get("recommendations", [])
            
            # Debug logging
            print(f"HTML Report: ai_analysis keys = {list(ai_analysis.keys()) if ai_analysis else 'None'}")
            print(f"HTML Report: recommendations count = {len(recommendations)}")
            
            report_data = {
                "hosts": results.get("vulnerabilities", []),
                "ai_threat_summary": ai_analysis.get("ai_threat_summary", "") if ai_analysis else "",
                "ai_executive_summary": ai_analysis.get("ai_executive_summary", "") if ai_analysis else "",
                "ai_attack_scenarios": ai_analysis.get("ai_attack_scenarios", []) if ai_analysis else [],
                "ai_remediation_steps": ai_analysis.get("ai_remediation_steps", []) if ai_analysis else [],
                "recommendations": recommendations,
            }
            
            try:
                reporter = HTMLReporter()
                reporter.generate_from_scan_results(report_data, filepath)
            except Exception as e:
                print(f"HTML generation error: {e}")
                import traceback
                traceback.print_exc()
                raise HTTPException(status_code=500, detail=f"HTML generation failed: {str(e)}")
            
            return FileResponse(
                path=filepath,
                filename=filename,
                media_type="text/html"
            )
        
        elif format_type == "pdf":
            # PDF report using our PDFReporter
            from src.reporting import PDFReporter
            
            filename = f"report_{request.scan_id}.pdf"
            filepath = temp_dir / filename
            
            # Prepare data for reporter - handle None values
            ai_analysis = results.get("ai_analysis") or {}
            report_data = {
                "hosts": results.get("vulnerabilities", []),
                "ai_threat_summary": ai_analysis.get("ai_threat_summary", "") if ai_analysis else "",
                "ai_executive_summary": ai_analysis.get("ai_executive_summary", "") if ai_analysis else "",
                "ai_attack_scenarios": ai_analysis.get("ai_attack_scenarios", []) if ai_analysis else [],
                "ai_remediation_steps": ai_analysis.get("ai_remediation_steps", []) if ai_analysis else [],
            }
            
            try:
                reporter = PDFReporter()
                success = reporter.generate_from_scan_results(report_data, filepath)
            except Exception as e:
                print(f"PDF generation error: {e}")
                import traceback
                traceback.print_exc()
                raise HTTPException(status_code=500, detail=f"PDF generation failed: {str(e)}")
            
            if not success:
                raise HTTPException(status_code=500, detail="PDF generation failed - WeasyPrint may not be installed")
            
            return FileResponse(
                path=filepath,
                filename=filename,
                media_type="application/pdf"
            )
        
        else:
            raise HTTPException(status_code=400, detail=f"Unknown format: {format_type}")
    
    except ImportError as e:
        raise HTTPException(status_code=500, detail=f"Reporter not available: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report generation failed: {e}")


@router.get("/download/{scan_id}/{format}")
async def download_report(scan_id: str, format: str):
    """Download a report directly via GET request."""
    return await generate_report(ReportRequest(scan_id=scan_id, format=format))
