"""Live scanning endpoint - runs actual nmap scans on the server."""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Optional
import asyncio
import os
import sys
import uuid
import json
from datetime import datetime
from pathlib import Path

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

router = APIRouter()

# Scan storage directory
SCANS_DIR = Path(__file__).parent.parent.parent / "data" / "scans"
MAX_STORED_SCANS = 50


class LiveScanRequest(BaseModel):
    """Request to start a live scan."""
    target: str
    max_cves: int = 20
    skip_ai: bool = False


class ScanStatus(BaseModel):
    """Status of ongoing scan."""
    scan_id: str
    status: str  # pending, scanning, vuln_check, analyzing, complete, failed
    message: str
    progress: int  # 0-100
    results: Optional[dict] = None


# In-memory scan tracking
_active_scans: dict[str, ScanStatus] = {}


def _ensure_scans_dir():
    """Create scans directory if it doesn't exist."""
    SCANS_DIR.mkdir(parents=True, exist_ok=True)


def _save_scan(scan_id: str, scan_status: ScanStatus):
    """Save completed scan to disk."""
    _ensure_scans_dir()
    scan_file = SCANS_DIR / f"{scan_id}.json"
    
    data = {
        "scan_id": scan_status.scan_id,
        "status": scan_status.status,
        "message": scan_status.message,
        "progress": scan_status.progress,
        "results": scan_status.results,
        "saved_at": datetime.now().isoformat()
    }
    
    with open(scan_file, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, default=str)
    
    # Enforce scan limit
    _cleanup_old_scans()


def _cleanup_old_scans():
    """Remove old scans if over limit."""
    if not SCANS_DIR.exists():
        return
    
    scan_files = sorted(SCANS_DIR.glob("*.json"), key=lambda f: f.stat().st_mtime, reverse=True)
    
    # Delete oldest scans if over limit
    for old_file in scan_files[MAX_STORED_SCANS:]:
        old_file.unlink()


def _load_all_scans():
    """Load all saved scans from disk."""
    if not SCANS_DIR.exists():
        return
    
    for scan_file in SCANS_DIR.glob("*.json"):
        try:
            with open(scan_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            scan_status = ScanStatus(
                scan_id=data["scan_id"],
                status=data["status"],
                message=data["message"],
                progress=data["progress"],
                results=data.get("results")
            )
            _active_scans[data["scan_id"]] = scan_status
        except Exception as e:
            print(f"Failed to load scan {scan_file}: {e}")


def _delete_scan(scan_id: str) -> bool:
    """Delete a scan from disk and memory."""
    # Remove from memory
    if scan_id in _active_scans:
        del _active_scans[scan_id]
    
    # Remove from disk
    scan_file = SCANS_DIR / f"{scan_id}.json"
    if scan_file.exists():
        scan_file.unlink()
        return True
    return False


# Load existing scans on module import
_load_all_scans()


@router.post("/live", response_model=ScanStatus)
async def start_live_scan(request: LiveScanRequest, background_tasks: BackgroundTasks):
    """
    Start a live network scan against a target.
    
    This will run nmap service detection and CVE lookup on the server.
    Requires nmap to be installed on the server.
    """
    # Validate target (basic security check)
    target = request.target.strip()
    if not target:
        raise HTTPException(status_code=400, detail="Target is required")
    
    # Block dangerous targets
    blocked = ['localhost', '127.0.0.1', '0.0.0.0', '::1']
    if target.lower() in blocked:
        raise HTTPException(status_code=400, detail="Cannot scan localhost")
    
    # Generate scan ID
    scan_id = f"live_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
    
    # Initialize scan status
    _active_scans[scan_id] = ScanStatus(
        scan_id=scan_id,
        status="pending",
        message=f"Starting scan of {target}...",
        progress=0
    )
    
    # Run scan in background
    background_tasks.add_task(run_scan_task, scan_id, target, request.max_cves, request.skip_ai)
    
    return _active_scans[scan_id]


@router.get("/live/{scan_id}", response_model=ScanStatus)
async def get_scan_status(scan_id: str):
    """Get the status of an ongoing or completed scan."""
    if scan_id not in _active_scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _active_scans[scan_id]


@router.get("/live")
async def list_scans():
    """List all scans, sorted by newest first."""
    # Always reload from disk to ensure consistency (handles multi-worker environments)
    global _active_scans
    
    # Clear and reload from disk
    _active_scans.clear()
    _load_all_scans()
    
    # Sort by scan_id descending (scan_id contains timestamp: live_YYYYMMDD_HHMMSS_xxx)
    sorted_scans = sorted(_active_scans.values(), key=lambda s: s.scan_id, reverse=True)
    return {
        "scans": [
            {
                "scan_id": s.scan_id,
                "status": s.status,
                "message": s.message,
                "progress": s.progress
            }
            for s in sorted_scans
        ]
    }




async def run_scan_task(scan_id: str, target: str, max_cves: int, skip_ai: bool):
    """Background task to run the full scan."""
    try:
        # Update status
        _active_scans[scan_id].status = "scanning"
        _active_scans[scan_id].message = f"Detecting services on {target}..."
        _active_scans[scan_id].progress = 10
        
        # Step 1: Service Detection
        from src.scanner import ServiceDetector
        
        detector = ServiceDetector()
        hosts = await asyncio.to_thread(
            detector.detect_services,
            target=target,
            os_detection=False,
            intensity=7,
            show_progress=False
        )
        
        if not hosts:
            _active_scans[scan_id].status = "failed"
            _active_scans[scan_id].message = f"No hosts found. Target may be offline or firewalled."
            _active_scans[scan_id].progress = 100
            return
        
        total_services = sum(len(h.services) for h in hosts)
        if total_services == 0:
            _active_scans[scan_id].status = "failed"
            _active_scans[scan_id].message = f"Host responded but no open services found."
            _active_scans[scan_id].progress = 100
            return
        
        _active_scans[scan_id].progress = 30
        _active_scans[scan_id].message = f"Found {total_services} services. Checking CVEs..."
        
        # Step 2: Vulnerability Scan
        _active_scans[scan_id].status = "vuln_check"
        
        from src.vulnerability import VulnerabilityScanner
        
        vuln_scanner = VulnerabilityScanner()
        all_reports = []
        
        for host in hosts:
            report = await asyncio.to_thread(
                vuln_scanner.scan_host,
                host,
                max_cves_per_cpe=max_cves,
                show_progress=False
            )
            all_reports.append(report)
        
        vuln_scanner.close()
        
        total_cves = sum(r.total_cves for r in all_reports)
        _active_scans[scan_id].progress = 60
        _active_scans[scan_id].message = f"Found {total_cves} CVEs. "
        
        # Step 3: AI Analysis (optional)
        ai_data = {}
        recommendations = []
        
        if not skip_ai:
            _active_scans[scan_id].status = "analyzing"
            _active_scans[scan_id].message += "Running AI analysis..."
            _active_scans[scan_id].progress = 70
            
            # Load dotenv here in case it wasn't loaded in main
            from dotenv import load_dotenv
            load_dotenv()
            
            gemini_key = os.environ.get("GEMINI_API_KEY")
            print(f"GEMINI_API_KEY found: {'Yes' if gemini_key else 'No'}")
            
            if gemini_key:
                try:
                    from src.intelligence import ThreatAnalyzer
                    
                    vuln_data = [r.to_dict() for r in all_reports]
                    analyzer = ThreatAnalyzer(gemini_api_key=gemini_key)
                    assessment = await asyncio.to_thread(
                        analyzer.analyze,
                        {"hosts": vuln_data},
                        True
                    )
                    ai_data = assessment.to_dict()
                    print(f"AI analysis complete: threat_summary length = {len(ai_data.get('ai_threat_summary', ''))}")
                    
                    # Generate recommendations from AI remediation steps
                    if assessment.ai_remediation_steps:
                        recommendations = assessment.ai_remediation_steps[:10]
                    
                    # Add priority actions as recommendations if none from AI
                    if not recommendations:
                        recommendations = analyzer.get_priority_actions(assessment)
                        
                except Exception as e:
                    print(f"AI analysis failed: {e}")
                    import traceback
                    traceback.print_exc()
            else:
                print("No GEMINI_API_KEY found in environment. AI analysis skipped.")
                # Generate rule-based recommendations
                if total_cves > 0:
                    if critical_count > 0:
                        recommendations.append(f"🔴 CRITICAL: Patch {critical_count} critical vulnerabilities immediately")
                    if high_count > 0:
                        recommendations.append(f"🟠 URGENT: Address {high_count} high severity vulnerabilities within 1-2 weeks")
                    if medium_count > 0:
                        recommendations.append(f"🟡 PLANNED: Schedule fixes for {medium_count} medium severity issues")
        
        _active_scans[scan_id].progress = 90
        
        # Calculate severity counts from all CVEs
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        
        for report in all_reports:
            for vuln_svc in report.vulnerable_services:
                for cve in vuln_svc.cves:
                    # cve.severity is a Severity enum, use .name to get string
                    severity_name = cve.severity.name if hasattr(cve.severity, 'name') else str(cve.severity)
                    if severity_name == 'CRITICAL':
                        critical_count += 1
                    elif severity_name == 'HIGH':
                        high_count += 1
                    elif severity_name == 'MEDIUM':
                        medium_count += 1
                    elif severity_name == 'LOW':
                        low_count += 1
        
        # Compile results
        results = {
            "target": target,
            "scanned_at": datetime.now().isoformat(),
            "hosts": [h.to_dict() for h in hosts],
            "vulnerabilities": [r.to_dict() for r in all_reports],
            "summary": {
                "hosts_count": len(hosts),
                "services_count": total_services,
                "total_cves": total_cves,
                "critical_count": critical_count,
                "high_count": high_count,
                "medium_count": medium_count,
                "low_count": low_count,
            },
            "ai_analysis": ai_data if ai_data else None,
            "recommendations": recommendations
        }
        
        _active_scans[scan_id].status = "complete"
        _active_scans[scan_id].message = f"Scan complete! Found {total_cves} vulnerabilities."
        _active_scans[scan_id].progress = 100
        _active_scans[scan_id].results = results
        
        # Save completed scan to disk
        _save_scan(scan_id, _active_scans[scan_id])
        
    except Exception as e:
        _active_scans[scan_id].status = "failed"
        _active_scans[scan_id].message = f"Scan failed: {str(e)}"
        _active_scans[scan_id].progress = 100
        print(f"Scan error: {e}")


@router.delete("/live/{scan_id}")
async def delete_scan(scan_id: str):
    """Delete a scan from history."""
    if _delete_scan(scan_id):
        return {"message": f"Scan {scan_id} deleted successfully"}
    raise HTTPException(status_code=404, detail="Scan not found")


@router.delete("/live")
async def delete_all_scans():
    """Delete all scans from history."""
    global _active_scans
    
    # Delete all scan files
    if SCANS_DIR.exists():
        for scan_file in SCANS_DIR.glob("*.json"):
            scan_file.unlink()
    
    # Clear memory
    count = len(_active_scans)
    _active_scans.clear()
    
    return {"message": f"Deleted {count} scans"}
