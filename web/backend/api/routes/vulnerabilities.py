"""Vulnerability scanning endpoints."""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Optional
import os
import sys

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

router = APIRouter()


class VulnScanRequest(BaseModel):
    """Request for vulnerability scan."""
    scan_id: str
    max_cves_per_service: int = 20


class VulnScanResponse(BaseModel):
    """Response for vulnerability scan."""
    success: bool
    message: str
    total_cves: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    results: list


# In-memory results storage
_vuln_results: dict = {}


@router.post("/scan", response_model=VulnScanResponse)
async def scan_vulnerabilities(request: VulnScanRequest):
    """
    Scan uploaded services for known vulnerabilities using NVD API.
    
    Requires a valid scan_id from a previously uploaded scan.
    """
    from api.routes.scan import _scans
    
    if request.scan_id not in _scans:
        raise HTTPException(status_code=404, detail="Scan not found. Upload a scan first.")
    
    scan_data = _scans[request.scan_id]["data"]
    
    try:
        from src.vulnerability import VulnerabilityScanner
        
        scanner = VulnerabilityScanner()
        all_results = []
        
        # Convert scan data to HostInfo objects
        from src.scanner import HostInfo, ServiceInfo
        
        for host_data in scan_data:
            host = HostInfo(
                ip=host_data.get("ip", host_data.get("host", "unknown")),
                hostname=host_data.get("hostname", ""),
                status="up"
            )
            
            # Add services
            services = host_data.get("services", host_data.get("vulnerable_services", []))
            for svc in services:
                host.services.append(ServiceInfo(
                    port=svc.get("port", 0),
                    protocol=svc.get("protocol", "tcp"),
                    state="open",
                    service_name=svc.get("service", svc.get("service_name", "")),
                    product=svc.get("product", ""),
                    version=svc.get("version", ""),
                    cpe=svc.get("cpe", "")
                ))
            
            # Scan host
            report = scanner.scan_host(
                host,
                max_cves_per_cpe=request.max_cves_per_service,
                show_progress=False
            )
            all_results.append(report.to_dict())
        
        scanner.close()
        
        # Calculate totals
        total_cves = sum(r.get("total_cves", 0) for r in all_results)
        critical = sum(r.get("critical_count", 0) for r in all_results)
        high = sum(r.get("high_count", 0) for r in all_results)
        medium = sum(r.get("medium_count", 0) for r in all_results)
        low = sum(r.get("low_count", 0) for r in all_results)
        
        # Store results
        _vuln_results[request.scan_id] = all_results
        
        return VulnScanResponse(
            success=True,
            message=f"Found {total_cves} CVEs across {len(all_results)} host(s)",
            total_cves=total_cves,
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            low_count=low,
            results=all_results
        )
        
    except ImportError as e:
        raise HTTPException(status_code=500, detail=f"Module import error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan error: {str(e)}")


@router.get("/{scan_id}")
async def get_vulnerabilities(scan_id: str):
    """Get vulnerability results for a scan."""
    if scan_id not in _vuln_results:
        raise HTTPException(status_code=404, detail="No vulnerability results found for this scan")
    return {"scan_id": scan_id, "results": _vuln_results[scan_id]}


@router.get("/{scan_id}/summary")
async def get_vulnerability_summary(scan_id: str):
    """Get summary of vulnerabilities for a scan."""
    if scan_id not in _vuln_results:
        raise HTTPException(status_code=404, detail="No vulnerability results found")
    
    results = _vuln_results[scan_id]
    
    return {
        "scan_id": scan_id,
        "total_cves": sum(r.get("total_cves", 0) for r in results),
        "by_severity": {
            "critical": sum(r.get("critical_count", 0) for r in results),
            "high": sum(r.get("high_count", 0) for r in results),
            "medium": sum(r.get("medium_count", 0) for r in results),
            "low": sum(r.get("low_count", 0) for r in results),
        },
        "hosts_scanned": len(results)
    }
