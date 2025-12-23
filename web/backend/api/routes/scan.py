"""Scan upload and processing endpoints."""

from fastapi import APIRouter, UploadFile, File, HTTPException
from pydantic import BaseModel
from typing import Optional
import json

router = APIRouter()


class ScanUploadResponse(BaseModel):
    """Response for scan upload."""
    success: bool
    message: str
    hosts_count: int
    services_count: int
    scan_id: str


class ManualScanRequest(BaseModel):
    """Request for manual scan data entry."""
    target: str
    services: list[dict]


# In-memory storage (replace with database in production)
_scans: dict = {}


@router.post("/upload", response_model=ScanUploadResponse)
async def upload_scan(file: UploadFile = File(...)):
    """
    Upload a scan results JSON file (e.g., from Nmap).
    
    The JSON should contain host and service information.
    """
    if not file.filename.endswith('.json'):
        raise HTTPException(status_code=400, detail="Only JSON files are accepted")
    
    try:
        content = await file.read()
        scan_data = json.loads(content.decode('utf-8'))
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON file")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error reading file: {str(e)}")
    
    # Generate scan ID
    import uuid
    from datetime import datetime
    scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
    
    # Parse scan data
    hosts = scan_data if isinstance(scan_data, list) else scan_data.get("hosts", [scan_data])
    services_count = sum(len(h.get("services", h.get("vulnerable_services", []))) for h in hosts)
    
    # Store scan
    _scans[scan_id] = {
        "id": scan_id,
        "uploaded_at": datetime.now().isoformat(),
        "filename": file.filename,
        "data": hosts
    }
    
    return ScanUploadResponse(
        success=True,
        message=f"Scan uploaded successfully",
        hosts_count=len(hosts),
        services_count=services_count,
        scan_id=scan_id
    )


@router.get("/{scan_id}")
async def get_scan(scan_id: str):
    """Get scan data by ID."""
    if scan_id not in _scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _scans[scan_id]


@router.get("/")
async def list_scans():
    """List all uploaded scans."""
    return {
        "scans": [
            {
                "id": s["id"],
                "uploaded_at": s["uploaded_at"],
                "filename": s["filename"],
                "hosts_count": len(s["data"])
            }
            for s in _scans.values()
        ]
    }
