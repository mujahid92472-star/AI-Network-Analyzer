"""
AI Network Analyzer - FastAPI Backend

REST API for vulnerability scanning and AI threat analysis.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Import routers (will create these next)
from api.routes import health, vulnerabilities, analysis, scan, live_scan, reports

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler for startup/shutdown."""
    # Startup
    print("🚀 AI Network Analyzer API starting...")
    yield
    # Shutdown
    print("👋 API shutting down...")


app = FastAPI(
    title="AI Network Analyzer API",
    description="REST API for network vulnerability scanning and AI-powered threat analysis",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware for frontend access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(health.router, prefix="/api", tags=["Health"])
app.include_router(scan.router, prefix="/api/scan", tags=["Scan"])
app.include_router(live_scan.router, prefix="/api/live", tags=["Live Scan"])
app.include_router(vulnerabilities.router, prefix="/api/vulnerabilities", tags=["Vulnerabilities"])
app.include_router(analysis.router, prefix="/api/analysis", tags=["AI Analysis"])
app.include_router(reports.router, prefix="/api/reports", tags=["Reports"])


@app.get("/")
async def root():
    """Root endpoint with API info."""
    return {
        "name": "AI Network Analyzer API",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/api/health"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=True)
