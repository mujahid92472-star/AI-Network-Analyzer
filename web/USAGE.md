# AI Network Analyzer - Web Application Usage Guide

Complete guide for setting up and using the AI Network Analyzer web application.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Backend Setup](#backend-setup)
3. [Frontend Setup](#frontend-setup)
4. [Using the Web Interface](#using-the-web-interface)
5. [API Reference](#api-reference)
6. [Configuration](#configuration)
7. [Troubleshooting](#troubleshooting)

---

## Quick Start

### Prerequisites

- **Python 3.11+** with pip
- **Node.js 18+** with npm
- **Nmap** installed and in PATH
- **API Keys** (recommended):
  - `GEMINI_API_KEY` - For AI threat analysis
  - `NVD_API_KEY` - For higher CVE lookup rate limits

### Start Both Servers

```bash
# Terminal 1: Start Backend
cd web/backend

python -m venv venv # First time only

.\venv\Scripts\activate  # Windows

pip install -r requirements.txt

python -m uvicorn api.main:app --reload --host 0.0.0.0 --port 8000

# Terminal 2: Start Frontend
cd web/frontend

npm install # First time only

npm run dev
```

**Access the app:**
- Frontend: http://localhost:3000
- Backend API: http://localhost:8000
- API Docs: http://localhost:8000/docs

---

## Backend Setup

### 1. Create Virtual Environment

```bash
cd web/backend

# Create venv
python -m venv venv

# Activate (Windows)
.\venv\Scripts\activate

# Activate (Linux/Mac)
source venv/bin/activate
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure Environment Variables

```bash
# Create .env file
copy .env.example .env

# Edit .env with your keys
notepad .env
```

**.env file contents:**
```env
# Required for AI Analysis
GEMINI_API_KEY=your_gemini_api_key_here

# Optional (improves CVE lookup rate limits)
NVD_API_KEY=your_nvd_api_key_here
```

### 4. Start the Backend Server

```bash
# Development mode with auto-reload
python -m uvicorn api.main:app --reload --host 0.0.0.0 --port 8000

# Production mode
python -m uvicorn api.main:app --host 0.0.0.0 --port 8000 --workers 4
```

**Expected output:**
```
🚀 AI Network Analyzer API starting...
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
```

### 5. Verify Backend is Running

```bash
# Health check
curl http://localhost:8000/api/health

# Expected response:
{"status": "healthy"}
```

---

## Frontend Setup

### 1. Install Dependencies

```bash
cd web/frontend
npm install
```

### 2. Start Development Server

```bash
npm run dev
```

**Expected output:**
```
▲ Next.js 16.1.0 (Turbopack)
- Local:        http://localhost:3000
✓ Ready in 1670ms
```

### 3. Access the Web Interface

Open your browser and navigate to: **http://localhost:3000**

---

## Using the Web Interface

### Homepage - Scanner

The homepage (`/`) is the main scanning interface.

#### Starting a Scan

1. Enter a **target IP address** or hostname in the input field
   - Example: `192.168.1.1` or `scanme.nmap.org`
   
2. Click **🔍 Start Live Scan**

3. Watch the **real-time progress**:
   - 🔍 Detecting Services... (0-30%)
   - 🔒 Checking CVEs... (30-70%)
   - 🤖 AI Analysis... (70-95%)
   - ✅ Complete (100%)

#### Viewing Results

After scan completion, you'll see:

| Section | Description |
|---------|-------------|
| **Summary Cards** | Total CVEs, Critical, High, Medium, Low counts |
| **AI Threat Analysis** | Risk level, threat summary, executive summary |
| **Attack Scenarios** | Potential exploitation paths (red boxes) |
| **Recommendations** | Prioritized remediation steps (green section) |
| **CVE Table** | Full vulnerability listing with severity badges |

#### Downloading Reports

Click the download buttons to get reports:
- **JSON** - Raw scan data
- **HTML** - Interactive web report
- **PDF** - Professional document

---

### History Page

Navigate to **/history** to see all past scans.

#### Features

| Action | Description |
|--------|-------------|
| **View Details** | Open full scan results |
| **JSON** | Download JSON export |
| **HTML** | Download HTML report |
| **PDF** | Download PDF report |
| **🗑️** | Delete individual scan |
| **🗑️ Delete All** | Remove all scan history |
| **🔄 Refresh** | Reload scan list |

#### Scan Status Colors

| Color | Status |
|-------|--------|
| 🟢 Green | Complete |
| 🔴 Red | Failed |
| 🔵 Cyan | In Progress |
| ⚪ Gray | Pending |

---

### Scan Detail Page

Navigate to **/scan/{scan_id}** to view detailed results for a specific scan.

This page shows the same content as the homepage results but for historical scans.

---

## API Reference

### Endpoints

#### Live Scanning

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/live/live` | Start a new scan |
| `GET` | `/api/live/live` | List all scans |
| `GET` | `/api/live/live/{scan_id}` | Get scan status/results |
| `DELETE` | `/api/live/live/{scan_id}` | Delete a scan |
| `DELETE` | `/api/live/live` | Delete all scans |

#### Reports

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/reports/download/{scan_id}/json` | Download JSON |
| `GET` | `/api/reports/download/{scan_id}/html` | Download HTML |
| `GET` | `/api/reports/download/{scan_id}/pdf` | Download PDF |

#### Health

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/health` | Health check |

---

### API Examples

#### Start a Scan

```bash
curl -X POST http://localhost:8000/api/live/live \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.1", "max_cves": 20, "skip_ai": false}'
```

**Response:**
```json
{
  "scan_id": "live_20251222_143000_abc123",
  "status": "pending",
  "message": "Scan queued",
  "progress": 0
}
```

#### Get Scan Status

```bash
curl http://localhost:8000/api/live/live/live_20251222_143000_abc123
```

**Response (in-progress):**
```json
{
  "scan_id": "live_20251222_143000_abc123",
  "status": "scanning",
  "message": "Detecting services...",
  "progress": 25
}
```

**Response (complete):**
```json
{
  "scan_id": "live_20251222_143000_abc123",
  "status": "complete",
  "message": "Scan complete! Found 15 vulnerabilities.",
  "progress": 100,
  "results": {
    "target": "192.168.1.1",
    "summary": {
      "total_cves": 15,
      "critical_count": 2,
      "high_count": 5,
      "medium_count": 6,
      "low_count": 2
    },
    "ai_analysis": {...},
    "vulnerabilities": [...]
  }
}
```

#### List All Scans

```bash
curl http://localhost:8000/api/live/live
```

**Response:**
```json
{
  "scans": [
    {
      "scan_id": "live_20251222_143000_abc123",
      "status": "complete",
      "message": "Scan complete! Found 15 vulnerabilities.",
      "progress": 100
    }
  ]
}
```

#### Delete a Scan

```bash
curl -X DELETE http://localhost:8000/api/live/live/live_20251222_143000_abc123
```

#### Delete All Scans

```bash
curl -X DELETE http://localhost:8000/api/live/live
```

#### Download HTML Report

```bash
curl -o report.html http://localhost:8000/api/reports/download/live_20251222_143000_abc123/html
```

---

## Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `GEMINI_API_KEY` | Yes* | Google Gemini API key for AI analysis |
| `NVD_API_KEY` | No | NVD API key for higher rate limits |
| `DEBUG` | No | Enable debug logging |

*Without GEMINI_API_KEY, AI analysis will be skipped

### Getting API Keys

1. **Gemini API Key**: https://aistudio.google.com/apikey
2. **NVD API Key**: https://nvd.nist.gov/developers/request-an-api-key

### Scan Persistence

- Scans are stored in `data/scans/` as JSON files
- Maximum 50 scans are kept (oldest are automatically deleted)
- Scans persist across server restarts

---

## Troubleshooting

### Backend Won't Start

**Error:** `ModuleNotFoundError: No module named 'xxx'`
```bash
pip install -r requirements.txt
```

**Error:** `Port 8000 already in use`
```bash
# Use a different port
python -m uvicorn api.main:app --port 8001
```

### Frontend Won't Connect to Backend

**Error:** `Failed to fetch` or `Network error`

1. Verify backend is running:
   ```bash
   curl http://localhost:8000/api/health
   ```

2. Check CORS is enabled (backend automatically allows all origins in dev mode)

### Scans Fail with "Nmap not found"

Install Nmap from https://nmap.org/download.html and ensure it's in your PATH:
```bash
nmap --version
```

### AI Analysis Not Working

1. Check GEMINI_API_KEY is set in `.env`:
   ```bash
   cat .env | grep GEMINI
   ```

2. Verify your API key is valid at https://aistudio.google.com

3. Use `--skip-ai` option or set `skip_ai: true` in the scan request

### Low CVE Counts

- Get an NVD API key for higher rate limits
- Some services may not have CPE identifiers
- Very old or obscure software may not be in NVD

---

## Quick Reference

```bash
# Start Backend
cd web/backend
.\venv\Scripts\activate
python -m uvicorn api.main:app --reload --port 8000

# Start Frontend
cd web/frontend
npm run dev

# Access
# Frontend: http://localhost:3000
# API Docs: http://localhost:8000/docs

# API Calls
curl http://localhost:8000/api/health
curl -X POST http://localhost:8000/api/live/live -H "Content-Type: application/json" -d '{"target": "192.168.1.1"}'
```

---

*Part of the AI Network Analyzer suite (Desktop CLI | Web | Mobile)*
