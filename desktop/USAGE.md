# AI Network Analyzer - Desktop CLI User Guide

A comprehensive guide to using the AI Network Analyzer command-line tool for network vulnerability assessment.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Installation](#installation)
3. [Commands Overview](#commands-overview)
4. [Command Reference](#command-reference)
5. [Workflow Examples](#workflow-examples)
6. [Configuration](#configuration)
7. [Troubleshooting](#troubleshooting)

---

## Quick Start

```bash
# Activate virtual environment
cd desktop
.\venv\Scripts\Activate.ps1  # Windows
source venv/bin/activate  # Linux/Mac

# Run a complete security scan
python -m src.main fullscan -t 192.168.117.128

# Check system requirements
python -m src.main check
```

---

## Installation

### Prerequisites

1. **Python 3.11+** - Required for running the CLI
2. **Nmap** - Required for network scanning ([Download](https://nmap.org/download.html))
3. **API Keys** (optional but recommended):
   - `GEMINI_API_KEY` - For AI threat analysis
   - `NVD_API_KEY` - For higher CVE lookup rate limits

### Setup

```bash
# 1. Navigate to desktop directory
cd desktop

# 2. Create virtual environment
python -m venv venv

# 3. Activate virtual environment
.\venv\Scripts\Activate.ps1  # Windows
source venv/bin/activate  # Linux/Mac

# 4. Install dependencies
pip install -r requirements.txt

# 5. Create .env file with API keys
echo GEMINI_API_KEY=your_key_here > .env
echo NVD_API_KEY=your_nvd_key >> .env

# 6. Verify installation
python -m src.main check
```

---

## Commands Overview

| Command | Description |
|---------|-------------|
| `fullscan` | **Recommended** - Complete security scan (services → CVEs → AI analysis → reports) |
| `scan` | Basic port scan with optional vulnerability lookup |
| `discover` | Find live hosts on a network without port scanning |
| `services` | Deep service detection with CPE extraction |
| `vulns` | Lookup vulnerabilities from NVD database |
| `analyze` | AI-powered threat analysis using Gemini |
| `report` | Generate HTML/PDF reports from scan results |
| `check` | Verify system requirements and dependencies |
| `init-config` | Generate default configuration file |
| `version` | Show version information |

---

## Command Reference

### Global Options

These options work with all commands:

```bash
python -m src.main [OPTIONS] COMMAND [ARGS]

Options:
  --config PATH    Path to configuration file (YAML)
  --debug          Enable debug mode with verbose logging
  --quiet          Suppress banner and reduce output
  --help           Show help message
```

---

### `fullscan` - Complete Security Scan ⭐

The recommended command for running a complete security assessment.

```bash
python -m src.main fullscan [OPTIONS]
```

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `-t, --target` | TEXT | Required | Target IP, hostname, or CIDR range |
| `--max-cves` | INTEGER | 20 | Maximum CVEs to lookup per service |
| `--skip-ai` | FLAG | False | Skip AI threat analysis |

**Examples:**

```bash
# Full scan of a single host
python -m src.main fullscan -t 192.168.117.128

# Scan a subnet
python -m src.main fullscan -t 192.168.117.0/24

# Skip AI analysis for faster results
python -m src.main fullscan -t 10.0.0.5 --skip-ai

# Set maximum CVEs per service
python -m src.main fullscan -t 192.168.117.128 --max-cves 10
```

**Output:**
- `results/scan_YYYYMMDD_HHMMSS/services.json` - Detected services
- `results/scan_YYYYMMDD_HHMMSS/vulnerabilities.json` - Found CVEs
- `results/scan_YYYYMMDD_HHMMSS/ai_analysis.json` - AI threat analysis
- `results/scan_YYYYMMDD_HHMMSS/report.html` - Interactive HTML report
- `results/scan_YYYYMMDD_HHMMSS/report.pdf` - PDF report

---

### `scan` - Basic Port Scan

Perform port scanning with optional service detection and CVE lookup.

```bash
python -m src.main scan [OPTIONS]
```

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `-t, --target` | TEXT | Required | Target IP, hostname, or CIDR range |
| `-p, --ports` | TEXT | None | Specific ports (e.g., "22,80,443" or "1-1024") |
| `--top-ports` | INTEGER | None | Scan only top N most common ports |
| `--scan-type` | CHOICE | syn | Scan type: syn, tcp, udp, ack, fin |
| `-T, --timing` | INTEGER | 4 | Timing template (0-5, higher=faster) |
| `-sV, --service-detection` | FLAG | False | Enable service version detection |
| `-O, --os-detection` | FLAG | False | Enable OS detection (requires root) |
| `--cve-lookup` | FLAG | False | Look up CVEs for detected services |
| `-o, --output` | PATH | None | Output file path |
| `-f, --format` | CHOICE | text | Output format: text, json, xml |

**Examples:**

```bash
# Basic scan
python -m src.main scan -t 192.168.1.1

# Scan specific ports with service detection
python -m src.main scan -t 192.168.1.1 -p 22,80,443,3306 -sV

# Scan top 100 ports
python -m src.main scan -t 192.168.1.1 --top-ports 100

# UDP scan with JSON output
python -m src.main scan -t 192.168.1.1 --scan-type udp -o scan.json -f json

# Full scan with CVE lookup
python -m src.main scan -t 192.168.1.1 -sV --cve-lookup -o results.json -f json
```

---

### `discover` - Host Discovery

Find live hosts on a network without performing port scanning.

```bash
python -m src.main discover [OPTIONS]
```

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `-t, --target` | TEXT | Required | Network range (e.g., 192.168.1.0/24) |
| `-m, --method` | CHOICE | ping | Discovery method: ping, arp, tcp, syn |
| `-T, --timing` | INTEGER | 4 | Timing template (0-5) |
| `--tcp-ports` | TEXT | 22,80,443 | Ports for TCP discovery |
| `-r, --resolve` | FLAG | False | Resolve hostnames |
| `-o, --output` | PATH | None | Output file (JSON) |

**Examples:**

```bash
# Ping sweep
python -m src.main discover -t 192.168.1.0/24

# ARP discovery (local network only)
python -m src.main discover -t 192.168.1.0/24 -m arp

# TCP discovery on custom ports
python -m src.main discover -t 10.0.0.0/24 -m tcp --tcp-ports 22,80,443,8080

# With hostname resolution
python -m src.main discover -t 192.168.1.0/24 -r -o hosts.json
```

---

### `services` - Service Detection

Perform deep service fingerprinting to identify services and extract CPE identifiers.

```bash
python -m src.main services [OPTIONS]
```

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `-t, --target` | TEXT | Required | Target IP, hostname, or CIDR range |
| `-p, --ports` | TEXT | None | Specific ports to scan |
| `--top-ports` | INTEGER | None | Scan only top N ports |
| `-O, --os-detection` | FLAG | False | Enable OS detection |
| `-i, --intensity` | INTEGER | 7 | Service detection intensity (1-9) |
| `-T, --timing` | INTEGER | 4 | Timing template (0-5) |
| `-o, --output` | PATH | None | Output file (JSON) |

**Examples:**

```bash
# Service detection with default settings
python -m src.main services -t 192.168.1.1

# With OS detection
python -m src.main services -t 192.168.1.1 -O

# Maximum intensity for thorough detection
python -m src.main services -t 192.168.1.1 -i 9

# Save results for vulnerability scanning
python -m src.main services -t 192.168.1.1 -o services.json
```

---

### `vulns` - Vulnerability Lookup

Query the National Vulnerability Database (NVD) for CVEs.

```bash
python -m src.main vulns [OPTIONS]
```

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `-t, --target` | TEXT | None | Target to scan (runs service detection first) |
| `--cpe` | TEXT | None | Lookup CVEs for a specific CPE string |
| `--cve` | TEXT | None | Lookup details for a specific CVE ID |
| `-i, --input` | PATH | None | Input file from service detection |
| `--max-cves` | INTEGER | 20 | Maximum CVEs per service |
| `--check-exploits` | FLAG | False | Check for known exploits (KEV) |
| `-o, --output` | PATH | None | Output file (JSON) |

**Examples:**

```bash
# Scan a target for vulnerabilities
python -m src.main vulns -t 192.168.1.1

# From previous service detection
python -m src.main vulns -i services.json -o vulnerabilities.json

# Lookup specific CPE
python -m src.main vulns --cpe "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"

# Lookup specific CVE
python -m src.main vulns --cve CVE-2021-44228

# Check for actively exploited vulnerabilities
python -m src.main vulns -i services.json --check-exploits
```

---

### `analyze` - AI Threat Analysis

Analyze scan results using Google Gemini AI for threat intelligence.

```bash
python -m src.main analyze [OPTIONS]
```

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `-i, --input` | PATH | Required | Vulnerability scan results (JSON) |
| `-k, --api-key` | TEXT | None | Gemini API key (or use GEMINI_API_KEY env var) |
| `-o, --output` | PATH | None | Output file (JSON) |

**Examples:**

```bash
# Analyze vulnerability results
python -m src.main analyze -i vulnerabilities.json

# Specify API key
python -m src.main analyze -i vulnerabilities.json -k YOUR_API_KEY

# Save analysis
python -m src.main analyze -i vulnerabilities.json -o threat_analysis.json
```

**Output includes:**
- Threat summary
- Risk assessment (0-100 score)
- Potential attack scenarios
- Prioritized remediation steps

---

### `report` - Generate Reports

Generate HTML or PDF reports from scan results.

```bash
python -m src.main report [OPTIONS]
```

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `-i, --input` | PATH | Required | Scan results file (JSON) |
| `-f, --format` | CHOICE | html | Report format: html, pdf |
| `-o, --output` | PATH | None | Output file path |

**Examples:**

```bash
# Generate HTML report
python -m src.main report -i vulnerabilities.json -f html -o report.html

# Generate PDF report
python -m src.main report -i vulnerabilities.json -f pdf -o report.pdf
```

---

### `check` - System Requirements Check

Verify that all required tools are installed.

```bash
python -m src.main check
```

**Checks for:**
- Python version
- Nmap installation
- Required Python packages
- API key configuration

---

### `init-config` - Create Configuration

Generate a default configuration file.

```bash
python -m src.main init-config -o config.yaml
```

---

### `version` - Show Version

Display version information.

```bash
python -m src.main version
```

---

## Workflow Examples

### 1. Quick Security Assessment

```bash
# One-command full assessment
python -m src.main fullscan -t 192.168.117.128
```

### 2. Step-by-Step Manual Workflow

```bash
# Step 1: Discover hosts
python -m src.main discover -t 192.168.1.0/24 -o hosts.json

# Step 2: Detailed service detection
python -m src.main services -t 192.168.117.128 -o services.json

# Step 3: Vulnerability lookup
python -m src.main vulns -i services.json -o vulnerabilities.json

# Step 4: AI analysis
python -m src.main analyze -i vulnerabilities.json -o ai_analysis.json

# Step 5: Generate report
python -m src.main report -i ai_analysis.json -f html -o report.html
```

### 3. Network-Wide Scan

```bash
# Scan entire subnet with quick settings
python -m src.main fullscan -t 192.168.1.0/24 --max-cves 5 --skip-ai
```

---

## Configuration

### Environment Variables

Create a `.env` file in the `desktop` directory:

```env
# Required for AI analysis
GEMINI_API_KEY=your_gemini_api_key_here

# Recommended for higher NVD rate limits
NVD_API_KEY=your_nvd_api_key_here
```

### Getting API Keys

1. **Gemini API Key**: [Google AI Studio](https://aistudio.google.com/apikey)
2. **NVD API Key**: [NVD API Key Request](https://nvd.nist.gov/developers/request-an-api-key)

---

## Troubleshooting

### "Nmap not found"

Install Nmap from [nmap.org](https://nmap.org/download.html) and ensure it's in your PATH.

### "No module named 'src'"

Always run from the `desktop` directory using:
```bash
python -m src.main <command>
```

### Low CVE counts

- Get an NVD API key for higher rate limits
- Increase `--max-cves` parameter
- Some services may not have CPE identifiers

### Host unreachable warnings

- Verify target is online: `ping <target>`
- Check firewall settings
- Try different timing: `-T 3`

### AI analysis fails

- Verify GEMINI_API_KEY is set correctly
- Check your API quota at [Google AI Studio](https://aistudio.google.com)
- Use `--skip-ai` to skip AI analysis

---

## Quick Reference Card

```bash
# Full scan (recommended)
python -m src.main fullscan -t TARGET

# Service detection only
python -m src.main services -t TARGET -o services.json

# CVE lookup from services
python -m src.main vulns -i services.json -o vulnerabilities.json

# Generate HTML report
python -m src.main report -i vulnerabilities.json -f html -o report.html

# AI threat analysis
python -m src.main analyze -i vulnerabilities.json -o analysis.json

# Check system
python -m src.main check
```

---

## Support

For issues or questions, refer to the project documentation or create an issue on the repository.
