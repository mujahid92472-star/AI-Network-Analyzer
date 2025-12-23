# 🛡️ AI Network Analyzer - Desktop CLI

> **Enterprise-Grade Network Security Scanner with AI-Powered Threat Intelligence**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A powerful command-line network security analysis tool that scans networks, identifies vulnerabilities through NVD CVE matching, and provides AI-driven threat intelligence using Google Gemini.

## ✨ Key Features

| Category | Features |
|----------|----------|
| **🔍 Network Scanning** | Host discovery, Port scanning (SYN/TCP/UDP), Service detection, OS fingerprinting |
| **🔒 Vulnerability Assessment** | NVD API 2.0 integration, CVE matching, CVSS scoring, KEV (Known Exploited) detection |
| **🤖 AI Analysis** | Google Gemini threat analysis, Attack scenarios, Remediation steps, Executive summaries |
| **📊 Reporting** | HTML reports, PDF reports, JSON export, Color-coded CLI output |

## 📋 Requirements

- **Python** 3.11 or higher
- **Nmap** installed and in PATH ([download](https://nmap.org/download.html))
- **API Keys** (optional but recommended):
  - `GEMINI_API_KEY` - For AI threat analysis
  - `NVD_API_KEY` - For higher CVE lookup rate limits

## 🚀 Quick Start

### Installation

```bash
cd desktop

# Create virtual environment
python -m venv venv

# Activate (Windows)
venv\Scripts\Activate.ps1

# Activate (Linux/macOS)
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Configuration

```bash
# Copy environment template
cp .env.example .env

# Edit .env with your API keys
GEMINI_API_KEY=your_gemini_api_key
NVD_API_KEY=your_nvd_api_key  # Optional
```

### Basic Commands

```bash
# Check system requirements
python -m src.main check

# Full vulnerability scan with AI analysis
python -m src.main scan --target 192.168.1.1

# Scan with custom options
python -m src.main scan --target 192.168.1.0/24 --ports 22,80,443 --max-cves 50

# Skip AI analysis for faster scans
python -m src.main scan --target 192.168.1.1 --skip-ai

# Generate configuration file
python -m src.main init-config
```

## 📁 Project Structure

```
desktop/
├── src/
│   ├── core/           # Configuration, logging
│   ├── scanner/        # Network scanning (Nmap integration)
│   ├── vulnerability/  # CVE lookup (NVD API)
│   ├── intelligence/   # AI analysis (Gemini)
│   ├── reporting/      # HTML/PDF/JSON reports
│   └── main.py         # CLI entry point
├── data/               # CVE cache
├── logs/               # Application logs
├── requirements.txt    # Python dependencies
├── FEATURES.md         # Complete feature documentation
└── USAGE.md            # Detailed usage guide
```

## 📊 Output

Scans produce:
- **CLI Output** - Color-coded terminal display with severity indicators
- **HTML Report** - Interactive web report with charts and tables
- **PDF Report** - Professional document for stakeholders
- **JSON Export** - Machine-readable data for integration

### Sample Output
```
🛡️ AI Network Analyzer
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Target: 192.168.1.100
Services Found: 5
Total CVEs: 23

 CRITICAL   HIGH   MEDIUM   LOW
    3        8       10      2

🤖 AI Threat Analysis: HIGH RISK
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
This host exposes critical services with known exploits...
```

## 📖 Documentation

- **[FEATURES.md](FEATURES.md)** - Complete feature reference
- **[USAGE.md](USAGE.md)** - Detailed usage examples

## ⚠️ Legal Notice

**Only scan networks you own or have explicit written permission to scan.** Unauthorized network scanning may be illegal in your jurisdiction.

## 📄 License

MIT License - See [LICENSE](../LICENSE) for details.

---

*Part of the AI Network Analyzer multi-platform suite (Desktop CLI | Web | Mobile)*
