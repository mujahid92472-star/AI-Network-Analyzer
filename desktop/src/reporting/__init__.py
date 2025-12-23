"""
Reporting Module - Report generation and visualization.

This module provides reporting capabilities:
- Console reporter with color-coded output
- HTML report generation with charts
- PDF report generation
- Export formats (JSON, CSV, Markdown)
"""

from .console_reporter import (
    ConsoleReporter,
    ScanStatistics,
    SEVERITY_COLORS,
    SEVERITY_ICONS
)

from .html_reporter import (
    HTMLReporter,
    ReportData
)

from .pdf_reporter import (
    PDFReporter
)

__all__ = [
    "ConsoleReporter",
    "ScanStatistics",
    "SEVERITY_COLORS",
    "SEVERITY_ICONS",
    "HTMLReporter",
    "ReportData",
    "PDFReporter"
]
