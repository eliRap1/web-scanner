"""
Report Generator for vulnerability scan results.

This module handles the generation of HTML, PDF, and JSON reports from scan data.
Reports include:
- Executive summary with statistics
- Visual charts showing vulnerability distribution
- Detailed findings with evidence
- Remediation guidance with code examples
- Methodology explanation

Dependencies:
- jinja2: Template rendering
- xhtml2pdf: PDF generation (pure Python, no GTK required)
- weasyprint (optional): PDF generation (requires GTK on Windows)
"""

import os
import re
import io
import json
from datetime import datetime
from typing import Dict, Any, List
from pathlib import Path
import logging
from jinja2 import Environment, FileSystemLoader
from reports.remediation import get_remediation, REMEDIATION_GUIDE

logger = logging.getLogger(__name__)

# Report storage directory - stores generated HTML/PDF files
REPORTS_DIR = Path(__file__).parent.parent.parent / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

# Templates directory - contains Jinja2 templates
TEMPLATES_DIR = Path(__file__).parent / "templates"


class ReportGenerator:
    """
    Generate PDF/HTML reports from vulnerability scan results.

    This class handles:
    - Loading and rendering Jinja2 templates
    - Preparing vulnerability data for display
    - Adding remediation guidance
    - Generating both HTML and PDF output

    Attributes:
        env: Jinja2 environment for template loading
    """

    def __init__(self):
        """Initialize the report generator with Jinja2 environment."""
        self.env = Environment(
            loader=FileSystemLoader(str(TEMPLATES_DIR)),
            autoescape=True  # Escape HTML to prevent XSS payloads from rendering
        )

    def generate_report(
        self,
        scan_id: int,
        scan_data: Dict[str, Any],
        vulnerabilities: List[Dict[str, Any]],
        format: str = "html"
    ) -> str:
        """
        Generate a report from scan data.

        Args:
            scan_id: Database scan ID
            scan_data: Scan metadata (target_url, start_time, etc.)
            vulnerabilities: List of vulnerability findings
            format: "pdf", "html", or "json"

        Returns:
            Path to generated report file
        """
        # Prepare report data
        report_data = self._prepare_report_data(scan_id, scan_data, vulnerabilities)

        # Generate filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"scan_{scan_id}_{timestamp}"

        if format == "json":
            # Generate JSON report
            output_path = REPORTS_DIR / f"{base_name}.json"
            json_report = self._generate_json_report(report_data)
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(json_report, f, indent=2, default=str)
            logger.info("JSON report generated: %s", output_path)
        elif format == "pdf":
            # Render HTML template for PDF generation
            template = self.env.get_template("report_template.html")
            html_content = template.render(**report_data)

            pdf_generated = False
            output_path = REPORTS_DIR / f"{base_name}.pdf"

            # Try xhtml2pdf first (pure Python, works everywhere)
            if not pdf_generated:
                try:
                    from xhtml2pdf import pisa
                    with open(output_path, "wb") as pdf_file:
                        pisa_status = pisa.CreatePDF(
                            io.BytesIO(html_content.encode("utf-8")),
                            dest=pdf_file
                        )
                        if not pisa_status.err:
                            pdf_generated = True
                            logger.info("PDF generated with xhtml2pdf: %s", output_path)
                        else:
                            logger.warning("xhtml2pdf error: %s", pisa_status.err)
                except ImportError:
                    logger.info("xhtml2pdf not installed, trying weasyprint...")
                except Exception as e:
                    logger.warning("xhtml2pdf failed: %s", e)

            # Try WeasyPrint as fallback (requires GTK on Windows)
            if not pdf_generated:
                try:
                    from weasyprint import HTML
                    HTML(string=html_content).write_pdf(str(output_path))
                    pdf_generated = True
                    logger.info("PDF generated with WeasyPrint: %s", output_path)
                except (ImportError, OSError) as e:
                    logger.info("WeasyPrint unavailable: %s", e)
                except Exception as e:
                    logger.warning("WeasyPrint failed: %s", e)

            # If all PDF methods failed, fall back to HTML
            if not pdf_generated:
                logger.warning("All PDF generators failed, falling back to HTML format.")
                output_path = REPORTS_DIR / f"{base_name}.html"
                with open(output_path, "w", encoding="utf-8") as f:
                    f.write(html_content)
        else:
            # Default: HTML format
            template = self.env.get_template("report_template.html")
            html_content = template.render(**report_data)
            output_path = REPORTS_DIR / f"{base_name}.html"
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html_content)

        return str(output_path)

    def _prepare_report_data(
        self,
        scan_id: int,
        scan_data: Dict,
        vulnerabilities: List[Dict]
    ) -> Dict[str, Any]:
        """Prepare data context for template rendering."""
        # Normalize vulnerability data for template
        normalized_vulns = []
        for vuln in vulnerabilities:
            v = dict(vuln)  # Copy to avoid modifying original

            # Extract URL from description if not present
            if not v.get("url") and v.get("description"):
                desc = v["description"]
                # Try to extract URL from "at http..." pattern
                url_match = re.search(r'at\s+(https?://[^\s]+)', desc)
                if url_match:
                    v["url"] = url_match.group(1)

            # Extract parameter from description if not present
            if not v.get("parameter") and v.get("description"):
                desc = v["description"]
                param_match = re.search(r"parameter\s+'([^']+)'", desc)
                if param_match:
                    v["parameter"] = param_match.group(1)

            # Normalize vuln_type
            if not v.get("vuln_type") and v.get("type"):
                v["vuln_type"] = v["type"]

            normalized_vulns.append(v)

        # Group vulnerabilities by severity
        by_severity = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "info": []
        }
        for vuln in normalized_vulns:
            sev = (vuln.get("severity") or "medium").lower()
            if sev in by_severity:
                by_severity[sev].append(vuln)
            else:
                by_severity["medium"].append(vuln)

        # Group by vulnerability type
        by_type = {}
        for vuln in normalized_vulns:
            vtype = vuln.get("vuln_type") or vuln.get("type") or "Unknown"
            if vtype not in by_type:
                by_type[vtype] = []
            by_type[vtype].append(vuln)

        # Calculate statistics
        stats = {
            "total": len(normalized_vulns),
            "critical": len(by_severity["critical"]),
            "high": len(by_severity["high"]),
            "medium": len(by_severity["medium"]),
            "low": len(by_severity["low"]),
            "info": len(by_severity["info"]),
        }

        # Calculate risk score (0-100)
        risk_score = min(100, (
            stats["critical"] * 25 +
            stats["high"] * 15 +
            stats["medium"] * 5 +
            stats["low"] * 1
        ))

        # Build remediation guide for found vulnerability types
        remediation_guide = {}
        for vuln_type in by_type.keys():
            remediation_guide[vuln_type] = get_remediation(vuln_type)

        # Add remediation steps to each vulnerability
        for vuln in normalized_vulns:
            vuln_type = vuln.get("vuln_type") or vuln.get("type") or "Unknown"
            guide = get_remediation(vuln_type)
            if guide:
                vuln["remediation"] = guide.get("remediation", [])

        return {
            "scan_id": scan_id,
            "target_url": scan_data.get("target_url") or scan_data.get("url", "Unknown"),
            "start_time": scan_data.get("start_time", "N/A"),
            "end_time": scan_data.get("end_time", "N/A"),
            "status": scan_data.get("status", "completed"),
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "vulnerabilities": normalized_vulns,
            "by_severity": by_severity,
            "by_type": by_type,
            "stats": stats,
            "risk_score": risk_score,
            "remediation_guide": remediation_guide,
        }

    def _generate_json_report(self, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """Return a JSON-serializable dict of the report data."""
        # Repack only the fields that are safe to serialise directly
        return {
            "scan_id": report_data.get("scan_id"),
            "target_url": report_data.get("target_url"),
            "start_time": str(report_data.get("start_time", "")),
            "end_time": str(report_data.get("end_time", "")),
            "generated_at": report_data.get("generated_at"),
            "status": report_data.get("status"),
            "stats": report_data.get("stats", {}),
            "risk_score": report_data.get("risk_score", 0),
            "vulnerabilities": report_data.get("vulnerabilities", []),
            "remediation_guide": report_data.get("remediation_guide", {}),
        }
