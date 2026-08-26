"""
Vulnerability reporter for the bug bounty module.
Generates detailed, submission-ready reports in multiple formats.
"""

import json
import logging
from datetime import datetime
from typing import Optional

from .scanner import ScanResult, Vulnerability

logger = logging.getLogger(__name__)


class VulnerabilityReporter:
    """
    Generates vulnerability reports in multiple formats
    suitable for bug bounty submissions.
    """

    SEVERITY_BADGE = {
        "critical": "[CRITICAL]",
        "high": "[HIGH]",
        "medium": "[MEDIUM]",
        "low": "[LOW]",
        "info": "[INFO]",
    }

    def __init__(self, fmt: str = "markdown"):
        self.fmt = fmt.lower()

    def generate_report(self, result: ScanResult) -> str:
        """Generate a report for a scan result in the configured format."""
        if self.fmt == "json":
            return self._generate_json(result)
        elif self.fmt == "html":
            return self._generate_html(result)
        else:
            return self._generate_markdown(result)

    def _generate_markdown(self, result: ScanResult) -> str:
        """Generate a Markdown-formatted vulnerability report."""
        lines = [
            f"# Bug Bounty Report - {result.target}",
            "",
            f"**Scan ID:** {result.id}",
            f"**Date:** {datetime.utcnow().isoformat()}Z",
            f"**Duration:** {result.scan_duration}s",
            f"**Total Findings:** {len(result.vulnerabilities)}",
            "",
            "---",
            "",
        ]

        if not result.vulnerabilities:
            lines.append("No vulnerabilities found.")
            return "\n".join(lines)

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_vulns = sorted(
            result.vulnerabilities,
            key=lambda v: severity_order.get(v.severity.lower(), 99),
        )

        for idx, vuln in enumerate(sorted_vulns, 1):
            badge = self.SEVERITY_BADGE.get(vuln.severity, "[INFO]")
            lines.append(f"## {idx}. {badge} {vuln.title}")
            lines.append("")
            lines.append(f"**Severity:** {vuln.severity.upper()}")
            if vuln.cwe:
                lines.append(f"**CWE:** {vuln.cwe}")
            if vuln.cve:
                lines.append(f"**CVE:** {vuln.cve}")
            lines.append(f"**Affected URL:** `{vuln.affected_url}`")
            lines.append(f"**Description:**")
            lines.append(vuln.description)
            lines.append("")
            if vuln.payload:
                lines.append("**Payload:**")
                lines.append("```")
                lines.append(vuln.payload)
                lines.append("```")
                lines.append("")
            if vuln.evidence:
                lines.append("**Evidence:**")
                lines.append("```")
                lines.append(vuln.evidence)
                lines.append("```")
                lines.append("")
            lines.append("**Remediation:**")
            lines.append(vuln.remediation)
            lines.append("")
            if vuln.references:
                lines.append("**References:**")
                for ref in vuln.references:
                    lines.append(f"- {ref}")
                lines.append("")
            lines.append("---")
            lines.append("")

        return "\n".join(lines)

    def _generate_json(self, result: ScanResult) -> str:
        """Generate a JSON-formatted vulnerability report."""
        report = {
            "scan_id": result.id,
            "target": result.target,
            "date": datetime.utcnow().isoformat() + "Z",
            "duration_seconds": result.scan_duration,
            "total_findings": len(result.vulnerabilities),
            "findings": [
                {
                    "title": v.title,
                    "severity": v.severity,
                    "cwe": v.cwe,
                    "cve": v.cve,
                    "affected_url": v.affected_url,
                    "description": v.description,
                    "payload": v.payload,
                    "evidence": v.evidence,
                    "remediation": v.remediation,
                    "references": v.references,
                }
                for v in result.vulnerabilities
            ],
        }
        return json.dumps(report, indent=2)

    def _generate_html(self, result: ScanResult) -> str:
        """Generate a minimal HTML vulnerability report."""
        md = self._generate_markdown(result)
        html_lines = [
            "<!DOCTYPE html>",
            "<html>",
            "<head><title>Bug Bounty Report</title></head>",
            "<body><pre>",
            md,
            "</pre></body>",
            "</html>",
        ]
        return "\n".join(html_lines)
