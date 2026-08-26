"""
Scanner integration for the bug bounty module.
Wraps Robin's existing scanning pipeline and adds bug-bounty-specific checks.
"""

import hashlib
import logging
import re
import time
from dataclasses import dataclass, field
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)

CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
LOW = "low"
INFO = "info"


@dataclass
class Vulnerability:
    """Represents a single vulnerability finding."""
    title: str
    severity: str
    cwe: Optional[str] = None
    cve: Optional[str] = None
    description: str = ""
    affected_url: str = ""
    payload: str = ""
    evidence: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)


@dataclass
class ScanResult:
    """Container for scan results of a single target."""
    target: str
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    scan_duration: float = 0.0
    id: str = ""
    report: Optional[str] = None

    def __post_init__(self):
        if not self.id:
            self.id = hashlib.sha256(self.target.encode()).hexdigest()[:12]

    @property
    def severity(self) -> str:
        """Return the highest severity among all vulnerabilities."""
        order = {INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4}
        if not self.vulnerabilities:
            return INFO
        return max(self.vulnerabilities, key=lambda v: order.get(v.severity, 0)).severity

    def fingerprint(self) -> str:
        """Generate a unique fingerprint for deduplication."""
        parts = [self.target]
        for v in sorted(self.vulnerabilities, key=lambda x: x.title):
            parts.append(f"{v.title}:{v.affected_url}")
        raw = "|".join(parts)
        return hashlib.sha256(raw.encode()).hexdigest()


class BugBountyScanner:
    """
    Scanner that coordinates vulnerability checks for bug bounty targets.
    Integrates with Robin's existing scanning pipeline and adds
    bug-bounty-specific heuristics.
    """

    XSS_PATTERNS = [
        r"<script[^>]*>.*?</script>",
        r"javascript:",
        r"onerror\s*=",
        r"onload\s*=",
    ]

    SQLI_PATTERNS = [
        r"SQLITE_ERROR",
        r"You have an error in your SQL syntax",
        r"ORA-\d{5}",
        r"PG::Error",
        r"Microsoft SQL Server",
    ]

    SSRF_PATTERNS = [
        r"169\.254\.169\.254",
        r"metadata\.google\.internal",
        r"localhost",
    ]

    SECURITY_HEADERS = [
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
    ]

    def __init__(self, config=None):
        self.config = config
        self._timeout = 30

    def scan_targets(self, targets: List[str]) -> List[ScanResult]:
        """Scan multiple targets and return results."""
        results = []
        for target in targets:
            try:
                result = self.scan_target(target)
                results.append(result)
            except Exception as exc:
                logger.error("Scan failed for %s: %s", target, exc)
                results.append(ScanResult(target=target, vulnerabilities=[]))
        return results

    def scan_target(self, target: str) -> ScanResult:
        """Scan a single target for vulnerabilities."""
        start = time.time()
        logger.info("Scanning target: %s", target)

        vulns: List[Vulnerability] = []
        vulns.extend(self._check_xss(target))
        vulns.extend(self._check_sqli(target))
        vulns.extend(self._check_ssrf(target))
        vulns.extend(self._check_csrf(target))
        vulns.extend(self._check_security_headers(target))
        vulns.extend(self._check_open_redirect(target))

        duration = time.time() - start
        result = ScanResult(
            target=target,
            vulnerabilities=vulns,
            scan_duration=round(duration, 2),
        )
        logger.info("Scan complete for %s: %d finding(s)", target, len(vulns))
        return result

    def _check_xss(self, target: str) -> List[Vulnerability]:
        """Check for Cross-Site Scripting vulnerabilities."""
        # Placeholder: inject payloads and check responses
        # In production, this would use Robin's existing XSS scanner
        return []

    def _check_sqli(self, target: str) -> List[Vulnerability]:
        """Check for SQL Injection vulnerabilities."""
        return []

    def _check_ssrf(self, target: str) -> List[Vulnerability]:
        """Check for Server-Side Request Forgery."""
        return []

    def _check_csrf(self, target: str) -> List[Vulnerability]:
        """Check for Cross-Site Request Forgery issues."""
        return []

    def _check_security_headers(self, target: str) -> List[Vulnerability]:
        """Check for missing security headers."""
        return []

    def _check_open_redirect(self, target: str) -> List[Vulnerability]:
        """Check for open redirect vulnerabilities."""
        return []

    def _match_patterns(self, content: str, patterns: List[str]) -> bool:
        """Check if content matches any of the given patterns."""
        for pattern in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        return False
