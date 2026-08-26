"""
Autonomous Bug Bounty Module for Robin Security Agent.

Coordinates scanning, triaging, reporting, and optional submission
to bug bounty platforms on a configurable schedule.
"""

import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from dataclasses import dataclass, field

from .scanner import BugBountyScanner, ScanResult
from .reporter import VulnerabilityReporter
from .bounty_manager import BountyManager, BountySubmission

logger = logging.getLogger(__name__)


@dataclass
class BugBountyConfig:
    """Configuration for the autonomous bug bounty module."""
    scan_interval_hours: int = 24
    min_severity: str = "medium"
    auto_submit: bool = False
    programs: List[str] = field(default_factory=list)
    target_whitelist: List[str] = field(default_factory=list)
    max_concurrent_scans: int = 5
    dedup_enabled: bool = True
    report_format: str = "markdown"
    api_keys: Dict[str, str] = field(default_factory=dict)


class BugBountyModule:
    """
    Main module orchestrating the autonomous bug bounty workflow:
    scan -> triage -> report -> (optionally) submit -> track.
    """

    SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

    def __init__(self, config: Optional[BugBountyConfig] = None):
        self.config = config or BugBountyConfig()
        self.scanner = BugBountyScanner(config=self.config)
        self.reporter = VulnerabilityReporter(fmt=self.config.report_format)
        self.bounty_manager = BountyManager(config=self.config)
        self._last_scan_time: Optional[datetime] = None
        self._submitted_fingerprints: List[str] = []

    def run_cycle(self, targets: Optional[List[str]] = None) -> List[ScanResult]:
        """Execute one full scan-triage-report cycle."""
        targets = targets or self.config.target_whitelist
        if not targets:
            logger.warning("No targets configured for bug bounty scan.")
            return []

        logger.info("Starting bug bounty scan cycle for %d target(s).", len(targets))

        results = self.scanner.scan_targets(targets)

        if self.config.dedup_enabled:
            results = self._deduplicate(results)

        results = self._filter_by_severity(results)

        for result in results:
            result.report = self.reporter.generate_report(result)

        if self.config.auto_submit:
            for result in results:
                self._submit_finding(result)

        self._last_scan_time = datetime.utcnow()
        logger.info("Bug bounty cycle complete: %d finding(s).", len(results))
        return results

    def _deduplicate(self, results: List[ScanResult]) -> List[ScanResult]:
        seen = set(self._submitted_fingerprints)
        unique = []
        for r in results:
            fp = r.fingerprint()
            if fp not in seen:
                seen.add(fp)
                unique.append(r)
        logger.info("Dedup: %d -> %d unique findings.", len(results), len(unique))
        return unique

    def _filter_by_severity(self, results: List[ScanResult]) -> List[ScanResult]:
        threshold = self.SEVERITY_ORDER.get(self.config.min_severity.lower(), 2)
        return [
            r for r in results
            if self.SEVERITY_ORDER.get(r.severity.lower(), 0) >= threshold
        ]

    def _submit_finding(self, result: ScanResult) -> Optional[BountySubmission]:
        submission = self.bounty_manager.submit(result)
        if submission:
            self._submitted_fingerprints.append(result.fingerprint())
            logger.info("Submitted finding %s to %s.", result.id, submission.program)
        return submission

    def should_run(self) -> bool:
        """Check if enough time has elapsed since the last scan."""
        if self._last_scan_time is None:
            return True
        elapsed = datetime.utcnow() - self._last_scan_time
        return elapsed >= timedelta(hours=self.config.scan_interval_hours)

    def get_status(self) -> Dict:
        """Return current module status for dashboards."""
        return {
            "last_scan": self._last_scan_time.isoformat() + "Z" if self._last_scan_time else None,
            "total_submitted": len(self._submitted_fingerprints),
            "active_programs": len(self.config.programs),
            "targets_count": len(self.config.target_whitelist),
            "auto_submit": self.config.auto_submit,
            "bounty_summary": self.bounty_manager.get_summary(),
        }
