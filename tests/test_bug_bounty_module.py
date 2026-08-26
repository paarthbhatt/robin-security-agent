"""
Unit tests for the autonomous bug bounty module.
"""

import unittest
from datetime import datetime, timedelta

from src.modules.bug_bounty import BugBountyModule, BugBountyConfig
from src.modules.bug_bounty.scanner import ScanResult, Vulnerability, BugBountyScanner
from src.modules.bug_bounty.reporter import VulnerabilityReporter
from src.modules.bug_bounty.bounty_manager import BountyManager, BountySubmission, SubmissionStatus


class TestBugBountyConfig(unittest.TestCase):
    def test_defaults(self):
        config = BugBountyConfig()
        self.assertEqual(config.scan_interval_hours, 24)
        self.assertEqual(config.min_severity, "medium")
        self.assertFalse(config.auto_submit)
        self.assertTrue(config.dedup_enabled)
        self.assertEqual(config.report_format, "markdown")

    def test_custom_config(self):
        config = BugBountyConfig(
            scan_interval_hours=12,
            min_severity="high",
            auto_submit=True,
            target_whitelist=["https://example.com"],
        )
        self.assertEqual(config.scan_interval_hours, 12)
        self.assertEqual(config.min_severity, "high")
        self.assertTrue(config.auto_submit)
        self.assertEqual(len(config.target_whitelist), 1)


class TestScanResult(unittest.TestCase):
    def test_id_generation(self):
        result = ScanResult(target="https://example.com")
        self.assertEqual(len(result.id), 12)

    def test_same_target_same_id(self):
        r1 = ScanResult(target="https://example.com")
        r2 = ScanResult(target="https://example.com")
        self.assertEqual(r1.id, r2.id)

    def test_severity_no_vulns(self):
        result = ScanResult(target="https://example.com")
        self.assertEqual(result.severity, "info")

    def test_severity_with_vulns(self):
        vulns = [
            Vulnerability(title="XSS", severity="medium"),
            Vulnerability(title="SQLi", severity="high"),
        ]
        result = ScanResult(target="https://example.com", vulnerabilities=vulns)
        self.assertEqual(result.severity, "high")

    def test_fingerprint(self):
        vulns = [Vulnerability(title="XSS", severity="medium", affected_url="https://example.com/x")]
        r1 = ScanResult(target="https://example.com", vulnerabilities=vulns)
        r2 = ScanResult(target="https://example.com", vulnerabilities=vulns)
        self.assertEqual(r1.fingerprint(), r2.fingerprint())


class TestVulnerabilityReporter(unittest.TestCase):
    def test_markdown_report(self):
        vulns = [
            Vulnerability(
                title="Reflected XSS",
                severity="high",
                cwe="CWE-79",
                affected_url="https://example.com/search?q=test",
                description="User input reflected without encoding.",
                remediation="Encode all user input on output.",
            )
        ]
        result = ScanResult(target="https://example.com", vulnerabilities=vulns)
        reporter = VulnerabilityReporter(fmt="markdown")
        report = reporter.generate_report(result)
        self.assertIn("# Bug Bounty Report", report)
        self.assertIn("[HIGH]", report)
        self.assertIn("Reflected XSS", report)
        self.assertIn("CWE-79", report)

    def test_json_report(self):
        vulns = [Vulnerability(title="SQLi", severity="critical")]
        result = ScanResult(target="https://example.com", vulnerabilities=vulns)
        reporter = VulnerabilityReporter(fmt="json")
        report = reporter.generate_report(result)
        import json
        parsed = json.loads(report)
        self.assertEqual(parsed["target"], "https://example.com")
        self.assertEqual(len(parsed["findings"]), 1)

    def test_empty_report(self):
        result = ScanResult(target="https://example.com")
        reporter = VulnerabilityReporter(fmt="markdown")
        report = reporter.generate_report(result)
        self.assertIn("No vulnerabilities found", report)


class TestBugBountyModule(unittest.TestCase):
    def test_no_targets(self):
        config = BugBountyConfig()
        module = BugBountyModule(config=config)
        results = module.run_cycle()
        self.assertEqual(results, [])

    def test_should_run_no_history(self):
        module = BugBountyModule()
        self.assertTrue(module.should_run())

    def test_should_run_recent_scan(self):
        module = BugBountyModule()
        module._last_scan_time = datetime.utcnow()
        self.assertFalse(module.should_run())

    def test_should_run_old_scan(self):
        module = BugBountyModule(config=BugBountyConfig(scan_interval_hours=1))
        module._last_scan_time = datetime.utcnow() - timedelta(hours=2)
        self.assertTrue(module.should_run())

    def test_status(self):
        module = BugBountyModule()
        status = module.get_status()
        self.assertIn("last_scan", status)
        self.assertIn("total_submitted", status)
        self.assertIn("auto_submit", status)

    def test_severity_filter(self):
        low_vuln = Vulnerability(title="Info Leak", severity="low")
        high_vuln = Vulnerability(title="RCE", severity="high")
        results = [
            ScanResult(target="https://a.com", vulnerabilities=[low_vuln]),
            ScanResult(target="https://b.com", vulnerabilities=[high_vuln]),
        ]
        config = BugBountyConfig(min_severity="high")
        module = BugBountyModule(config=config)
        filtered = module._filter_by_severity(results)
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0].target, "https://b.com")

    def test_dedup(self):
        vulns = [Vulnerability(title="XSS", severity="medium", affected_url="https://example.com/x")]
        r1 = ScanResult(target="https://example.com", vulnerabilities=vulns)
        r2 = ScanResult(target="https://example.com", vulnerabilities=vulns)
        module = BugBountyModule()
        unique = module._deduplicate([r1, r2])
        self.assertEqual(len(unique), 1)


class TestBountyManager(unittest.TestCase):
    def test_summary_empty(self):
        import os
        os.environ["ROBIN_DATA_DIR"] = "/tmp/robin_test"
        manager = BountyManager()
        summary = manager.get_summary()
        self.assertEqual(summary["total_submissions"], 0)
        self.assertEqual(summary["total_reward"], 0)

    def test_update_nonexistent(self):
        os.environ["ROBIN_DATA_DIR"] = "/tmp/robin_test"
        manager = BountyManager()
        result = manager.update_submission_status("nonexistent", SubmissionStatus.RESOLVED)
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
