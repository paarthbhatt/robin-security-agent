"""
Bounty manager for the bug bounty module.
Tracks submissions, rewards, and program integrations.
"""

import json
import logging
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import List, Dict, Optional

from .scanner import ScanResult

logger = logging.getLogger(__name__)


class SubmissionStatus(Enum):
    DRAFT = "draft"
    SUBMITTED = "submitted"
    TRIAGED = "triaged"
    RESOLVED = "resolved"
    DUPLICATE = "duplicate"
    REJECTED = "rejected"
    BOUNTY_AWARDED = "bounty_awarded"


@dataclass
class BountySubmission:
    """Represents a single bug bounty submission."""
    id: str
    scan_result_id: str
    target: str
    program: str
    status: str = "draft"
    severity: str = ""
    reward: Optional[float] = None
    submitted_at: Optional[str] = None
    resolved_at: Optional[str] = None
    notes: str = ""


@dataclass
class BountyProgram:
    """Configuration for a bug bounty platform."""
    name: str
    platform: str
    scope: List[str] = field(default_factory=list)
    out_of_scope: List[str] = field(default_factory=list)
    min_bounty: float = 0.0
    max_bounty: float = 0.0
    url: str = ""
    api_key_env: str = ""

    def is_in_scope(self, target: str) -> bool:
        """Check if a target is within the program scope."""
        for pattern in self.scope:
            if pattern in target or target in pattern:
                return True
        return False


class BountyManager:
    """
    Manages bug bounty program interactions, submission tracking,
    and reward monitoring.
    """

    KNOWN_PROGRAMS: Dict[str, BountyProgram] = {
        "hackerone": BountyProgram(
            name="HackerOne",
            platform="hackerone",
            url="https://api.hackerone.com/v1",
            api_key_env="HACKERONE_API_TOKEN",
        ),
        "bugcrowd": BountyProgram(
            name="Bugcrowd",
            platform="bugcrowd",
            url="https://docs.bugcrowd.com/reference",
            api_key_env="BUGCROWD_API_TOKEN",
        ),
    }

    def __init__(self, config=None):
        self.config = config
        self.submissions: List[BountySubmission] = []
        self._state_file = os.path.join(
            os.environ.get("ROBIN_DATA_DIR", "."),
            "bug_bounty_state.json",
        )
        self._load_state()

    def submit(self, result: ScanResult, program: str = "") -> Optional[BountySubmission]:
        """
        Submit a scan result to a bug bounty program.
        If program is empty, tries to find a matching program by scope.
        """
        program_name = program or self._find_matching_program(result.target)
        if not program_name:
            logger.warning("No matching bug bounty program for target: %s", result.target)
            return None

        submission = BountySubmission(
            id=f"sub-{result.id}",
            scan_result_id=result.id,
            target=result.target,
            program=program_name,
            severity=result.severity,
            submitted_at=datetime.utcnow().isoformat() + "Z",
            status=SubmissionStatus.SUBMITTED.value,
        )

        # In production, this would call the actual platform API
        logger.info(
            "Submitting finding %s to %s (severity: %s)",
            result.id,
            program_name,
            result.severity,
        )

        self.submissions.append(submission)
        self._save_state()
        return submission

    def update_submission_status(
        self, submission_id: str, status: SubmissionStatus, reward: Optional[float] = None
    ) -> Optional[BountySubmission]:
        """Update the status of an existing submission."""
        for sub in self.submissions:
            if sub.id == submission_id:
                sub.status = status.value
                if reward is not None:
                    sub.reward = reward
                if status in (SubmissionStatus.RESOLVED, SubmissionStatus.BOUNTY_AWARDED):
                    sub.resolved_at = datetime.utcnow().isoformat() + "Z"
                self._save_state()
                logger.info("Updated submission %s -> %s", submission_id, status.value)
                return sub
        logger.warning("Submission not found: %s", submission_id)
        return None

    def get_summary(self) -> Dict:
        """Get a summary of all submissions and rewards."""
        total_reward = sum(s.reward or 0 for s in self.submissions)
        by_status: Dict[str, int] = {}
        for s in self.submissions:
            by_status[s.status] = by_status.get(s.status, 0) + 1
        return {
            "total_submissions": len(self.submissions),
            "total_reward": total_reward,
            "by_status": by_status,
            "programs_active": len(set(s.program for s in self.submissions)),
        }

    def _find_matching_program(self, target: str) -> Optional[str]:
        """Find a bug bounty program that includes the target in its scope."""
        for name, program in self.KNOWN_PROGRAMS.items():
            if program.is_in_scope(target):
                return name
        return None

    def _load_state(self):
        """Load submission state from disk."""
        if os.path.exists(self._state_file):
            try:
                with open(self._state_file, "r") as f:
                    data = json.load(f)
                    self.submissions = [
                        BountySubmission(**item) for item in data.get("submissions", [])
                    ]
                logger.info("Loaded %d submissions from state file.", len(self.submissions))
            except Exception as exc:
                logger.error("Failed to load state: %s", exc)

    def _save_state(self):
        """Persist submission state to disk."""
        try:
            data = {
                "submissions": [asdict(s) for s in self.submissions],
                "last_updated": datetime.utcnow().isoformat() + "Z",
            }
            os.makedirs(os.path.dirname(self._state_file) or ".", exist_ok=True)
            with open(self._state_file, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as exc:
            logger.error("Failed to save state: %s", exc)
