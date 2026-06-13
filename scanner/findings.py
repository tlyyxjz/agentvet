"""Finding data models for scan results."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """A single security finding from a scan."""

    rule_id: str
    title: str
    severity: Severity
    file_path: str
    line_number: int
    description: str
    code_snippet: str = ""
    attack_demo: str = ""
    fix_suggestion: str = ""
    owasp_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "description": self.description,
            "code_snippet": self.code_snippet,
            "attack_demo": self.attack_demo,
            "fix_suggestion": self.fix_suggestion,
            "owasp_ids": self.owasp_ids,
        }


@dataclass
class ScanReport:
    """Complete scan report for a target directory."""

    target: str
    findings: list[Finding] = field(default_factory=list)
    total_checks: int = 0
    duration_ms: float = 0.0
    l2_filtered_count: int = 0
    l2_verdicts: list = field(default_factory=list)
    l2_model: str = ""
    l2_duration_ms: float = 0.0
    l3_audited_count: int = 0
    l3_model: str = ""
    l3_duration_ms: float = 0.0
    # L4 attack chain synthesis
    chain: object = None
    chain_model: str = ""
    chain_duration_ms: float = 0.0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def score(self) -> str:
        """Letter grade based on findings."""
        total = self.critical_count * 10 + self.high_count * 4 + self.medium_count * 1
        if total == 0:
            return "A+"
        elif total <= 2:
            return "A"
        elif total <= 5:
            return "B"
        elif total <= 10:
            return "C"
        elif total <= 20:
            return "D"
        return "F"

    @property
    def owasp_coverage(self) -> dict[str, int]:
        """Count findings per OWASP category."""
        counts: dict[str, int] = {}
        for f in self.findings:
            for oid in f.owasp_ids:
                counts[oid] = counts.get(oid, 0) + 1
        return counts

    def fails_on(self, minimum_severity: str) -> bool:
        """Whether this report fails a CI gate at the given severity threshold."""
        order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        threshold = order.get(minimum_severity, 4)
        for f in self.findings:
            if order.get(f.severity.value, 0) >= threshold:
                return True
        return False

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "score": self.score,
            "total_checks": self.total_checks,
            "duration_ms": self.duration_ms,
            "summary": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "total": len(self.findings),
            },
            "findings": [f.to_dict() for f in self.findings],
            "owasp_coverage": self.owasp_coverage,
            "attack_chain": self._chain_to_dict(),
        }

    def _chain_to_dict(self) -> dict | None:
        if not self.chain:
            return None
        c = self.chain
        return {
            "campaign_name": c.campaign_name,
            "executive_summary": c.executive_summary,
            "risk_level": c.risk_level,
            "stages": [
                {
                    "stage": s.stage,
                    "stage_name": s.stage_name,
                    "entry_point": s.entry_point,
                    "technique": s.technique,
                    "what_attacker_gains": s.what_attacker_gains,
                    "enables_next_stage": s.enables_next_stage,
                    "prerequisites": s.prerequisites,
                    "detection_difficulty": s.detection_difficulty,
                }
                for s in c.stages
            ],
            "total_impact": c.total_impact,
            "mitigation_priority": c.mitigation_priority,
        }
