"""Tests for the vulnerable and safe fixtures.

Vulnerable fixtures (6 files) — each MUST produce at least one finding
for its target rule.
Safe fixtures (6 files) — each MUST produce 0 findings total.
"""
from pathlib import Path

from scanner.engine import ScanEngine

FIXTURES = Path(__file__).resolve().parent / "fixtures"
VULN = FIXTURES / "vulnerable"
SAFE = FIXTURES / "safe"


def _scan(fixture_path: Path):
    """Scan a single fixture file with L1 only (no L2/L3/L4)."""
    engine = ScanEngine(use_l2=False, use_l3=False, use_l4=False)
    return engine.scan(str(fixture_path))


# ── vulnerable fixtures ───────────────────────────────────────

class TestVulnerableFixtures:
    """Each vulnerable fixture must be detected by its target rule."""

    def test_pi_001_concat(self):
        report = _scan(VULN / "pi_001_concat.py")
        assert any(f.rule_id == "PI-001" for f in report.findings), \
            "PI-001 not detected on pi_001_concat.py"

    def test_ta_001_no_confirm(self):
        report = _scan(VULN / "ta_001_no_confirm.py")
        assert any(f.rule_id == "TA-001" for f in report.findings), \
            "TA-001 not detected on ta_001_no_confirm.py"

    def test_sec_001_hardcoded_key(self):
        report = _scan(VULN / "sec_001_hardcoded_key.py")
        assert any(f.rule_id == "SEC-001" for f in report.findings), \
            "SEC-001 not detected on sec_001_hardcoded_key.py"

    def test_sec_002_aws_key(self):
        report = _scan(VULN / "sec_002_aws_key.py")
        assert any(f.rule_id == "SEC-002" for f in report.findings), \
            "SEC-002 not detected on sec_002_aws_key.py"

    def test_mcp_001_no_auth(self):
        report = _scan(VULN / "mcp_001_no_auth.json")
        assert any(f.rule_id == "MCP-001" for f in report.findings), \
            "MCP-001 not detected on mcp_001_no_auth.json"

    def test_fw_001_no_docker(self):
        report = _scan(VULN / "fw_001_no_docker.py")
        assert any(f.rule_id == "FW-002" for f in report.findings), \
            "FW-002 not detected on fw_001_no_docker.py"


# ── safe fixtures ─────────────────────────────────────────────

class TestSafeFixtures:
    """Each safe fixture must produce 0 findings (no false positives)."""

    def test_pi_001_ok(self):
        report = _scan(SAFE / "pi_001_ok.py")
        assert len(report.findings) == 0, \
            f"Safe fixture pi_001_ok.py has {len(report.findings)} findings: " \
            f"{[(f.rule_id, f.line_number) for f in report.findings]}"

    def test_ta_001_ok(self):
        report = _scan(SAFE / "ta_001_ok.py")
        assert len(report.findings) == 0, \
            f"Safe fixture ta_001_ok.py has {len(report.findings)} findings: " \
            f"{[(f.rule_id, f.line_number) for f in report.findings]}"

    def test_sec_001_ok(self):
        report = _scan(SAFE / "sec_001_ok.py")
        assert len(report.findings) == 0, \
            f"Safe fixture sec_001_ok.py has {len(report.findings)} findings: " \
            f"{[(f.rule_id, f.line_number) for f in report.findings]}"

    def test_sec_002_ok(self):
        report = _scan(SAFE / "sec_002_ok.py")
        assert len(report.findings) == 0, \
            f"Safe fixture sec_002_ok.py has {len(report.findings)} findings: " \
            f"{[(f.rule_id, f.line_number) for f in report.findings]}"

    def test_mcp_001_ok(self):
        report = _scan(SAFE / "mcp_001_ok.json")
        assert len(report.findings) == 0, \
            f"Safe fixture mcp_001_ok.json has {len(report.findings)} findings: " \
            f"{[(f.rule_id, f.line_number) for f in report.findings]}"

    def test_fw_001_ok(self):
        report = _scan(SAFE / "fw_001_ok.py")
        assert len(report.findings) == 0, \
            f"Safe fixture fw_001_ok.py has {len(report.findings)} findings: " \
            f"{[(f.rule_id, f.line_number) for f in report.findings]}"


# ── full fixture directory scans ──────────────────────────────

class TestFixtureDirectoryScan:
    def test_vulnerable_directory_has_findings(self):
        engine = ScanEngine(use_l2=False, use_l3=False, use_l4=False)
        report = engine.scan(str(VULN))
        assert len(report.findings) > 0, "Vulnerable directory should have findings"

    def test_safe_directory_has_zero_findings(self):
        engine = ScanEngine(use_l2=False, use_l3=False, use_l4=False)
        report = engine.scan(str(SAFE))
        assert len(report.findings) == 0, \
            f"Safe directory should have 0 findings, got {len(report.findings)}: " \
            f"{[(f.rule_id, f.file_path, f.line_number) for f in report.findings]}"
