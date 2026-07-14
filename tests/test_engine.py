"""Tests for the scan engine: file collection, minified detection, dedup,
and the overall scan flow."""
import os
import tempfile
from pathlib import Path

import pytest

from scanner.engine import ScanEngine
from scanner.findings import Finding, Severity


# ── helpers ───────────────────────────────────────────────────

@pytest.fixture
def tmp_project(tmp_path):
    """Create a tiny project with a few source files."""
    (tmp_path / "agent.py").write_text(
        'API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz012345"\n', encoding="utf-8"
    )
    (tmp_path / "utils.py").write_text(
        'def hello():\n    print("hi")\n', encoding="utf-8"
    )
    # A minified file that should be skipped
    (tmp_path / "bundle.min.js").write_text(
        'var x=1;function f(){return x*2+3+4+5+6+7+8+9+10+11+12+13+14+15+16+17+18+19+20;'
        'function g(){return f()+1+2+3+4+5+6+7+8+9+10+11+12+13+14+15+16+17+18+19+20+21+22;}',
        encoding="utf-8",
    )
    return tmp_path


# ── _collect_files ────────────────────────────────────────────

class TestCollectFiles:
    def test_collects_py_and_js(self, tmp_project):
        engine = ScanEngine(use_l2=False, use_l3=False, use_l4=False)
        files = engine._collect_files(tmp_project, None)
        names = {f.name for f in files}
        assert "agent.py" in names
        assert "utils.py" in names
        assert "bundle.min.js" in names

    def test_single_file_target(self, tmp_project):
        engine = ScanEngine(use_l2=False, use_l3=False, use_l4=False)
        target = tmp_project / "agent.py"
        files = engine._collect_files(target, None)
        assert files == [target]

    def test_skip_dirs_excluded(self, tmp_project):
        (tmp_project / "__pycache__").mkdir()
        (tmp_project / "__pycache__" / "junk.pyc").write_text("garbage", encoding="utf-8")
        engine = ScanEngine(use_l2=False, use_l3=False, use_l4=False)
        files = engine._collect_files(tmp_project, None)
        assert not any("__pycache__" in str(f) for f in files)


# ── _is_minified ──────────────────────────────────────────────

class TestIsMinified:
    def test_min_js_detected(self, tmp_path):
        engine = ScanEngine(use_l2=False, use_l3=False, use_l4=False)
        f = tmp_path / "code.min.js"
        f.write_text("x=1", encoding="utf-8")
        assert engine._is_minified(f, "x=1") is True

    def test_normal_py_not_minified(self, tmp_path):
        engine = ScanEngine(use_l2=False, use_l3=False, use_l4=False)
        f = tmp_path / "agent.py"
        content = "def hello():\n    print('hi')\n    return 42\n"
        f.write_text(content, encoding="utf-8")
        assert engine._is_minified(f, content) is False


# ── scan: dedup ───────────────────────────────────────────────

class TestScanDedup:
    def test_sec001_dedup_same_line(self, tmp_path):
        """SEC-001 has 2 patterns that match the same line — engine dedup
        should collapse them to 1 finding."""
        f = tmp_path / "secrets.py"
        f.write_text(
            'API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz012345"\n',
            encoding="utf-8",
        )
        engine = ScanEngine(use_l2=False, use_l3=False, use_l4=False)
        report = engine.scan(str(f))
        sec001 = [x for x in report.findings if x.rule_id == "SEC-001"]
        assert len(sec001) == 1, f"Expected 1 SEC-001 finding, got {len(sec001)}"


# ── scan: missing target ──────────────────────────────────────

class TestScanMissingTarget:
    def test_missing_target_returns_report(self):
        engine = ScanEngine(use_l2=False, use_l3=False, use_l4=False)
        report = engine.scan("/nonexistent/path/that/does/not/exist")
        assert report.findings
        assert any("not found" in f.description.lower() or "does not exist" in f.description.lower()
                    for f in report.findings)


# ── scan: end-to-end on a single file ─────────────────────────

class TestScanSingleFile:
    def test_finds_hardcoded_key(self, tmp_path):
        f = tmp_path / "leak.py"
        f.write_text(
            'API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz012345"\n',
            encoding="utf-8",
        )
        engine = ScanEngine(use_l2=False, use_l3=False, use_l4=False)
        report = engine.scan(str(f))
        assert any(x.rule_id == "SEC-001" for x in report.findings)


# ── rule discovery ────────────────────────────────────────────

class TestRuleDiscovery:
    def test_discovers_all_rules(self):
        engine = ScanEngine(use_l2=False, use_l3=False, use_l4=False)
        rule_ids = {r.rule_id for r in engine.rules}
        # The 22 documented rules
        expected = {
            "PI-001", "PI-002", "PI-003", "PI-004",
            "TA-001", "TA-002", "TA-003",
            "DL-001", "DL-002",
            "FW-001", "FW-002", "FW-003", "FW-004",
            "SEC-001", "SEC-002", "SEC-003",
            "MCP-001", "MCP-002", "MCP-003", "MCP-004",
            "SC-001", "SC-002",
        }
        missing = expected - rule_ids
        assert not missing, f"Missing rules: {missing}"
        assert len(rule_ids) >= 22

    def test_all_rules_have_required_fields(self):
        engine = ScanEngine(use_l2=False, use_l3=False, use_l4=False)
        for rule in engine.rules:
            assert rule.rule_id, f"Rule {rule.__class__.__name__} has no rule_id"
            assert rule.title, f"Rule {rule.rule_id} has no title"
            assert rule.description, f"Rule {rule.rule_id} has no description"
            assert len(rule.description) >= 30, f"Rule {rule.rule_id} description too short"
            assert rule.file_patterns, f"Rule {rule.rule_id} has no file_patterns"
            assert rule.owasp_ids, f"Rule {rule.rule_id} has no owasp_ids"
            assert rule.fix_suggestion(), f"Rule {rule.rule_id} has no fix_suggestion"
            assert rule._severity() in Severity, f"Rule {rule.rule_id} has invalid severity"
