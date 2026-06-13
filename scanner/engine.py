"""Rule engine — loads and runs security rules against target code."""

import ast
import fnmatch
import logging
import os
import re
import time
from pathlib import Path
from typing import Iterable, Optional

from .findings import Finding, ScanReport

logger = logging.getLogger(__name__)


class Rule:
    """Base class for all scanning rules."""

    rule_id: str = ""
    title: str = ""
    description: str = ""
    file_patterns: list[str] = ["*.py"]  # glob patterns for files to scan

    def check(self, file_path: str, content: str) -> list[Finding]:
        """Run this rule against a single file. Override in subclasses."""
        return []


class RegexRule(Rule):
    """Rule that scans file content with regex patterns."""

    patterns: list[tuple[str, str]] = []  # (regex, description)

    def check(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        lines = content.split("\n")
        for pattern, desc in self.patterns:
            for i, line in enumerate(lines, start=1):
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            title=self.title,
                            severity=self._severity(),
                            file_path=file_path,
                            line_number=i,
                            description=desc,
                            code_snippet=self._get_context(lines, i),
                            fix_suggestion=self.fix_suggestion(),
                        )
                    )
        return findings

    def _severity(self):
        from .findings import Severity

        return Severity.MEDIUM

    def _get_context(self, lines: list[str], line_no: int, context: int = 3) -> str:
        start = max(0, line_no - context - 1)
        end = min(len(lines), line_no + context)
        return "\n".join(f"{i+1}: {l}" for i, l in enumerate(lines[start:end], start=start))

    def fix_suggestion(self) -> str:
        return ""


class ASTRule(Rule):
    """Rule that analyzes Python AST for structural vulnerabilities."""

    def check(self, file_path: str, content: str) -> list[Finding]:
        try:
            tree = ast.parse(content)
            return self.check_ast(file_path, content, tree)
        except SyntaxError:
            return []

    def check_ast(self, file_path: str, content: str, tree: ast.AST) -> list[Finding]:
        return []


class ScanEngine:
    """Orchestrates scanning a target directory with all registered rules.

    Three-tier detection:
      L1 — regex + AST (fast, broad, some noise)
      L2 — local LLM semantic filter (slower, removes false positives)
      L3 — DeepSeek deep audit (attack path analysis on confirmed HIGH/CRITICAL)
    """

    # Directories skipped during file collection
    SKIP_DIRS: set[str] = {
        "node_modules", ".git", "__pycache__", ".venv", "venv",
        "dist", "build", ".next", "egg-info", ".tox",
        "targets", ".tmp", "plugins", "archive", "reports",
    }

    def __init__(self, rules: Optional[list[Rule]] = None, use_l2: bool = True, use_l3: bool = True):
        self.rules = rules or self._default_rules()
        self.use_l2 = use_l2
        self.use_l3 = use_l3
        self._l2_filter = None  # lazy init
        self._l3_auditor = None  # lazy init

    def _default_rules(self) -> list[Rule]:
        from .rules.prompt_injection import (
            DirectInputConcatRule,
            MissingInputSanitization,
            NoSystemDefenseRule,
        )
        from .rules.tool_auth import (
            HighRiskToolNoConfirmRule,
            MissingToolPermissionRule,
        )
        from .rules.data_leak import (
            LogSensitiveDataRule,
            ExternalServiceNoAuditRule,
        )

        return [
            # Prompt injection
            DirectInputConcatRule(),
            MissingInputSanitization(),
            NoSystemDefenseRule(),
            # Tool authorization
            HighRiskToolNoConfirmRule(),
            MissingToolPermissionRule(),
            # Data leakage
            LogSensitiveDataRule(),
            ExternalServiceNoAuditRule(),
        ]

    def scan(self, target: str, file_patterns: Optional[list[str]] = None) -> ScanReport:
        """Scan a target directory or file and return a report."""
        start = time.perf_counter()
        report = ScanReport(target=target)

        target_path = Path(target)
        if not target_path.exists():
            report.findings.append(
                Finding(
                    rule_id="engine",
                    title="Target not found",
                    severity="info",
                    file_path=target,
                    line_number=0,
                    description=f"Path does not exist: {target}",
                )
            )
            return report

        files_to_scan = self._collect_files(target_path, file_patterns)
        report.total_checks = len(self.rules) * len(files_to_scan)

        for file_path in files_to_scan:
            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                logger.warning("Could not read %s, skipping", file_path, exc_info=True)
                continue

            # Skip minified files — regex patterns produce noise
            if self._is_minified(file_path, content):
                continue

            for rule in self.rules:
                if not self._matches_pattern(file_path, rule.file_patterns):
                    continue
                try:
                    findings = rule.check(str(file_path), content)
                    report.findings.extend(findings)
                except Exception:
                    logger.warning("Rule %s failed on %s", rule.rule_id, file_path, exc_info=True)
                    continue  # one bad rule shouldn't kill the scan

        # ── L2 semantic filter ──────────────────────────────────
        l2_dropped = 0
        if self.use_l2 and report.findings:
            if self._l2_filter is None:
                from .l2_filter import L2Filter

                self._l2_filter = L2Filter()
            l2_result = self._l2_filter.filter(report.findings)
            l2_dropped = len(l2_result.dropped)
            report.findings = l2_result.kept
            report.l2_verdicts = l2_result.verdicts
            report.l2_model = l2_result.model
            report.l2_duration_ms = l2_result.duration_ms

        # ── L3 deep audit ──────────────────────────────────────
        l3_audited = 0
        if self.use_l3 and report.findings:
            if self._l3_auditor is None:
                from .l3_audit import L3DeepAudit

                self._l3_auditor = L3DeepAudit()
            if self._l3_auditor.api_key:
                l3_report = self._l3_auditor.audit(report.findings)
                l3_audited = len(l3_report.audited)
                report.l3_model = l3_report.model
                report.l3_duration_ms = l3_report.total_duration_ms
                # Merge L3 results into findings
                self._l3_auditor.enrich(report.findings)

        report.duration_ms = (time.perf_counter() - start) * 1000
        report.l2_filtered_count = l2_dropped
        report.l3_audited_count = l3_audited
        return report

    def _is_minified(self, file_path: Path, content: str) -> bool:
        """Heuristic: detect minified/bundled files to skip."""
        name = file_path.name.lower()
        # .min.js / .min.css
        if ".min." in name:
            return True
        # Files in directories named 'Min' or 'min'
        if "Min" in str(file_path.parent) or "min" in file_path.parent.name.split("/"):
            return True
        # Single-line file longer than 500 chars is almost certainly minified
        lines = content.split("\n")
        if len(lines) < 3 and sum(len(l) for l in lines) > 500:
            return True
        # Files with average line > 400 chars
        if len(lines) > 0 and (len(content) / len(lines)) > 400:
            return True
        return False

    def _collect_files(self, target: Path, file_patterns: Optional[list[str]]) -> list[Path]:
        """Collect files to scan."""
        patterns = file_patterns or ["*.py", "*.js", "*.ts", "*.tsx", "*.jsx"]

        if target.is_file():
            return [target]

        files = []
        for root, dirs, _ in os.walk(target):
            # Skip common non-source directories
            dirs[:] = [d for d in dirs if d not in self.SKIP_DIRS]

            for filename in os.listdir(root):
                for pat in patterns:
                    if fnmatch.fnmatch(filename, pat):
                        files.append(Path(root) / filename)
                        break

        return files

    def _matches_pattern(self, file_path: Path, patterns: list[str]) -> bool:
        """Check if file matches any of the given patterns."""
        filename = file_path.name
        return any(fnmatch.fnmatch(filename, p) for p in patterns)

    @classmethod
    def quick_scan(cls, target: str) -> ScanReport:
        """One-liner: Scan a target with default rules."""
        engine = cls()
        return engine.scan(target)
