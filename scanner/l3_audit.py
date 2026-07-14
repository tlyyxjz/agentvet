"""L3 deep audit layer — uses DeepSeek API to analyze attack paths.

Runs on HIGH/CRITICAL findings that survived L2 filtering.
Generates: attack path analysis, exploit demo, detailed fix recommendation.

One finding per API call — deep analysis needs full file context.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

import requests

from .findings import Finding, Severity

logger = logging.getLogger(__name__)

# ── config ──────────────────────────────────────────────────────────

DEEPSEEK_CHAT = os.environ.get(
    "DEEPSEEK_BASE_URL",
    "https://api.deepseek.com/v1/chat/completions",
)
DEEPSEEK_BASE = "https://api.deepseek.com"  # kept for health check
DEFAULT_MODEL = os.environ.get("DEEPSEEK_MODEL", "deepseek-chat")

# Only audit these severities (skip MEDIUM/LOW/INFO to save cost)
AUDITABLE_SEVERITIES = {Severity.CRITICAL, Severity.HIGH}

AUDIT_PROMPT = """You are a senior penetration tester reviewing a confirmed security vulnerability in an AI agent codebase.

Analyze this finding and produce a deep audit report. Your report MUST be valid JSON with these fields:
- "attack_path": Step-by-step attack narrative. Explain how an attacker would discover, reach, and exploit this vulnerability. Be concrete — mention specific code patterns, attack vectors, and tools. For prompt injection: show the exact malicious input. For tool auth: show the privilege escalation chain. For data leak: show the exfiltration path.
- "exploit_demo": A concrete code example demonstrating the exploit. For prompt injection, show the crafted user input. For tool auth bypass, show the attack sequence. Make it realistic and reproducible.
- "impact": What the attacker gains — data accessed, commands executed, privileges obtained. Quantify where possible.
- "cvss_vector": A rough CVSS 3.1 vector string (e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).
- "fix": A specific, actionable fix with code. Show the before/after diff or the exact code change needed. This should be production-ready.

Respond ONLY with valid JSON, no markdown, no extra text:
{{"attack_path": "...", "exploit_demo": "...", "impact": "...", "cvss_vector": "...", "fix": "..."}}

Finding to analyze:
Rule: {rule_id} — {title}
Severity: {severity}
File: {file_path}:{line_number}
Description: {description}

Code context (lines around the vulnerability):
{code_snippet}

Full file content for deeper analysis:
{full_file}"""


@dataclass
class L3AuditResult:
    attack_path: str = ""
    exploit_demo: str = ""
    impact: str = ""
    cvss_vector: str = ""
    fix: str = ""
    model: str = ""
    duration_ms: float = 0


@dataclass
class L3Report:
    audited: list[tuple[Finding, L3AuditResult]] = field(default_factory=list)
    skipped: list[Finding] = field(default_factory=list)
    failed: list[Finding] = field(default_factory=list)
    model: str = ""
    total_duration_ms: float = 0


class L3DeepAudit:
    """Deep audit using DeepSeek API. One finding per call for depth."""

    def __init__(
        self,
        api_key: str = "",
        model: str = DEFAULT_MODEL,
        base_url: str = DEEPSEEK_CHAT,
        enabled: bool = True,
        max_file_bytes: int = 32_000,  # max file content to include
    ):
        self.api_key = api_key or os.environ.get("DEEPSEEK_API_KEY") or ""
        self.model = model
        self.base_url = base_url
        self.enabled = enabled
        self.max_file_bytes = max_file_bytes

    # ── public API ─────────────────────────────────────────────────

    def audit(self, findings: list[Finding]) -> L3Report:
        """Deep-audit findings that survived L2.

        Only HIGH/CRITICAL findings are audited (cost optimization).
        MEDIUM/LOW/INFO are placed in skipped.
        """
        t0 = time.perf_counter()
        report = L3Report(model=self.model)

        if not self.enabled:
            report.skipped = list(findings)
            return report

        if not self.api_key:
            report.skipped = list(findings)
            return report

        for finding in findings:
            if finding.severity not in AUDITABLE_SEVERITIES:
                report.skipped.append(finding)
                continue

            try:
                result = self._audit_one(finding)
                report.audited.append((finding, result))
            except Exception:
                logger.warning("L3 audit failed for %s", finding.rule_id, exc_info=True)
                report.failed.append(finding)

        report.total_duration_ms = (time.perf_counter() - t0) * 1000
        return report

    def enrich(self, findings: list[Finding]) -> list[Finding]:
        """Audit and merge results back into findings (attack_demo + fix_suggestion)."""
        report = self.audit(findings)

        for finding, result in report.audited:
            if result.attack_path:
                finding.attack_demo = (
                    f"## Attack Path\n{result.attack_path}\n\n"
                    f"## Exploit Demo\n{result.exploit_demo}\n\n"
                    f"## Impact\n{result.impact}\n\n"
                    f"## CVSS\n{result.cvss_vector}"
                )
            if result.fix:
                # Prepend L3 fix to existing suggestion
                existing = finding.fix_suggestion
                finding.fix_suggestion = (
                    f"[L3 DeepSeek Analysis]\n{result.fix}"
                    + (f"\n\n[L1 Suggestion]\n{existing}" if existing else "")
                )

        return findings

    # ── internals ──────────────────────────────────────────────────

    def _audit_one(self, finding: Finding) -> L3AuditResult:
        t0 = time.perf_counter()

        # Read full file for deep context
        full_file = self._read_file(finding.file_path)

        prompt = AUDIT_PROMPT.format(
            rule_id=finding.rule_id,
            title=finding.title,
            severity=finding.severity.value,
            file_path=finding.file_path,
            line_number=finding.line_number,
            description=finding.description,
            code_snippet=finding.code_snippet,
            full_file=full_file,
        )

        resp = requests.post(
            self.base_url,
            json={
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1,
                "max_tokens": 4096,
            },
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            timeout=120,
        )
        resp.raise_for_status()
        body = resp.json()
        raw = body["choices"][0]["message"]["content"]

        parsed = self._parse_response(raw)

        return L3AuditResult(
            attack_path=parsed.get("attack_path", ""),
            exploit_demo=parsed.get("exploit_demo", ""),
            impact=parsed.get("impact", ""),
            cvss_vector=parsed.get("cvss_vector", ""),
            fix=parsed.get("fix", ""),
            model=self.model,
            duration_ms=(time.perf_counter() - t0) * 1000,
        )

    def _read_file(self, file_path: str) -> str:
        """Read file content, truncated to max_file_bytes."""
        try:
            path = Path(file_path).resolve()
            # Prevent path traversal — reject paths outside allowed roots.
            # The old check (`if ".." in str(path)`) was ineffective because
            # Path.resolve() already collapses `..` components, so the
            # substring check never matched. Instead, verify the resolved
            # path lives under one of the configured audit roots.
            if not self._is_within_allowed_roots(path):
                return f"[Path traversal blocked: {file_path}]"
            if not path.exists():
                return f"[File not found: {file_path}]"
            content = path.read_text(encoding="utf-8", errors="replace")
            if len(content) > self.max_file_bytes:
                # Keep head and tail for context
                half = self.max_file_bytes // 2
                content = content[:half] + "\n... [truncated] ...\n" + content[-half:]
            return content
        except Exception:
            logger.warning("Could not read %s for L3 audit", file_path, exc_info=True)
            return f"[Could not read: {file_path}]"

    @staticmethod
    def _is_within_allowed_roots(path: Path) -> bool:
        """Return True if *path* lives under one of the allowed audit roots.

        Roots are read from the ``AGENTVET_AUDIT_ROOTS`` env var
        (comma-separated, OS path separator tolerant). When unset, the
        current working directory is used as the only root — which is the
        safe default because L3 audits files that were found during a scan
        launched from that directory.
        """
        env_roots = os.environ.get("AGENTVET_AUDIT_ROOTS", "")
        if env_roots.strip():
            roots = [Path(r.strip()).resolve() for r in env_roots.split(",") if r.strip()]
        else:
            roots = [Path.cwd().resolve()]
        try:
            for root in roots:
                # is_relative_to would be cleaner, but only exists on 3.9+.
                # Use relative_to with a try/except for broader compat.
                path.relative_to(root)
                return True
        except ValueError:
            pass
        return False

    def _parse_response(self, raw: str) -> dict:
        """Extract JSON from DeepSeek response."""
        # Find JSON object in response
        match = re.search(r"\{[\s\S]*\}", raw)
        if not match:
            return {}

        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            # Clean common issues
            cleaned = re.sub(r"//.*?\n", "\n", match.group())
            cleaned = re.sub(r",\s*}", "}", cleaned)
            cleaned = re.sub(r",\s*]", "]", cleaned)
            try:
                return json.loads(cleaned)
            except json.JSONDecodeError:
                return {}

    def check_health(self) -> bool:
        """Verify API key is valid by listing models (lightweight call)."""
        if not self.api_key:
            return False
        try:
            resp = requests.get(
                f"{DEEPSEEK_BASE}/v1/models",
                headers={"Authorization": f"Bearer {self.api_key}"},
                timeout=10,
            )
            return resp.status_code == 200
        except Exception:
            logger.warning("L3 health check failed", exc_info=True)
            return False
