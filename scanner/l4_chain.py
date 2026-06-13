"""L4 attack chain synthesis — the AgentVet differentiator.

While every other scanner stops at "here are your vulnerabilities,"
AgentVet asks: "how would an attacker chain these together?"

Takes all HIGH/CRITICAL findings from L3 and sends them to DeepSeek
in a single prompt that demands attacker-perspective chain analysis.

The result is a red-team playbook: Step 1 → Step 2 → Step 3,
with each step referencing specific code locations and findings.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Optional

import requests

from .findings import Finding, Severity

logger = logging.getLogger(__name__)

DEEPSEEK_CHAT = os.environ.get(
    "DEEPSEEK_BASE_URL",
    "https://api.deepseek.com/v1/chat/completions",
)
DEFAULT_MODEL = os.environ.get("DEEPSEEK_MODEL", "deepseek-chat")

# Only findings at or above this severity participate in chain analysis
CHAINABLE_SEVERITIES = {Severity.CRITICAL, Severity.HIGH}

CHAIN_PROMPT = """You are a red-team penetration tester. You have just finished a security audit of an AI agent codebase and found the following vulnerabilities.

Your job: figure out how an attacker would CHAIN these vulnerabilities together — not just exploit each one in isolation, but combine them into a multi-stage attack campaign.

Think like an attacker:
- Which vulnerability do you exploit FIRST to get a foothold?
- What does that first exploit give you that enables the NEXT step?
- How do you escalate from "annoying the AI" to "owning the server"?
- What's the full kill chain from initial access to final impact?

Vulnerabilities found:

{findings_text}

Respond with a single JSON object — no markdown, no extra text:

{{
  "campaign_name": "A memorable name for this attack campaign (like a CTF challenge name or APT campaign name)",
  "executive_summary": "2-3 sentences: what the attacker achieves end-to-end, in plain language a CTO would understand",
  "risk_level": "CRITICAL|HIGH|MEDIUM|LOW",
  "attack_chain": [
    {{
      "stage": 1,
      "stage_name": "Short name for this stage",
      "entry_point": "Which vulnerability starts this chain? Reference the finding ID and file:line",
      "technique": "What the attacker does — be specific. Show the malicious input, the curl command, the crafted payload",
      "what_attacker_gains": "What capability or data the attacker acquires at this stage",
      "enables_next_stage": "How this gain unlocks the next stage. If this is the final stage, describe the ultimate impact",
      "prerequisites": "What the attacker needs before this stage (e.g., 'valid user account', 'network access to port 8765')",
      "detection_difficulty": "How hard is this to detect? Consider logs, alerts, anomalous patterns"
    }}
  ],
  "total_impact": {{
    "data_exposed": "What data can the attacker access? Be specific about types of data",
    "systems_compromised": "What systems or services fall under attacker control?",
    "business_impact": "What does this mean for the organization? Revenue loss, compliance violation, reputational damage?",
    "cvss_chain_score": "Estimated CVSS 3.1 vector for the WORST outcome of the full chain (not individual vulns)"
  }},
  "mitigation_priority": [
    {{
      "order": 1,
      "action": "The single most impactful fix — the one that breaks the entire chain",
      "finding_ids": ["RULE-ID that this fix addresses"],
      "effort": "LOW|MEDIUM|HIGH — how much work to implement"
    }}
  ]
}}

Rules:
- Every stage MUST reference specific findings by their rule_id
- Every technique MUST be concrete — show the actual attack, not theory
- If vulnerabilities CANNOT be chained (they're independent), say so and explain why
- The campaign_name should be memorable — think "Operation Iron Saddle" or "Vector Glide" style
- mitigation_priority must be ordered: the FIRST item should be the fix that breaks the MOST of the chain"""


@dataclass
class ChainStage:
    stage: int
    stage_name: str = ""
    entry_point: str = ""
    technique: str = ""
    what_attacker_gains: str = ""
    enables_next_stage: str = ""
    prerequisites: str = ""
    detection_difficulty: str = ""


@dataclass
class AttackChain:
    campaign_name: str = ""
    executive_summary: str = ""
    risk_level: str = ""
    stages: list[ChainStage] = field(default_factory=list)
    total_impact: dict = field(default_factory=dict)
    mitigation_priority: list[dict] = field(default_factory=list)


@dataclass
class ChainReport:
    chain: Optional[AttackChain] = None
    findings_analyzed: int = 0
    model: str = ""
    duration_ms: float = 0
    error: str = ""


class L4ChainAnalyzer:
    """Cross-finding attack chain synthesis.

    This is AgentVet's signature capability: understanding not just
    individual vulnerabilities, but how they compose into real attacks.
    """

    def __init__(
        self,
        api_key: str = "",
        model: str = DEFAULT_MODEL,
        base_url: str = DEEPSEEK_CHAT,
        enabled: bool = True,
    ):
        self.api_key = api_key or os.environ.get("DEEPSEEK_API_KEY") or ""
        self.model = model
        self.base_url = base_url
        self.enabled = enabled

    def analyze(self, findings: list[Finding]) -> ChainReport:
        """Analyze findings for attack chains.

        Only runs when >=2 HIGH/CRITICAL findings exist — a chain
        requires multiple vulnerabilities to connect.
        """
        t0 = time.perf_counter()

        chainable = [f for f in findings if f.severity in CHAINABLE_SEVERITIES]

        if len(chainable) < 2:
            return ChainReport(
                findings_analyzed=len(chainable),
                model=self.model,
                duration_ms=(time.perf_counter() - t0) * 1000,
            )

        if not self.api_key or not self.enabled:
            return ChainReport(
                findings_analyzed=len(chainable),
                model=self.model,
                duration_ms=(time.perf_counter() - t0) * 1000,
                error="No API key configured",
            )

        try:
            findings_text = self._format_findings(chainable)
            chain = self._call_api(findings_text)
            return ChainReport(
                chain=chain,
                findings_analyzed=len(chainable),
                model=self.model,
                duration_ms=(time.perf_counter() - t0) * 1000,
            )
        except Exception:
            logger.warning("L4 chain analysis failed", exc_info=True)
            return ChainReport(
                findings_analyzed=len(chainable),
                model=self.model,
                duration_ms=(time.perf_counter() - t0) * 1000,
                error="API call failed",
            )

    def _format_findings(self, findings: list[Finding]) -> str:
        """Format findings for the prompt, truncating if needed.

        DeepSeek-chat has a 64K context window. We reserve ~8K for
        the prompt template + response, leaving ~56K for findings.
        At ~300 chars per finding, this handles ~180 findings — far
        more than any real-world scan produces for HIGH/CRITICAL only.
        """
        MAX_CHARS = 48_000  # well within 64K window, leaves room for prompt + response

        parts = []
        total = 0
        truncated = False
        for f in findings:
            text = (
                f"--- Finding {f.rule_id} ---\n"
                f"Severity: {f.severity.value.upper()}\n"
                f"File: {f.file_path}:{f.line_number}\n"
                f"Title: {f.title}\n"
                f"Description: {f.description}\n"
                f"Attack demo (if available): {f.attack_demo or 'Not yet analyzed'}\n"
            )
            if total + len(text) > MAX_CHARS:
                truncated = True
                break
            parts.append(text)
            total += len(text)

        result = "\n".join(parts)
        if truncated:
            result += f"\n\n[... {len(findings) - len(parts)} more findings omitted to stay within context window]"
        return result

    def _call_api(self, findings_text: str) -> Optional[AttackChain]:
        prompt = CHAIN_PROMPT.format(findings_text=findings_text)

        resp = requests.post(
            self.base_url,
            json={
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.2,
                "max_tokens": 8192,
            },
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            timeout=180,
        )
        resp.raise_for_status()
        body = resp.json()
        raw = body["choices"][0]["message"]["content"]

        data = self._parse_json(raw)
        if not data:
            return None

        stages = [
            ChainStage(
                stage=s.get("stage", i + 1),
                stage_name=s.get("stage_name", ""),
                entry_point=s.get("entry_point", ""),
                technique=s.get("technique", ""),
                what_attacker_gains=s.get("what_attacker_gains", ""),
                enables_next_stage=s.get("enables_next_stage", ""),
                prerequisites=s.get("prerequisites", ""),
                detection_difficulty=s.get("detection_difficulty", ""),
            )
            for i, s in enumerate(data.get("attack_chain", []))
        ]

        return AttackChain(
            campaign_name=data.get("campaign_name", "Unnamed Campaign"),
            executive_summary=data.get("executive_summary", ""),
            risk_level=data.get("risk_level", "HIGH"),
            stages=stages,
            total_impact=data.get("total_impact", {}),
            mitigation_priority=data.get("mitigation_priority", []),
        )

    def _parse_json(self, raw: str) -> dict:
        match = re.search(r"\{[\s\S]*\}", raw)
        if not match:
            return {}

        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            cleaned = re.sub(r"//.*?\n", "\n", match.group())
            cleaned = re.sub(r",\s*}", "}", cleaned)
            cleaned = re.sub(r",\s*]", "]", cleaned)
            try:
                return json.loads(cleaned)
            except json.JSONDecodeError:
                return {}
