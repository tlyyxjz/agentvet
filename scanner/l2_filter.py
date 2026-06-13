"""L2 semantic filter — uses local LLM to classify L1 findings as REAL or NOISE.

Batch design: groups findings by file, sends one prompt per file.
Default provider: Ollama qwen3:8b (free, local). Falls back gracefully.
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field

import requests

from .findings import Finding

logger = logging.getLogger(__name__)

# ── config ──────────────────────────────────────────────────────────

_OLLAMA_HOST = os.environ.get("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
OLLAMA_URL = f"{_OLLAMA_HOST}/api/chat"
DEFAULT_MODEL = os.environ.get("OLLAMA_MODEL", "qwen3:8b")
BATCH_SIZE = 12  # max findings per batch to keep prompt small

CLASSIFY_PROMPT = """You are a security code reviewer. For each finding below, classify it as:
- "REAL": a genuine security vulnerability that should be fixed
- "NOISE": a false positive (logging format strings, test fixtures, comments, type annotations, etc.)

Respond ONLY with valid JSON: {{"results": [{{"index": 0, "verdict": "REAL", "reason": "..."}}, ...]}}

Here are the findings from a static analysis scanner:

{findings_text}

Classify each one. Be strict — flag as NOISE if it's:
- Python logging format strings like %(asctime)s, %(levelname)s
- String formatting patterns that aren't user-controlled
- Test files or example code
- Comments or docstrings
- Type annotations or generic error messages

Respond with JSON only, no other text."""


@dataclass
class L2Verdict:
    index: int
    verdict: str  # "REAL" | "NOISE"
    reason: str


@dataclass
class L2Result:
    kept: list[Finding]
    dropped: list[Finding]
    verdicts: list[L2Verdict] = field(default_factory=list)
    model: str = ""
    duration_ms: float = 0


class L2Filter:
    """Batch semantic filter. Uses Ollama by default, configurable model URL."""

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        base_url: str = OLLAMA_URL,
        enabled: bool = True,
    ):
        self.model = model
        self.base_url = base_url
        self.enabled = enabled

    def filter(self, findings: list[Finding]) -> L2Result:
        """Run semantic filtering on a list of L1 findings.

        Returns L2Result with kept (real) and dropped (noise) findings.
        If L2 is disabled or unreachable, all findings pass through as kept.
        """
        if not self.enabled or not findings:
            return L2Result(kept=findings, dropped=[])

        import time
        start = time.perf_counter()

        # Group findings by file for batched prompts
        by_file: dict[str, list[tuple[int, Finding]]] = {}
        for i, f in enumerate(findings):
            by_file.setdefault(f.file_path, []).append((i, f))

        all_verdicts: list[L2Verdict] = []
        real_indices: set[int] = set()

        for file_path, indexed_findings in by_file.items():
            # Batch within file if there are many findings
            for batch_start in range(0, len(indexed_findings), BATCH_SIZE):
                batch = indexed_findings[batch_start : batch_start + BATCH_SIZE]
                findings_text = self._format_findings(batch)
                try:
                    verdicts = self._classify(findings_text, file_path)
                    # Remap by position if model assigns wrong indices
                    batch_indices = [idx for idx, _ in batch]
                    for pos, v in enumerate(verdicts):
                        real_idx = batch_indices[pos] if pos < len(batch_indices) else v.index
                        all_verdicts.append(v)
                        if v.verdict == "REAL":
                            real_indices.add(real_idx)
                except Exception:
                    logger.warning("L2 classify failed for %s, keeping all findings", file_path, exc_info=True)
                    for idx, _ in batch:
                        real_indices.add(idx)

        kept = [f for i, f in enumerate(findings) if i in real_indices]
        dropped = [f for i, f in enumerate(findings) if i not in real_indices]

        result = L2Result(
            kept=kept,
            dropped=dropped,
            verdicts=all_verdicts,
            model=self.model,
            duration_ms=(time.perf_counter() - start) * 1000,
        )
        return result

    def _format_findings(self, indexed: list[tuple[int, Finding]]) -> str:
        lines = []
        for idx, f in indexed:
            lines.append(
                f"--- Finding {idx} ---\n"
                f"Rule: {f.rule_id} | Severity: {f.severity}\n"
                f"File: {f.file_path}:{f.line_number}\n"
                f"Title: {f.title}\n"
                f"Description: {f.description}\n"
                f"Code context:\n{f.code_snippet}\n"
            )
        return "\n".join(lines)

    def _classify(self, findings_text: str, file_path: str) -> list[L2Verdict]:
        """Send batch to LLM, parse JSON response."""
        prompt = CLASSIFY_PROMPT.format(findings_text=findings_text)

        resp = requests.post(
            self.base_url,
            json={
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "stream": False,
                "options": {"temperature": 0.0, "num_predict": 2048},
            },
            timeout=120,
            proxies={"http": None, "https": None},  # bypass global HTTP_PROXY for localhost
        )
        resp.raise_for_status()
        body = resp.json()
        raw = body["message"].get("content", "") or body["message"].get("thinking", "")

        # Extract JSON from response (model may add surrounding text)
        return self._parse_response(raw)

    def _parse_response(self, raw: str) -> list[L2Verdict]:
        """Parse model response, handling markdown code blocks and extra text.

        Verdicts are matched to findings by position if the model fails to set index correctly.
        """
        # Try to find JSON block
        json_match = re.search(r"\{[\s\S]*\"results\"[\s\S]*\}", raw)
        if not json_match:
            return []

        try:
            data = json.loads(json_match.group())
        except json.JSONDecodeError:
            # Try cleaning common issues
            cleaned = re.sub(r"//.*?\n", "\n", json_match.group())
            cleaned = re.sub(r",\s*}", "}", cleaned)
            try:
                data = json.loads(cleaned)
            except json.JSONDecodeError:
                return []

        verdicts = []
        for i, item in enumerate(data.get("results", [])):
            verdicts.append(
                L2Verdict(
                    index=item.get("index", i),  # fall back to position if index missing
                    verdict=item.get("verdict", "REAL").upper(),
                    reason=item.get("reason", ""),
                )
            )
        return verdicts

    def check_health(self) -> bool:
        """Check if the L2 model is reachable."""
        try:
            resp = requests.get(
                self.base_url.replace("/api/chat", "/api/tags"),
                timeout=5,
                proxies={"http": None, "https": None},
            )
            return resp.status_code == 200
        except Exception:
            logger.warning("L2 health check failed", exc_info=True)
            return False
