"""Skill/plugin supply-chain attack detection rules.

Covers malicious AI agent skills, plugins, and extensions — the
fastest-growing attack vector in the agent ecosystem. After the
ClawHavoc campaign (341 malicious skills in 3 days, Jan 2026) and
Snyk's ToxicSkills audit (13.4% of 3,984 skills contained critical
issues), scanning third-party agent extensions is no longer optional.

This module detects:
- Obfuscated payloads in skill manifests and source
- Data exfiltration endpoints in plugin code
- Destructive commands disguised as utility functions
- Encoded/encrypted payloads that evade regex-only scanners
"""

import re

from ..engine import RegexRule
from ..findings import Severity


class SkillSupplyChainRule(RegexRule):
    """Detect malicious patterns in AI agent skill/plugin/extension files.

    Targets the supply-chain attack surface unique to AI agent ecosystems:
    skills that look like legitimate tools but contain hidden payloads for
    data exfiltration, code execution, or agent hijacking.

    Unlike traditional malware scanning (which looks for binary signatures),
    this rule targets agent-specific attack patterns: description-based
    prompt injection, skill chaining for privilege escalation, and
    instruction-based data harvesting.
    """

    rule_id = "SC-001"
    title = "AI agent skill contains suspicious supply-chain pattern"
    description = (
        "A skill, plugin, or extension file for an AI agent platform "
        "(Claude Code, Cursor, Windsurf, etc.) contains patterns commonly "
        "associated with malicious supply-chain attacks: obfuscated code, "
        "hidden data exfiltration endpoints, encoded payloads in descriptions, "
        "or destructive commands masked as utility functions."
    )
    file_patterns = ["*.py", "*.js", "*.ts", "*.tsx", "*.md", "*.yaml", "*.yml", "*.toml"]
    owasp_ids = ["LLM01", "LLM02", "AG-10"]

    patterns = [
        # Base64-encoded payload in exec/eval (most common obfuscation)
        # exec(base64.b64decode("...")) or eval(atob("..."))
        (
            r"""(?:exec|eval|__import__)\s*\(\s*(?:base64\.b64decode|atob|Buffer\.from)\s*\(['"][A-Za-z0-9+/=]{40,}['"]""",
            "exec/eval of base64-encoded payload — classic supply-chain obfuscation",
        ),
        # Encoded payload in import or compile
        (
            r"""(?:importlib|__import__|compile)\s*\(.*(?:b64decode|atob|Buffer\.from|fromCharCode|unescape)""",
            "Dynamic import or compile with encoded payload — code smuggling",
        ),
        # Data exfiltration to raw IP or obscure hosts in skill code
        # requests.post("http://123.45.67.89/collect", ...) or fetch("https://paste.example.com/raw/...")
        (
            r"""(?:requests|httpx|urllib|fetch|axios|node-fetch)\s*\.\s*(?:post|put|get)\s*\(\s*['"]https?://(?:[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|(?:paste|raw|gist|hastebin|termbin|ix\.io|rentry|justpaste|0x0\.st|transfer\.sh|file\.io|anonfiles|webhook\.site|pipedream|requestbin|hookbin|beeceptor|mockbin|postb\.in|en\.wtools))""",
            "HTTP POST to exfiltration endpoint (raw IP or known paste/drop service)",
        ),
        # Obfuscated shell command in skill (hex-encoded, reversed, or nested encoding)
        (
            r"""(?:os\.system|subprocess\.|child_process\.exec|execSync|spawn\s*\(|popen)\s*\(.*(?:decode\s*\(|fromhex|replace\s*\(['"]\\x|\.join\s*\(.*chr\()""",
            "Shell command with encoded/obfuscated payload — likely malicious",
        ),
        # Skill description containing "update" or "patch" but actually exfiltrates
        (
            r"""["'](?:description|name|title)["']\s*:\s*["'].*(?:collect|harvest|gather|scrape|steal|exfiltrate|leak|dump).*(?:email|credential|password|token|key|secret|data)""",
            "Skill metadata references data harvesting — malicious intent in description",
        ),
        # Hidden file access: reading sensitive files and sending out
        # open("/etc/passwd") + .post(...) or fs.readFileSync(".env") + fetch(...)
        (
            r"""(?:open|readFile|readFileSync|fs\.read)\s*\(.*(?:/etc/|\.env|\.ssh/|\.aws/|\.config/|config\.json|credentials|\.git/config|\.npmrc|\.pypirc)""",
            "Skill reads sensitive files (/etc/, .env, .ssh, credentials) — data harvesting risk",
        ),
        # Arbitrary code evaluation from skill metadata or config
        (
            r"""(?:eval|exec|Function\s*\()\s*\(\s*(?:this\.|obj\.|data\.|config\.|meta\.|input\.|args\.|params\.)""",
            "Dynamic code evaluation from skill input — remote code execution risk",
        ),
    ]

    def _severity(self):
        return Severity.CRITICAL

    def fix_suggestion(self) -> str:
        return (
            "Third-party skills/plugins must be audited before installation:\n"
            "  1. Never install skills from untrusted sources or unverified publishers\n"
            "  2. Review skill source code — especially exec/eval/subprocess calls\n"
            "  3. Check all outbound HTTP requests in skill code\n"
            "  4. Run agentvet scan on every skill before adding it to your agent\n"
            "  5. Pin skill versions and verify checksums\n"
            "  6. Use a sandboxed agent environment for untrusted skills"
        )


class URLInSkillMetadataRule(RegexRule):
    """Detect skill/plugin manifests (package.json, pyproject.toml, skill.yaml)
    that reference URLs to raw content hosts or unverified domains.

    Many malicious skills embed references to pastebin, gist, or raw
    content URLs in their metadata — these URLs serve second-stage
    payloads that activate after installation.
    """

    rule_id = "SC-002"
    title = "Skill manifest references suspicious external URL"
    description = (
        "A skill manifest file (package.json, pyproject.toml, skill.yaml, etc.) "
        "contains a URL pointing to a pastebin, gist, raw content host, or "
        "unusual domain. Malicious skills often use these to fetch second-stage "
        "payloads after the initial install passes review."
    )
    file_patterns = ["*.json", "*.yaml", "*.yml", "*.toml"]
    owasp_ids = ["AG-10"]

    # Domains commonly abused for second-stage payload delivery
    _SUSPICIOUS_DOMAINS = re.compile(
        r"""(?x)https?://(?:
            paste(?:bin)?\.(?:com|ee|org|net|pl|de|fr|es|it|nl|ru)|
            (?:raw|gist)\.github(?:usercontent)?\.com/[^/\s\"']+/[^/\s\"']+/raw/|
            rentry\.co/[^\s\"']+/raw|
            justpaste\.it/[^\s\"']+|
            hastebin\.(?:com|skyra\.pw)|
            termbin\.com/[^\s\"']+|
            ix\.io/[^\s\"']+|
            0x0\.st/[^\s\"']+|
            transfer\.sh/[^\s\"']+|
            file\.io/[^\s\"']+|
            anonfiles\.com/[^\s\"']+|
            webhook\.site/[^\s\"']+|
            pipedream\.(?:net|com)/[^\s\"']+|
            requestbin\.(?:com|net|org)/[^\s\"']+|
            hookbin\.com/[^\s\"']+|
            beeceptor\.com/[^\s\"']+|
            mockbin\.(?:org|com)/[^\s\"']+|
            postb\.in/[^\s\"']+|
            en\.wtools\.io/[^\s\"']+
        )"""
    )

    patterns = [
        # Any match of the suspicious domain pattern
        (
            _SUSPICIOUS_DOMAINS.pattern,
            "Skill manifest contains URL to pastebin/raw/gist/requestbin — potential C2 or second-stage payload",
        ),
    ]

    def _severity(self):
        return Severity.HIGH

    def fix_suggestion(self) -> str:
        return (
            "Audit all external URLs in skill manifests:\n"
            "  1. URLs to paste/raw/gist/requestbin services are red flags\n"
            "  2. Verify the publisher owns any referenced domain\n"
            "  3. Replace external resource references with vendored copies\n"
            "  4. Consider blocking outbound requests from agent tools to these domains"
        )
