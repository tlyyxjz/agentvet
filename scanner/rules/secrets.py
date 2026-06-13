"""Hardcoded secret detection rules.

Detects API keys, cloud credentials, and authentication tokens
embedded in source code — one of the most common and impactful
security mistakes in AI agent codebases.

These patterns are designed for low false positives: each rule
targets a specific credential format with a unique structural
signature (prefix + character class + minimum length).
"""

from ..engine import RegexRule
from ..findings import Severity


class AIProviderKeyRule(RegexRule):
    """Detect AI service API keys (OpenAI, DeepSeek, Anthropic, etc.)
    hardcoded as string literals in source code.

    AI agent code often embeds the LLM provider's API key directly
    in the source for convenience. This is the single most common
    security finding in AI projects — and the most dangerous, since
    a leaked key gives the attacker free API access and the ability
    to exfiltrate all conversation data.
    """

    rule_id = "SEC-001"
    title = "AI provider API key embedded in source code"
    description = (
        "An AI service API key (OpenAI/DeepSeek/Anthropic/Cohere/etc.) "
        "is hardcoded as a string literal. If this code is committed to "
        "a repository, the key is exposed to anyone with read access. "
        "Leaked keys grant full API access including conversation history."
    )

    file_patterns = [
        "*.py", "*.js", "*.ts", "*.tsx", "*.jsx",
        "*.json", "*.yaml", "*.yml", "*.toml",
    ]

    patterns = [
        # OpenAI / DeepSeek / compatible keys: sk- prefix (but NOT sk-ant- Anthropic keys)
        (
            r"""["'](sk-(?!ant-)[A-Za-z0-9_-]{20,})["']""",
            "OpenAI-compatible API key embedded in string literal",
        ),
        # Anthropic keys: sk-ant- prefix
        (
            r"""["'](sk-ant-[A-Za-z0-9_-]{20,})["']""",
            "Anthropic API key embedded in string literal",
        ),
        # Generic "sk-" key in an assignment (catches lesser-known providers)
        (
            r"""(?:api_?key|secret_?key|access_?token)\s*[:=]\s*["']sk-[A-Za-z0-9_-]{16,}""",
            "Secret variable assigned an sk-prefixed API key",
        ),
    ]

    owasp_ids = ["LLM02"]

    def _severity(self):
        return Severity.CRITICAL

    def fix_suggestion(self) -> str:
        return (
            "Never put API keys in source files. Use environment variables:\n"
            '  api_key = os.environ["OPENAI_API_KEY"]\n\n'
            "For local development, use a .env file (never commit it):\n"
            '  # .env\n'
            "  OPENAI_API_KEY=sk-your-key-here\n\n"
            "And load it with python-dotenv:\n"
            "  from dotenv import load_dotenv; load_dotenv()\n"
            '  api_key = os.environ["OPENAI_API_KEY"]'
        )


class CloudCredentialRule(RegexRule):
    """Detect cloud service credentials (AWS, GCP, Azure) in source code.

    Cloud credentials in code grant access to compute, storage, and
    network resources. For AI agents that manage infrastructure or
    deploy services, a leaked cloud key can mean full account takeover.
    """

    rule_id = "SEC-002"
    title = "Cloud provider credential embedded in source code"
    description = (
        "An AWS access key, GCP service account key, or cloud provider "
        "token is hardcoded. Cloud credentials provide infrastructure "
        "access — a single leaked key can compromise entire environments."
    )

    file_patterns = [
        "*.py", "*.js", "*.ts", "*.tsx", "*.jsx",
        "*.json", "*.yaml", "*.yml",
    ]

    patterns = [
        # AWS IAM access key: AKIA + 16 uppercase alphanumeric
        (
            r"""["'](AKIA[A-Z0-9]{16})["']""",
            "AWS IAM access key (AKIA prefix) embedded in string literal",
        ),
        # AWS secret access key: 40-char base64-ish string assigned to secret variable
        (
            r"""(?:aws_?secret|secret_?access_?key)\s*[:=]\s*["'][A-Za-z0-9+/=]{30,50}["']""",
            "AWS secret key assigned to a variable named aws_secret*/secret_access_key",
        ),
        # GCP service account JSON key marker
        (
            r"""["'](?:type["']?\s*:\s*["']service_account)""",
            "GCP service account key file content — contains private_key_id",
        ),
        # Generic cloud key assignment pattern
        (
            r"""(?:azure_?(?:key|secret)|gcp_?(?:key|secret))""",
            "Azure or GCP secret variable name — verify the value isn't hardcoded",
        ),
    ]

    owasp_ids = ["LLM02"]

    def _severity(self):
        return Severity.CRITICAL

    def fix_suggestion(self) -> str:
        return (
            "Use the cloud provider's secret manager or IAM roles:\n"
            "- AWS: IAM instance roles (no keys needed in code)\n"
            "- GCP: Workload Identity Federation\n"
            "- Azure: Managed Identity\n\n"
            "If static keys are unavoidable, use environment variables:\n"
            '  aws_key = os.environ["AWS_ACCESS_KEY_ID"]\n\n'
            "Rotate any keys that have been committed to version control immediately."
        )


class GenericPasswordTokenRule(RegexRule):
    """Detect generic password, token, and credential assignments in source code.

    Catches patterns missed by the provider-specific rules: database
    passwords, JWT secrets, generic API tokens, and anything that looks
    like a credential in a variable assignment.
    """

    rule_id = "SEC-003"
    title = "Generic credential or password in source code"
    description = (
        "A variable name suggesting it holds a secret (password, token, "
        "secret) is assigned a string literal that looks like a real value "
        "(not an environment variable reference or placeholder). Database "
        "passwords and JWT secrets are the most common findings."
    )

    file_patterns = [
        "*.py", "*.js", "*.ts", "*.tsx", "*.jsx",
        "*.json", "*.yaml", "*.yml", "*.toml", "*.env",
    ]

    patterns = [
        # Variable named password/secret/token assigned a non-empty, non-env string
        (
            r"""(?:password|passwd|pwd|secret|token)\s*[:=]\s*["'][A-Za-z0-9!@#$%^&*()_+\-=\[\]{}|;:,.<>?/~]{8,}["']""",
            "Variable with secret-like name assigned a real value (not an env var ref)",
        ),
        # JWT secret / Flask SECRET_KEY / Django SECRET_KEY with hardcoded value
        (
            r"""(?:SECRET_KEY|JWT_SECRET|ENCRYPTION_KEY|SIGNING_KEY)\s*=\s*["'][A-Za-z0-9_\-+/=]{10,}["']""",
            "Application secret key hardcoded in source — common in Flask/Django config files",
        ),
        # Database connection string with embedded password
        (
            r"""["'](?:mysql|postgres(?:ql)?|mongodb|redis)://[^@]*:[^@]+@""",
            "Database connection URL with embedded password — use env vars instead",
        ),
        # GitHub personal access token (ghp_ / gho_ / ghu_ / ghs_ / ghr_)
        (
            r"""["'](gh[pousr]_[A-Za-z0-9]{30,})["']""",
            "GitHub personal access token embedded in source",
        ),
        # Slack webhook / bot token
        (
            r"""["'](xox[bpsar]-\d{10,}-\d{10,}-[A-Za-z0-9]{20,})["']""",
            "Slack bot or webhook token embedded in source",
        ),
    ]

    owasp_ids = ["LLM02"]

    def _severity(self):
        return Severity.HIGH

    def fix_suggestion(self) -> str:
        return (
            "All credentials must come from environment or a secrets manager:\n"
            "  1. Move the value to a .env file (never commit it)\n"
            '  2. Replace the hardcoded string with os.environ["VAR_NAME"]\n'
            "  3. For production, use a secret manager (AWS Secrets Manager, "
            "HashiCorp Vault, or your platform's built-in secrets store)\n"
            "  4. If this key has been committed to git, rotate it immediately"
        )
