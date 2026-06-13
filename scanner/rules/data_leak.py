"""Data leakage detection rules.

Detects logging of sensitive data, unredacted LLM I/O in logs,
and unauthorized external service data transmission.
"""

from ..engine import RegexRule
from ..findings import Severity


_SENSITIVE_VARS = r"(password|passwd|secret|token|api_key|apikey|credential|private_key|cert|auth_token|access_key)"
_LLM_IO_VARS = r"(response|output|answer|completion|messages|conversation|chat_history|llm_result)"


class LogSensitiveDataRule(RegexRule):
    """Detect logging of sensitive data like tokens, passwords, LLM I/O."""

    rule_id = "DL-001"
    title = "日志中输出敏感数据"
    description = (
        "将用户密码、API密钥、Token或LLM对话内容写入日志，"
        "导致敏感信息可通过日志文件泄露。"
    )

    patterns = [
        # console.log / print with sensitive variables
        (
            rf"(console\.log|print|logger\.(info|debug|error|warning)|logging\.)\s*\(.*{_SENSITIVE_VARS}",
            "敏感变量（密码/Token/密钥）被写入日志",
        ),
        # Logging LLM full response without redaction
        (
            rf"(console\.log|print|logger\.)\s*\(.*{_LLM_IO_VARS}",
            "LLM对话内容被完整记录到日志，可能含用户隐私",
        ),
        # Logging full request/response objects
        (
            r"console\.log\s*\(\s*(JSON\.stringify|json\.dumps)\s*\(\s*(req|request|res|response)\s*\)",
            "完整HTTP请求/响应对象被序列化到日志",
        ),
        # JS/TS: dangerouslySetInnerHTML with user input
        (
            r"dangerouslySetInnerHTML\s*[:=]\s*\{.*__html",
            "React dangerouslySetInnerHTML 可能导致XSS",
        ),
        # JS/TS: innerHTML assignment
        (
            r"\.innerHTML\s*=\s*.*(user|input|query|message|data|content)",
            "innerHTML直接赋值用户数据，XSS风险",
        ),
    ]
    file_patterns = ["*.py", "*.js", "*.ts", "*.tsx", "*.jsx"]

    def _severity(self):
        return Severity.MEDIUM

    def fix_suggestion(self) -> str:
        return (
            "日志输出前脱敏：\n"
            "  1. 密码/Token → 永远不记录\n"
            "  2. LLM I/O → 只记录前50字符 + hash\n"
            '  3. 用专门的sanitize函数: safe_log(user_input, mask_keys=["password", "token"])'
        )


class ExternalServiceNoAuditRule(RegexRule):
    """Detect LLM data sent to external services without audit trail."""

    rule_id = "DL-002"
    title = "Agent数据发往外部服务缺少审计"
    description = (
        "将用户对话、Agent输出等数据发送到外部API（监控/分析/存储），"
        "缺少审计日志和用户同意机制，可能违反数据隐私规定。"
    )

    patterns = [
        # HTTP POST of conversation data to external service
        (
            rf"(requests|httpx|urllib|fetch|axios)\.(post|put)\s*\(.*{_LLM_IO_VARS}",
            "LLM对话数据被POST到外部服务",
        ),
        # Sending to analytics/monitoring without user consent
        (
            r"(langsmith|langfuse|helicone|weights.*biases|wandb|agentops)",
            "数据发往第三方AI监控平台，检查用户是否知情同意",
        ),
    ]
    file_patterns = ["*.py", "*.js", "*.ts", "*.tsx", "*.jsx"]

    def _severity(self):
        return Severity.MEDIUM

    def fix_suggestion(self) -> str:
        return (
            "发送数据到外部服务前：\n"
            "  1. 获得用户明确同意（opt-in）\n"
            "  2. 记录审计日志（时间、数据量、目的地）\n"
            "  3. 允许用户随时关闭数据外发\n"
            "  4. 脱敏个人身份信息后再发送"
        )
