"""Tool authorization detection rules.

Detects high-risk tools registered without user confirmation,
and missing permission checks before tool execution.
"""

import re

from ..engine import RegexRule
from ..findings import Severity


_HIGH_RISK_TOOLS = r"(shell|bash|exec|eval|subprocess|os\.system|os\.popen|commands\.getoutput|rm |delete|unlink|write_file|send_email|http\.post|requests\.post|fetch)"
_CONFIRMATION_KEYWORDS = r"(confirm|confirmation|require_approval|ask_user|user_confirm|need_confirm|approval_required)"

# Confirmation indicators — when present near a finding, suppress the finding
# because the developer has implemented an explicit user-confirmation step.
_CONFIRMATION_DECORATOR_RE = re.compile(
    r"@\w*tool\w*\s*\([^)]*\bconfirmation\s*=", re.IGNORECASE
)
_CONFIRMATION_DECORATOR_PLAIN_RE = re.compile(
    r"@\w*tool\w*\s*\([^)]*\brequire_confirmation\s*=\s*True", re.IGNORECASE
)
_CONFIRMATION_CALL_RE = re.compile(
    r"\b(?:input|confirm|ask_user|require_confirmation|user_confirm|need_confirm)\s*\(",
    re.IGNORECASE,
)


class HighRiskToolNoConfirmRule(RegexRule):
    """Detect high-risk tools registered without user confirmation."""

    rule_id = "TA-001"
    title = "高风险工具未要求用户确认"
    description = (
        "文件删除、Shell执行、网络请求等高风险工具注册时"
        "未设置require_confirmation=True，Agent可绕过用户直接执行危险操作。"
    )

    patterns = [
        # Python
        # Tool function definition with high-risk operations, no confirm
        (
            r"(def |async def )\w*(shell|bash|exec|delete|remove|write)\w*",
            "高风险工具函数定义，检查是否缺少确认机制",
        ),
        # os.system / subprocess calls without guard
        (
            r"(os\.system|subprocess\.(call|run|Popen)|os\.popen|commands\.)",
            "直接调用系统Shell，Agent可能执行任意命令",
        ),
        # file delete/write without confirm
        (
            r"(os\.remove|os\.unlink|shutil\.rmtree|Path\(.*\)\.unlink)",
            "文件删除操作缺少用户确认",
        ),
        # JS/TS
        # child_process exec without confirmation
        (
            r"(child_process\.exec|execSync|spawn|exec\s*\(|execFile)",
            "Node.js 直接执行系统命令，检查是否缺少确认",
        ),
        # fs.unlink / fs.rm without confirmation
        (
            r"(fs\.(unlink|rm|rmSync|unlinkSync)\s*\(|rimraf\s*\()",
            "Node.js 文件删除操作缺少用户确认",
        ),
        # fetch/axios POST for destructive actions without confirm
        (
            r"(fetch|axios)\s*\(\s*[\"'][^\"']*(?:delete|remove|destroy|purge)",
            "通过网络请求执行删除操作，检查是否需用户确认",
        ),
    ]

    file_patterns = ["*.py", "*.js", "*.ts", "*.tsx", "*.jsx"]
    owasp_ids = ["LLM06", "AG-10"]

    def _severity(self):
        return Severity.HIGH

    def fix_suggestion(self) -> str:
        return (
            "所有高风险工具添加require_confirmation=True：\n"
            '  @tool(require_confirmation=True)\n'
            "  def delete_file(path: str): ...\n\n"
            "或在工具内部实现确认逻辑：\n"
            '  if not await ask_user(f"确认删除 {path}?"): return'
        )

    def check(self, file_path: str, content: str) -> list:
        """Run regex patterns, then drop findings that already have a
        confirmation mechanism (decorator with ``confirmation=`` /
        ``require_confirmation=True``, or a confirmation call in the
        function body).
        """
        findings = super().check(file_path, content)
        if not findings:
            return []

        lines = content.split("\n")
        kept = []
        for f in findings:
            if self._has_confirmation_nearby(lines, f.line_number):
                continue
            kept.append(f)
        return kept

    @staticmethod
    def _has_confirmation_nearby(lines: list, line_no: int) -> bool:
        """Return True if a confirmation mechanism appears in the decorator
        above the finding or in the function body below it.
        """
        # Look up to 6 lines above (decorators) and 30 lines below (body).
        start = max(0, line_no - 6)
        end = min(len(lines), line_no + 30)
        window = "\n".join(lines[start:end])

        if _CONFIRMATION_DECORATOR_RE.search(window):
            return True
        if _CONFIRMATION_DECORATOR_PLAIN_RE.search(window):
            return True
        if _CONFIRMATION_CALL_RE.search(window):
            return True
        return False


class MissingToolPermissionRule(RegexRule):
    """Detect tool calls without authorization/permission checks."""

    rule_id = "TA-002"
    title = "工具调用缺少权限校验"
    description = (
        "Agent工具在执行敏感操作前未检查调用者权限，"
        "任何能够与Agent交互的用户均可触发敏感操作。"
    )

    patterns = [
        # Python
        # Tool function that accesses sensitive resource without auth check.
        # Drop "user"/"config" — too generic (matched delete_user, get_user_config, etc.)
        (
            r"(def |async def )\w*(admin|secret|key|token|password|credential)\w*",
            "敏感操作函数定义，需检查是否有权限校验",
        ),
        # Database write via SQL execute() — require SQL keyword inside string literal
        (
            r"\.execute\s*\(\s*['\"]\s*(?:INSERT\s+|DELETE\s+|UPDATE\s+|DROP\s+)",
            "SQL写操作（execute），检查调用前是否验证了权限",
        ),
        # ORM commit/save/delete/update method calls — require call form with parens
        (
            r"\.\b(?:commit|save|delete|update)\b\s*\(",
            "数据库写操作（commit/save/delete/update），检查调用前是否验证了权限",
        ),
        # JS/TS
        # Prisma/ORM database write — require prisma. prefix to avoid matching
        # generic .create()/.delete() on any object (e.g. openai client)
        (
            r"prisma\.\w+\.(?:create|delete|update|upsert|deleteMany|updateMany)\s*\(",
            "Prisma数据库写操作，检查调用前是否验证权限",
        ),
        # Direct localStorage/sessionStorage access for auth tokens
        (
            r"(localStorage|sessionStorage)\.(getItem|setItem)\s*\(\s*[\"'](token|auth|session|user)",
            "客户端存储认证Token，检查是否可能被XSS窃取",
        ),
    ]
    file_patterns = ["*.py", "*.js", "*.ts", "*.tsx", "*.jsx"]
    owasp_ids = ["LLM06", "AG-03"]

    def _severity(self):
        return Severity.HIGH

    def fix_suggestion(self) -> str:
        return (
            "在每个敏感工具函数开头添加权限检查：\n"
            "  def admin_action(user_id: str, ...):\n"
            '      if not auth.is_admin(user_id):\n'
            '          return "权限不足"\n'
            "      # ... 执行操作"
        )


class CrossAgentPermissionLeakRule(RegexRule):
    """Detect multi-agent orchestration where auth context is lost when one
    agent delegates tasks to another.

    In multi-agent systems (AutoGen, CrewAI, LangGraph), a "manager" agent
    often spawns sub-agents to handle specific tasks. When the sub-agent is
    created without inheriting the caller's permission scope, it runs with
    full system privileges — bypassing the original user's restrictions.

    Real attack: A user with read-only access asks the manager agent a
    question. The manager spawns a sub-agent that writes to the database
    because the permission check happened at the manager level, not the
    sub-agent level.
    """

    rule_id = "TA-003"
    title = "Cross-agent delegation loses caller permission context"
    description = (
        "A sub-agent or child task is spawned without passing the caller's "
        "permission context (user_id, role, scope). The sub-agent inherits "
        "the parent process's privileges rather than the original user's — "
        "effectively a horizontal privilege escalation within the agent system."
    )
    file_patterns = ["*.py", "*.js", "*.ts", "*.tsx", "*.jsx"]
    owasp_ids = ["AG-03", "LLM06"]

    patterns = [
        # Python: Creating sub-agent without passing user context
        # agent.run() / agent.invoke() / asyncio.create_task(agent.process())
        (
            r"(?:\.run\(|\.invoke\(|\.process\(|\.execute\(|create_task\()(?!.*(?:user_id|auth|permission|scope|context|caller))",
            "Sub-agent spawned without passing caller's permission context",
        ),
        # CrewAI: Task creation without context propagation
        (
            r"Task\s*\([^)]*agent\s*=\s*\w+(?!.*context\s*=)(?!.*user_id\s*=)",
            "CrewAI Task delegates to agent without inheriting user context",
        ),
        # AutoGen: initiate_chat / a_initiate_chat without carryover
        (
            r"(?:initiate_chat|a_initiate_chat)\s*\([^)]*(?!.*carryover\s*=)",
            "AutoGen inter-agent chat initiated without context carryover",
        ),
        # LangGraph: StateGraph with subgraph but no auth in state schema
        (
            r"StateGraph\s*\([^)]*\)(?!.*\bauth\b)",
            "LangGraph state machine defined without auth field in state schema",
        ),
        # JS/TS: Child agent spawned without auth
        (
            r"(?:createChildAgent|spawnAgent|createAgent)\s*\([^)]*(?!.*(?:userId|auth|permission|scope|context))",
            "JavaScript child agent spawned without permission propagation",
        ),
    ]

    def _severity(self):
        return Severity.HIGH

    def fix_suggestion(self) -> str:
        return (
            "Always propagate caller identity and permissions to sub-agents:\n"
            "  sub_agent.run(\n"
            "      task=task_description,\n"
            '      context={"user_id": caller_context.user_id,\n'
            '               "role": caller_context.role,\n'
            '               "permissions": caller_context.permissions}\n'
            "  )\n\n"
            "Sub-agents MUST verify context before executing privileged operations.\n"
            "Never assume the parent has already checked — defense in depth."
        )
