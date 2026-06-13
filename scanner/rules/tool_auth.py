"""Tool authorization detection rules.

Detects high-risk tools registered without user confirmation,
and missing permission checks before tool execution.
"""

from ..engine import ASTRule, RegexRule
from ..findings import Severity


_HIGH_RISK_TOOLS = r"(shell|bash|exec|eval|subprocess|os\.system|os\.popen|commands\.getoutput|rm |delete|unlink|write_file|send_email|http\.post|requests\.post|fetch)"
_CONFIRMATION_KEYWORDS = r"(confirm|confirmation|require_approval|ask_user|user_confirm|need_confirm|approval_required)"


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
            rf"(def |async def )\w*(shell|bash|exec|delete|remove|write)\w*",
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
        # Tool function that accesses sensitive resource without auth check
        (
            r"(def |async def )\w*(admin|user|config|secret|key|token|password|credential)\w*",
            "敏感操作函数定义，需检查是否有权限校验",
        ),
        # Database write without permission check
        (
            r"(\.execute\(|\.commit\(|\.save\(|\.delete\(|\.update\(|INSERT|DELETE|UPDATE|DROP)",
            "数据库写操作，检查调用前是否验证了权限",
        ),
        # JS/TS
        # Prisma/ORM database write without auth
        (
            r"(\.(create|delete|update|upsert|deleteMany|updateMany)\s*\(|prisma\.\w+\.(create|delete|update))",
            "数据库写操作（Prisma/ORM），检查调用前是否验证权限",
        ),
        # Direct localStorage/sessionStorage access for auth tokens
        (
            r"(localStorage|sessionStorage)\.(getItem|setItem)\s*\(\s*[\"'](token|auth|session|user)",
            "客户端存储认证Token，检查是否可能被XSS窃取",
        ),
    ]
    file_patterns = ["*.py", "*.js", "*.ts", "*.tsx", "*.jsx"]

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
