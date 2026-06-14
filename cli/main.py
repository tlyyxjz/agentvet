#!/usr/bin/env python3
"""AgentVet CLI — AI Agent Security Scanner.

Usage:
    agentvet scan ./my-agent          # Scan a directory
    agentvet scan ./my-agent --json   # Output JSON report
    agentvet scan file.py             # Scan a single file
    agentvet version                  # Show version
"""

import argparse
import json
import sys
from pathlib import Path

# Fix Windows GBK encoding for emoji output
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Add project root to path so `scanner` imports work from CLI
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner.engine import ScanEngine
from scanner.findings import ScanReport

# ── color helpers ───────────────────────────────────────────────

RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
BLUE = "\033[94m"
GRAY = "\033[90m"
BOLD = "\033[1m"
RESET = "\033[0m"

SEVERITY_COLORS = {
    "critical": RED,
    "high": RED,
    "medium": YELLOW,
    "low": GREEN,
    "info": GRAY,
}

SEVERITY_ICONS = {
    "critical": "[!!]",
    "high": "[!] ",
    "medium": "[~] ",
    "low": "[*] ",
    "info": "[i] ",
}


def color_severity(severity: str) -> str:
    c = SEVERITY_COLORS.get(severity, "")
    return f"{c}{severity.upper()}{RESET}"


def icon_severity(severity: str) -> str:
    return SEVERITY_ICONS.get(severity, "  ")


def print_banner():
    from scanner import __version__
    print(f"{BOLD}{BLUE}  AgentVet v{__version__} — AI Agent Security Scanner{RESET}")
    print(f"  {GRAY}https://github.com/tlyyxjz/agentvet{RESET}")
    print()


def print_report(report: ScanReport, json_output: bool = False):
    if json_output:
        print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
        return

    print_banner()
    print(f"  Scanning {BOLD}{report.target}{RESET} ({report.total_checks} checks)...")
    print(f"  {'=' * 50}")
    print()

    if not report.findings:
        print(f"  {GREEN}[OK] No vulnerabilities found!{RESET}")
        print(f"  Score: {GREEN}A+{RESET}")
        return

    # Group by severity for display
    by_severity: dict = {}
    for f in sorted(
        report.findings,
        key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}[x.severity.value],
    ):
        by_severity.setdefault(f.severity.value, []).append(f)

    for sev in ["critical", "high", "medium", "low", "info"]:
        if sev not in by_severity:
            continue
        findings = by_severity[sev]
        for f in findings:
            icon = icon_severity(f.severity.value)
            sev_label = color_severity(f.severity.value)
            print(f"  {icon} [{sev_label}] {BOLD}{f.title}{RESET}")
            print(f"     {GRAY}{f.file_path}:{f.line_number}{RESET}")
            print(f"     {f.description[:120]}")
            if f.attack_demo:
                print(f"     {YELLOW}攻击演示: {f.attack_demo[:100]}{RESET}")
            print()

    # Summary
    print(f"  {'─' * 50}")

    # ── L4 attack chain ──────────────────────────────────────────
    if report.chain:
        chain = report.chain
        print(f"\n  {BOLD}{RED}[ATTACK CHAIN] {chain.campaign_name}{RESET}")
        print(f"  {GRAY}{chain.executive_summary[:200]}{RESET}")
        print(f"  {'─' * 50}")
        for s in chain.stages:
            print(f"\n  {BOLD}Stage {s.stage}: {s.stage_name}{RESET}")
            print(f"  {GRAY}Entry: {s.entry_point}{RESET}")
            print(f"  {s.technique[:150]}")
            if s.enables_next_stage:
                print(f"  {YELLOW}→ {s.enables_next_stage[:150]}{RESET}")
        if chain.mitigation_priority:
            print(f"\n  {BOLD}{GREEN}[FIX PRIORITY]{RESET}")
            for m in chain.mitigation_priority[:3]:
                print(f"  {m['order']}. {m['action'][:120]} [{m.get('effort', '?')} effort]")
        print()

    score_color = RED if report.score in ("D", "F") else YELLOW if report.score == "C" else GREEN
    print(f"  Score: {score_color}{report.score}{RESET}  "
          f"({report.critical_count} critical, {report.high_count} high, "
          f"{report.medium_count} medium, {report.low_count} low)")
    print(f"  Duration: {report.duration_ms:.1f}ms")
    print()
    print(f"  Full report: {GRAY}./agentvet-report.json{RESET}")


def cmd_scan(args):
    engine = ScanEngine(use_l2=args.depth >= 2, use_l3=args.depth >= 3, use_l4=args.depth >= 3)
    report = engine.scan(args.target)
    print_report(report, args.json)

    # Save JSON report
    if not args.json:
        report_path = Path.cwd() / "agentvet-report.json"
        report_path.write_text(
            json.dumps(report.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8"
        )

    # CI gate — exit non-zero when findings at or above --fail-on threshold
    if report.fails_on(args.fail_on):
        return 2
    return 0 if report.high_count + report.critical_count == 0 else 1


def cmd_version():
    from scanner import __version__
    print(f"AgentVet v{__version__}")
    return 0


def main():
    parser = argparse.ArgumentParser(
        prog="agentvet",
        description="AI Agent Security Scanner — detect prompt injection, tool auth bypass, data leaks",
    )
    sub = parser.add_subparsers(dest="command")

    scan_p = sub.add_parser("scan", help="Scan an AI agent directory or file")
    scan_p.add_argument("target", help="Path to agent directory or file")
    scan_p.add_argument("--json", action="store_true", help="Output JSON format")
    scan_p.add_argument(
        "--depth", "-d",
        type=int,
        default=3,
        choices=[1, 2, 3],
        help="Scan depth: 1=L1 only, 2=L1+L2, 3=full pipeline (default: 3)",
    )
    scan_p.add_argument(
        "--fail-on",
        type=str.lower,
        default="high",
        choices=["info", "low", "medium", "high", "critical"],
        help="CI mode: exit non-zero if findings reach this severity (default: high)",
    )
    scan_p.set_defaults(func=cmd_scan)

    _ver_p = sub.add_parser("version", help="Show version")
    _ver_p.set_defaults(func=lambda _: cmd_version())

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
