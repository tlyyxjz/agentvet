"""Quick scan CLI — L1 → L2 → L3 pipeline at chosen depth.

Usage:
  python quick_scan.py [target] [--depth 1|2|3] [--json]

Examples:
  python quick_scan.py                          # scan Codex at full depth
  python quick_scan.py C:/my-agent --depth 2    # L1 + L2 only
  python quick_scan.py --json | jq .score       # JSON output
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from scanner.engine import ScanEngine
from scanner.findings import Severity


def main():
    parser = argparse.ArgumentParser(description="AgentVet Quick Scan")
    parser.add_argument(
        "target", nargs="?", default=str(Path.home() / ".codex"),
        help="Directory or file to scan (default: ~/.codex)"
    )
    parser.add_argument(
        "--depth", type=int, default=3, choices=[1, 2, 3],
        help="1=L1 only, 2=L1+L2 semantic, 3=L1+L2+L3 deep audit (default: 3)"
    )
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    if not Path(args.target).exists():
        print(f"Error: target not found: {args.target}")
        sys.exit(1)

    use_l2 = args.depth >= 2
    use_l3 = args.depth >= 3
    use_l4 = args.depth >= 3

    print(f"AgentVet scanning: {args.target}")
    print(f"Depth: L1 + {'L2 (semantic)' if use_l2 else ''} + {'L3 (deep audit)' if use_l3 else ''} + {'L4 (chain)' if use_l4 else ''}")
    print("─" * 50)

    engine = ScanEngine(use_l2=use_l2, use_l3=use_l3, use_l4=use_l4)
    report = engine.scan(args.target)

    if args.json:
        data = report.to_dict()
        data["tiers"] = {
            "l1_findings": len(report.findings) + report.l2_filtered_count,
            "l2_dropped": report.l2_filtered_count,
            "l2_model": report.l2_model,
            "l2_duration_ms": round(report.l2_duration_ms, 0),
            "l3_audited": report.l3_audited_count,
            "l3_model": report.l3_model,
            "l3_duration_ms": round(report.l3_duration_ms, 0),
            "l4_chain": report.chain is not None,
        }
        data["owasp_coverage"] = report.owasp_coverage
        data["attack_chain"] = report._chain_to_dict()
        print(json.dumps(data, ensure_ascii=False, indent=2))
        return

    # Human-readable output
    l1_total = len(report.findings) + report.l2_filtered_count
    print(f"L1  raw findings : {l1_total}")
    if use_l2:
        print(f"L2  dropped noise: {report.l2_filtered_count}  ({report.l2_model}, {report.l2_duration_ms:.0f}ms)")
    print(f"L2→ findings     : {len(report.findings)}")
    if use_l3:
        print(f"L3  deep audit   : {report.l3_audited_count} findings  ({report.l3_model}, {report.l3_duration_ms:.0f}ms)")
    print(f"Score            : {report.score}")
    print(f"Duration         : {report.duration_ms:.0f}ms")
    print(f"Checks           : {report.total_checks}")
    print("─" * 50)

    if not report.findings:
        print("\nNo vulnerabilities found. Your agent is clean.")
        return

    severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
    findings = sorted(report.findings, key=lambda f: severity_order.get(f.severity, 99))

    print(f"\nFindings ({len(findings)}):")
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
        has_l3 = bool(f.attack_demo)
        l3_badge = " [L3]" if has_l3 else ""
        print(f"  [{sev.upper():7s}]{l3_badge} {f.title[:60]}")
        print(f"           {f.file_path}:{f.line_number}")
        if has_l3:
            # Show first line of attack path
            first_line = f.attack_demo.split("\n")[0] if f.attack_demo else ""
            print(f"           Attack: {first_line[:100]}")


if __name__ == "__main__":
    main()
