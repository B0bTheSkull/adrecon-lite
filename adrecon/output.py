"""Output formatting for ADRecon-Lite."""

from __future__ import annotations

import json
from dataclasses import asdict

from adrecon.findings import Finding


SEVERITY_COLOR = {
    "critical": "\033[1;91m",
    "high": "\033[91m",
    "medium": "\033[93m",
    "low": "\033[94m",
}
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"


def _badge(severity: str, color: bool) -> str:
    label = f"[{severity.upper():>8}]"
    if not color:
        return label
    return f"{SEVERITY_COLOR.get(severity, '')}{label}{RESET}"


def print_text(findings: list[Finding], record_count: int, color: bool = True) -> None:
    print(f"\n{BOLD if color else ''}ADRecon-Lite{RESET if color else ''}")
    print(
        f"{DIM if color else ''}Records inspected: {record_count}  |  "
        f"Findings: {len(findings)}{RESET if color else ''}\n"
    )
    if not findings:
        print("No security findings.")
        return

    sep = "─" * 80
    print(sep)
    for f in findings:
        print(f"{_badge(f.severity, color)} {BOLD if color else ''}{f.title}{RESET if color else ''}")
        print(f"  account: {f.sam_account_name}")
        if f.distinguished_name:
            print(f"  dn:      {f.distinguished_name}")
        print(f"  detail:  {f.detail}")
        if f.extra:
            for k, v in f.extra.items():
                if isinstance(v, list) and len(v) > 3:
                    v = f"{v[:3]} ... ({len(v)} total)"
                print(f"  {k}: {v}")
        print(sep)

    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    summary = "  ".join(f"{_badge(s, color)} {counts[s]}" for s in ("critical", "high", "medium", "low") if s in counts)
    print(f"\nSummary: {summary}")


def print_json(findings: list[Finding], record_count: int) -> None:
    payload = {
        "records_inspected": record_count,
        "total_findings": len(findings),
        "findings": [asdict(f) for f in findings],
    }
    print(json.dumps(payload, indent=2, default=str))
