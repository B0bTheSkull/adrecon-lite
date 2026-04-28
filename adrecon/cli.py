"""Command-line interface for ADRecon-Lite."""

import argparse
import getpass
import json
import sys
from pathlib import Path

from adrecon import __version__
from adrecon.findings import find_all
from adrecon.output import print_json, print_text


def _load_records_offline(path: Path) -> list[dict]:
    if not path.exists():
        print(f"error: records file not found: {path}", file=sys.stderr)
        sys.exit(2)
    data = json.loads(path.read_text())
    if not isinstance(data, list):
        print(f"error: records file must be a JSON array, got {type(data).__name__}", file=sys.stderr)
        sys.exit(2)
    return data


def _load_records_live(args: argparse.Namespace) -> list[dict]:
    from adrecon.client import fetch_records

    password = args.password or getpass.getpass(prompt=f"Password for {args.user}: ")
    return fetch_records(
        server=args.server,
        user=args.user,
        password=password,
        base_dn=args.base_dn,
        use_ssl=args.ssl,
    )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="adrecon",
        description="Lightweight Active Directory enumeration and dangerous-config detector.",
    )
    p.add_argument("--version", action="version", version=f"adrecon {__version__}")

    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--server", help="LDAP server URI, e.g. ldap://dc.lab.local")
    mode.add_argument(
        "--offline",
        action="store_true",
        help="Read records from --records JSON instead of querying live AD",
    )

    p.add_argument("--user", help="Bind user (e.g. CORP\\\\analyst or CN=analyst,...)")
    p.add_argument("--password", help="Bind password (omit to be prompted)")
    p.add_argument("--base-dn", help="Search base DN, e.g. DC=lab,DC=local")
    p.add_argument("--ssl", action="store_true", help="Use LDAPS (port 636)")
    p.add_argument("--records", type=Path, help="Path to JSON records file (with --offline)")
    p.add_argument("--json", action="store_true", help="Emit JSON output")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI color")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if args.offline:
        if not args.records:
            print("error: --offline requires --records FILE", file=sys.stderr)
            return 2
        records = _load_records_offline(args.records)
    else:
        if not (args.user and args.base_dn):
            print("error: --server requires --user and --base-dn", file=sys.stderr)
            return 2
        records = _load_records_live(args)

    findings = find_all(records)
    color = not args.no_color and sys.stdout.isatty()
    if args.json:
        print_json(findings, record_count=len(records))
    else:
        print_text(findings, record_count=len(records), color=color)

    has_critical_or_high = any(f.severity in ("critical", "high") for f in findings)
    return 1 if has_critical_or_high else 0


if __name__ == "__main__":
    sys.exit(main())
