from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path
from typing import Any

try:
    from .config import Config, ConfigError, load_config
    from .discovery import discover
    from .models import Finding, Flag, ScanResult
except ImportError:  # pragma: no cover
    from config import Config, ConfigError, load_config
    from discovery import discover
    from models import Finding, Flag, ScanResult

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
DEAD_DEFAULTS = {False, 0, "false", "off", "disabled", "0", "no"}

INIT_TEMPLATE = r"""# flagrot configuration
[discovery]
include = ["**/*"]
exclude = [".git/**", "node_modules/**", "dist/**", "build/**", "__pycache__/**", ".venv/**"]
test_patterns = ["**/test*/**", "**/*_test.py", "**/tests/**"]
code_patterns = [
  "\\b(?:FEATURE|FLAG|ENABLE|USE)_[A-Z0-9_]{2,}\\b",
  "\\bfeature_flags?\\s*\\[\\s*['\"]([^'\"]+)['\"]\\s*\\]",
]
env_files = [".env", ".env.*", "*.env"]
config_extensions = [".json", ".yaml", ".yml", ".toml", ".ini", ".cfg"]
ignore_directive = "flagrot: ignore"

[rules]
fail_on = "medium"
expired_severity = "high"
stale_severity = "medium"
dead_default_severity = "low"

[reporting]
format = "human"

[git]
metadata = true
"""


def is_dead_default(flag: Flag) -> bool:
    default = flag.default
    if isinstance(default, str):
        default = default.strip().lower()
    if default not in DEAD_DEFAULTS:
        return False
    rollout = flag.rollout or {}
    percentage = None
    for key in ("percentage", "percent", "rollout"):
        if key in rollout:
            percentage = rollout[key]
            break
    if percentage is None:
        return True
    if isinstance(percentage, str):
        try:
            percentage = float(percentage)
        except ValueError:
            return True
    return percentage in (0, 0.0, False, None)


def evaluate_findings(flags: list[Flag], usages: list[Any], config: Config) -> list[Finding]:
    findings: list[Finding] = []
    today = date.today()
    by_flag: dict[str, list[Any]] = {}
    for usage in usages:
        by_flag.setdefault(usage.flag_name, []).append(usage)

    for flag in flags:
        flag_usages = by_flag.get(flag.name, [])
        production = [usage for usage in flag_usages if getattr(usage, "kind", "code") != "test"]
        tests = [usage for usage in flag_usages if getattr(usage, "kind", "code") == "test"]
        location_path = flag_usages[0].path if flag_usages else None
        location_line = flag_usages[0].line if flag_usages else None
        if not location_path and ":" in flag.source:
            location_path = flag.source.split(":", 1)[0]

        if flag.expiry is not None and flag.expiry < today:
            findings.append(
                Finding(
                    flag_name=flag.name,
                    rule="expired",
                    severity=config.expired_severity,
                    message=f"Flag '{flag.name}' expired on {flag.expiry}.",
                    path=location_path,
                    line=location_line,
                )
            )
        if is_dead_default(flag):
            findings.append(
                Finding(
                    flag_name=flag.name,
                    rule="dead-default",
                    severity=config.dead_default_severity,
                    message=f"Default value makes '{flag.name}' effectively dead.",
                    path=location_path,
                    line=location_line,
                )
            )
        if not production:
            if tests:
                rule = "test-only"
                message = f"Flag '{flag.name}' has only test references."
            else:
                rule = "unused"
                message = f"Flag '{flag.name}' has no production references."
            findings.append(
                Finding(
                    flag_name=flag.name,
                    rule=rule,
                    severity=config.stale_severity,
                    message=message,
                    path=location_path,
                    line=location_line,
                )
            )
    return findings


def finding_key(finding: Finding) -> tuple[str, str, str, int]:
    return (finding.flag_name, finding.rule, finding.path or "", finding.line or 0)


def perform_scan(root: Path, config: Config, baseline_path: str | None = None) -> tuple[ScanResult, list[Finding]]:
    flags, usages = discover(root, config)
    findings = evaluate_findings(flags, usages, config)
    baseline_keys: set[tuple[str, str, str, int]] = set()
    if baseline_path:
        path = Path(baseline_path)
        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                baseline_keys = {
                    finding_key(Finding.from_dict(item)) for item in data.get("findings", [])
                }
            except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError):
                baseline_keys = set()
    compared = [finding for finding in findings if finding_key(finding) not in baseline_keys]
    result = ScanResult(
        root=str(root),
        config_path=str(config.config_path) if config.config_path else None,
        flags=tuple(flags),
        usages=tuple(usages),
        findings=tuple(compared),
        metadata={
            "total_findings": len(findings),
            "baseline_findings": len(baseline_keys),
        },
    )
    return result, findings


def policy_violation(findings: list[Finding], threshold: str) -> bool:
    if threshold.lower() in {"none", "off", "false"}:
        return False
    minimum = SEVERITY_RANK.get(threshold.lower(), 2)
    return any(SEVERITY_RANK.get(finding.severity.lower(), 0) >= minimum for finding in findings)


def render_human(result: ScanResult) -> str:
    lines = [
        f"flagrot scan: {result.root}",
        f"flags={len(result.flags)} usages={len(result.usages)} findings={len(result.findings)}",
    ]
    if result.metadata.get("total_findings", len(result.findings)) != len(result.findings):
        lines[1] += f" (total={result.metadata['total_findings']})"
    if result.findings:
        lines.extend(["", "Findings:"])
        for finding in result.findings:
            location = ""
            if finding.path:
                location = f" [{finding.path}:{finding.line}]" if finding.line else f" [{finding.path}]"
            lines.append(
                f"  - ({finding.severity}) {finding.flag_name} [{finding.rule}]: {finding.message}{location}"
            )
    else:
        lines.extend(["", "No findings."])
    return "\n".join(lines)


def render_sarif(result: ScanResult) -> str:
    levels = {"info": "note", "low": "note", "medium": "warning", "high": "error", "critical": "error"}
    rules = sorted({finding.rule for finding in result.findings})
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {"driver": {"name": "flagrot", "rules": [{"id": rule} for rule in rules]}},
                "results": [
                    {
                        "ruleId": finding.rule,
                        "level": levels.get(finding.severity.lower(), "warning"),
                        "message": {"text": finding.message},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": finding.path},
                                    "region": {"startLine": finding.line or 1},
                                }
                            }
                        ]
                        if finding.path
                        else [],
                    }
                    for finding in result.findings
                ],
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def _add_scan_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("path", nargs="?", default=".")
    parser.add_argument("--config")
    parser.add_argument("--format", choices=["human", "json", "sarif"])
    parser.add_argument("--output")
    parser.add_argument("--fail-on", choices=["none", "info", "low", "medium", "high", "critical"])
    parser.add_argument("--baseline")
    parser.add_argument("--create-baseline")


def cmd_scan(args: argparse.Namespace) -> int:
    root = Path(args.path).resolve()
    try:
        config = load_config(root, getattr(args, "config", None))
    except ConfigError as exc:
        print(f"flagrot: {exc}", file=sys.stderr)
        return 2
    result, all_findings = perform_scan(root, config, getattr(args, "baseline", None))
    if getattr(args, "create_baseline", None):
        baseline_path = Path(args.create_baseline)
        baseline_path.parent.mkdir(parents=True, exist_ok=True)
        baseline_path.write_text(
            json.dumps({"root": str(root), "findings": [finding.to_dict() for finding in all_findings]}, indent=2)
        )
        print(f"Wrote baseline with {len(all_findings)} findings to {baseline_path}")
    fmt = getattr(args, "format", None) or config.report_format
    if fmt == "json":
        output = result.to_json()
    elif fmt == "sarif":
        output = render_sarif(result)
    else:
        output = render_human(result)
    if getattr(args, "output", None):
        Path(args.output).write_text(output)
    else:
        print(output)
    threshold = getattr(args, "fail_on", None) or config.fail_on
    return 1 if policy_violation(result.findings, threshold) else 0


def cmd_report(args: argparse.Namespace) -> int:
    return cmd_scan(args)


def cmd_init(args: argparse.Namespace) -> int:
    root = Path(args.path).resolve()
    target = root / ".flagrot.toml"
    if target.exists() and not args.force:
        print(f"flagrot: {target} already exists (use --force to overwrite)", file=sys.stderr)
        return 2
    target.write_text(INIT_TEMPLATE)
    print(f"Created {target}")
    return 0


def cmd_explain(args: argparse.Namespace) -> int:
    root = Path(args.path).resolve()
    try:
        config = load_config(root, getattr(args, "config", None))
    except ConfigError as exc:
        print(f"flagrot: {exc}", file=sys.stderr)
        return 2
    result, all_findings = perform_scan(root, config, None)
    flag = next((item for item in result.flags if item.name == args.flag), None)
    if flag is None:
        print(f"flagrot: flag not found: {args.flag}", file=sys.stderr)
        return 1
    print(f"Flag: {flag.name}")
    print(f"  owner: {flag.owner}")
    print(f"  created: {flag.created}")
    print(f"  expiry: {flag.expiry}")
    print(f"  default: {flag.default!r}")
    print(f"  rollout: {flag.rollout}")
    print(f"  source: {flag.source}")
    print("Usages:")
    for usage in result.usages:
        if usage.flag_name == args.flag:
            print(f"  {usage.path}:{usage.line} [{usage.kind}] {usage.context} :: {usage.snippet}")
    print("Findings:")
    for finding in all_findings:
        if finding.flag_name == args.flag:
            print(f"  ({finding.severity}) {finding.rule}: {finding.message}")
    return 0


def cmd_baseline(args: argparse.Namespace) -> int:
    if args.action == "create":
        args.create_baseline = args.output or args.baseline
        args.baseline = None
    else:
        args.create_baseline = None
    if not getattr(args, "format", None):
        args.format = None
    return cmd_scan(args)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="flagrot", description="Audit feature flags across code and configuration.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Scan a project for feature flags.")
    _add_scan_arguments(scan)
    scan.set_defaults(handler=cmd_scan)

    report = subparsers.add_parser("report", help="Generate a flag report.")
    _add_scan_arguments(report)
    report.set_defaults(handler=cmd_report)

    init = subparsers.add_parser("init", help="Create a default .flagrot.toml file.")
    init.add_argument("path", nargs="?", default=".")
    init.add_argument("--force", action="store_true")
    init.set_defaults(handler=cmd_init)

    explain = subparsers.add_parser("explain", help="Explain a single flag.")
    explain.add_argument("flag")
    explain.add_argument("--path", default=".", dest="path")
    explain.add_argument("--config")
    explain.set_defaults(handler=cmd_explain)

    baseline = subparsers.add_parser("baseline", help="Create or compare a baseline.")
    baseline.add_argument("action", choices=["create", "compare"])
    baseline.add_argument("path", nargs="?", default=".")
    baseline.add_argument("--baseline", default=".flagrot-baseline.json")
    baseline.add_argument("--output")
    baseline.add_argument("--config")
    baseline.add_argument("--format", choices=["human", "json", "sarif"])
    baseline.add_argument("--fail-on", choices=["none", "info", "low", "medium", "high", "critical"])
    baseline.set_defaults(handler=cmd_baseline)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handler = getattr(args, "handler", None)
    if handler is None:
        parser.print_help()
        return 2
    return int(handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
