"""Command-line entry point: `cspm-triage triage` and `cspm-triage diff`."""

import argparse
import sys
from collections.abc import Callable, Sequence
from datetime import date
from pathlib import Path

from cspm_triage.diff import DiffResult, diff_scans, severity_increased
from cspm_triage.models import Finding
from cspm_triage.parser import load_findings
from cspm_triage.report import ReportContext, redaction_leaks, render_diff, render_triage
from cspm_triage.triage import (
    DEFAULT_MIN_SEVERITY,
    KNOWN_STATUSES,
    SEVERITY_ORDER,
    AcceptedRisk,
    TriageResult,
    expired_warnings,
    load_accepted_risks,
    triage,
)

DEFAULT_EXCEPTIONS = Path("config/exceptions.toml")
EXIT_OK = 0
EXIT_GATE_FAILED = 1
EXIT_ERROR = 2

EXIT_CODES_HELP = """\
exit codes (for CI gates):
  0  triage: no finding needs attention
     diff:   nothing new, no persisting finding got more severe, no expired exception
  1  triage: at least one finding needs attention
     diff:   at least one new finding, OR a persisting finding whose severity
             increased, OR an expired exception in the exceptions file
             (otherwise these would show only as persisting plus a warning)
  2  usage or input error, including an empty scan: a failed Prowler run must
     never pass a gate

Reports contain real resource ARNs and account IDs. Write them to stdout or to
reports/ (gitignored); never commit them. --redact-account removes account IDs
only; user, role, trail and bucket names, IP addresses and other identifiers
stay in the report.
"""


class CliError(Exception):
    """An input problem reported to the user with exit code 2."""


# --- argument parsing -------------------------------------------------------------


def parse_statuses(value: str) -> tuple[str, ...]:
    """Parse --status FAIL,MANUAL into upper-case known statuses."""
    statuses = tuple(dict.fromkeys(p.strip().upper() for p in value.split(",") if p.strip()))
    unknown = [s for s in statuses if s not in KNOWN_STATUSES]
    if not statuses or unknown:
        known = ", ".join(sorted(KNOWN_STATUSES))
        raise argparse.ArgumentTypeError(f"expected a comma-separated list of: {known}")
    return statuses


def parse_date(value: str) -> date:
    """Parse --today YYYY-MM-DD."""
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected a date as YYYY-MM-DD") from exc


def _common_options() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--exceptions",
        type=Path,
        help=f"accepted-risks TOML file (default: {DEFAULT_EXCEPTIONS} if it exists)",
    )
    common.add_argument(
        "--status",
        type=parse_statuses,
        default=("FAIL",),
        help="comma-separated statuses to report, e.g. FAIL,MANUAL (default: FAIL)",
    )
    common.add_argument(
        "--min-severity",
        type=str.lower,
        choices=SEVERITY_ORDER,
        default=DEFAULT_MIN_SEVERITY,
        help=f"lowest severity to report (default: {DEFAULT_MIN_SEVERITY})",
    )
    common.add_argument(
        "--today",
        type=parse_date,
        help="date for exception expiry, YYYY-MM-DD (default: today; set it for "
        "reproducible output)",
    )
    common.add_argument(
        "--output", type=Path, help="write the Markdown report here (default: stdout)"
    )
    common.add_argument(
        "--redact-account",
        action="store_true",
        help="replace account IDs (the scans' accounts and any other standalone 12-digit "
        "number) with <account>. Account IDs only: user, role, trail and bucket names, "
        "IP addresses and other identifiers are NOT removed",
    )
    return common


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser with the triage and diff subcommands."""
    common = _common_options()
    parser = argparse.ArgumentParser(
        prog="cspm-triage",
        description="Triage and compare Prowler OCSF scans.",
        epilog=EXIT_CODES_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    commands = parser.add_subparsers(dest="command", required=True)
    for name, help_text in (
        ("triage", "report findings that need attention in one scan"),
        ("diff", "compare a baseline scan with a current scan"),
    ):
        sub = commands.add_parser(
            name,
            parents=[common],
            help=help_text,
            description=help_text,
            epilog=EXIT_CODES_HELP,
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        if name == "triage":
            sub.add_argument("scan", type=Path, help="Prowler OCSF JSON scan")
        else:
            sub.add_argument("baseline", type=Path, help="earlier Prowler OCSF JSON scan")
            sub.add_argument("current", type=Path, help="later Prowler OCSF JSON scan")
    return parser


# --- inputs and outputs ---------------------------------------------------------------


def resolve_exceptions(path: Path | None) -> tuple[list[AcceptedRisk], str]:
    """Load accepted risks and describe where they came from."""
    if path is not None:
        if not path.is_file():
            raise CliError(f"exceptions file not found: {path}")
        risks = load_accepted_risks(path)
        return risks, f"{path.as_posix()} ({len(risks)} entries)"
    if DEFAULT_EXCEPTIONS.is_file():
        risks = load_accepted_risks(DEFAULT_EXCEPTIONS)
        return risks, f"{DEFAULT_EXCEPTIONS.as_posix()} ({len(risks)} entries, default)"
    return [], f"none ({DEFAULT_EXCEPTIONS.as_posix()} not found)"


def load_scan(path: Path, label: str) -> list[Finding]:
    """Load a scan; an empty scan is an error because it usually means the scan failed."""
    findings = load_findings(path)
    if not findings:
        raise CliError(f"{label} has no findings; the scan probably failed")
    return findings


def check_redaction(text: str, ctx: ReportContext) -> None:
    """Refuse to write a redacted report that still contains an account ID."""
    if ctx.redact and redaction_leaks(text, ctx.accounts):
        raise CliError("redaction check failed: an account ID remains in the report; not written")


def write_report(text: str, output: Path | None) -> None:
    """Write the report to stdout or to a file whose directory must exist."""
    if output is None:
        sys.stdout.write(text)
        return
    if not output.parent.is_dir():
        raise CliError(
            f"output directory does not exist: {output.parent} (create it, e.g. mkdir reports)"
        )
    output.write_text(text, encoding="utf-8")


def _context(
    args: argparse.Namespace,
    scans: tuple[tuple[str, str], ...],
    findings: Sequence[Finding],
    source: str,
    gate: Sequence[str],
) -> ReportContext:
    return ReportContext(
        scans=scans,
        today=args.today,
        statuses=args.status,
        min_severity=args.min_severity,
        exceptions=source,
        gate=tuple(gate),
        accounts=tuple(sorted({f.account_uid for f in findings})),
        redact=args.redact_account,
    )


def render_and_write(
    render: Callable[[ReportContext], str], ctx: ReportContext, output: Path | None
) -> None:
    text = render(ctx)
    check_redaction(text, ctx)
    write_report(text, output)


def _finish(summary: str, source: str, output: Path | None, gate: Sequence[str]) -> int:
    code = EXIT_GATE_FAILED if gate else EXIT_OK
    where = f"; report: {output}" if output is not None else ""
    print(f"{summary}; exceptions: {source}{where}; exit {code}", file=sys.stderr)
    return code


# --- gates ---------------------------------------------------------------------------------


def triage_gate(result: TriageResult) -> tuple[str, ...]:
    """Reasons the triage gate fails; empty means it passes."""
    n = len(result.attention)
    return (f"{n} finding(s) need attention",) if n else ()


def diff_gate(result: DiffResult, expired: int) -> tuple[str, ...]:
    """Reasons the diff gate fails: new findings, severity increases, expired exceptions."""
    increased = sum(severity_increased(e) for e in result.persisting)
    reasons = [
        (len(result.new), f"{len(result.new)} new finding(s)"),
        (increased, f"{increased} persisting finding(s) with increased severity"),
        (expired, f"{expired} expired exception(s)"),
    ]
    return tuple(text for count, text in reasons if count)


# --- commands ------------------------------------------------------------------------------


def run_triage(args: argparse.Namespace) -> int:
    risks, source = resolve_exceptions(args.exceptions)
    findings = load_scan(args.scan, "scan")
    result = triage(
        findings, risks, args.today, statuses=args.status, min_severity=args.min_severity
    )
    gate = triage_gate(result)
    ctx = _context(args, (("Scan", args.scan.name),), findings, source, gate)
    render_and_write(lambda c: render_triage(result, c), ctx, args.output)
    summary = (
        f"triage: {len(result.attention)} need attention, {len(result.accepted)} accepted, "
        f"{len(result.warnings)} warning(s)"
    )
    return _finish(summary, source, args.output, gate)


def run_diff(args: argparse.Namespace) -> int:
    risks, source = resolve_exceptions(args.exceptions)
    baseline = load_scan(args.baseline, "baseline scan")
    current = load_scan(args.current, "current scan")
    result = diff_scans(
        baseline, current, risks, args.today, statuses=args.status, min_severity=args.min_severity
    )
    expired = len(expired_warnings(risks, args.today))
    gate = diff_gate(result, expired)
    scans = (("Baseline", args.baseline.name), ("Current", args.current.name))
    ctx = _context(args, scans, [*baseline, *current], source, gate)
    render_and_write(lambda c: render_diff(result, c), ctx, args.output)
    increased = sum(severity_increased(e) for e in result.persisting)
    summary = (
        f"diff: {len(result.new)} new, {len(result.persisting)} persisting "
        f"({increased} severity increased), {len(result.resolved)} resolved, "
        f"{len(result.filtered_out)} filtered out, {len(result.accepted)} accepted, "
        f"{len(result.gone)} gone, {expired} expired exception(s)"
    )
    return _finish(summary, source, args.output, gate)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI; returns the exit code (argparse exits with 2 on usage errors)."""
    args = build_parser().parse_args(argv)
    if args.today is None:
        args.today = date.today()
    handler = run_triage if args.command == "triage" else run_diff
    try:
        return handler(args)
    except (CliError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
