"""Markdown reports for triage and diff results.

Every value that comes from a scan or an exceptions file is untrusted: resource
names, status details, titles and exception owners/reasons can be set by anyone
with access to the account or the config. Reports are Markdown that renderers
turn into HTML, so each such value goes through `escape()` or `code()` (or the
same methods of `Fmt`, which add account redaction):

- `escape()`: `&`, `<`, `>` are HTML-escaped, so no tags or entities get through.
  Backslash, backtick, `[`, `]` and `|` are backslash-escaped, so values cannot
  open code spans, form links or images, or break table cells.
- `code()`: wraps resource names and uids in a code span. Code span content is
  literal (never HTML, never entity-decoded), so it is not HTML-escaped. Values
  containing a backtick, `<`, `>`, `&` or `|` fall back to `escape()` instead:
  a backtick could close the span, `|` cannot be escaped reliably inside a code
  span in a GFM table cell, and raw tags stay out of the Markdown source entirely.
- Whitespace (including newlines) is collapsed to single spaces in both.

`*` and `_` are not escaped; they can only add emphasis. Remediation links are
rendered as links only when they are plain https URLs; anything else is shown as
escaped text.

With redaction on, every untrusted value has the scan's account IDs and any other
standalone 12-digit number replaced with `<account>` before it is escaped. Only
account IDs are redacted: user, role, trail and bucket names, IP addresses and
other identifiers stay as they are.

Output contains no timestamps, so the same inputs give identical reports.
"""

import html
import re
from collections import Counter
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import date

from cspm_triage.diff import DiffEntry, DiffResult, GoneReason, NewReason, severity_increased
from cspm_triage.models import Finding
from cspm_triage.triage import (
    SEVERITY_ORDER,
    UNKNOWN_SEVERITY_RANK,
    AcceptedRisk,
    Suppressed,
    TriageResult,
    severity_rank,
)

MARKDOWN_SPECIAL_RE = re.compile(r"([\\`\[\]|])")
SAFE_URL_RE = re.compile(r"https://[^\s<>()\[\]`|\\\"']+")
CODE_UNSAFE_RE = re.compile(r"[`<>&|]")
ACCOUNT_ID_RE = re.compile(r"(?<!\d)\d{12}(?!\d)")
REDACTED = "<account>"
REDACTION_NOTE = "Account IDs redacted; other identifiers are not."
NOTE_MAX = 60

# (short label for tables, legend text)
NEW_REASON_LABELS: dict[NewReason, tuple[str, str]] = {
    NewReason.CHECK_REGION_NOT_IN_BASELINE: (
        "region not in baseline",
        "the baseline has no findings for this check in this region (scan scope "
        "changed, or resources were created there)",
    ),
    NewReason.NEW_FINDING: ("new", "the check ran in the baseline but did not report this"),
    NewReason.REGRESSION: ("regression", "was PASS in the baseline"),
    NewReason.NOW_MATCHES_FILTER: (
        "now in filters",
        "was in the baseline but excluded by the status or severity filters",
    ),
    NewReason.NO_LONGER_ACCEPTED: (
        "exception ended",
        "an exception covered it in the baseline but no longer matches (see Source)",
    ),
}
GONE_REASON_LABELS: dict[GoneReason, tuple[str, str]] = {
    GoneReason.CHECK_PASSING: (
        "likely fixed",
        "the check still runs in this region and all its findings PASS; not counted as resolved",
    ),
    GoneReason.CHECK_NOT_RUN: ("not run", "no findings at all for this check in this region"),
    GoneReason.RESOURCE_NOT_REPORTED: (
        "not reported",
        "the check ran but did not report this resource (deleted or replaced?)",
    ),
}


@dataclass(frozen=True, slots=True)
class ReportContext:
    """Facts about the run that the report header shows."""

    scans: tuple[tuple[str, str], ...]  # (label, file name), e.g. ("Scan", "x.ocsf.json")
    today: date
    statuses: tuple[str, ...]
    min_severity: str
    exceptions: str  # where accepted risks came from, e.g. "none (... not found)"
    gate: tuple[str, ...]  # reasons the CI gate fails; empty means it passes
    accounts: tuple[str, ...] = ()  # account uids covered by the scan(s), sorted
    redact: bool = False


# --- escaping, redaction and cells ----------------------------------------------


def _escape_clean(text: str) -> str:
    return MARKDOWN_SPECIAL_RE.sub(r"\\\1", html.escape(text, quote=False))


def _code_clean(text: str) -> str:
    if not text:
        return ""
    if CODE_UNSAFE_RE.search(text.replace(REDACTED, "")):
        return _escape_clean(text)
    return f"`{text}`"


def redact_accounts(text: str, accounts: Iterable[str] = ()) -> str:
    """Replace known account uids and any standalone 12-digit number with <account>."""
    for account in sorted({a for a in accounts if a}, key=len, reverse=True):
        text = text.replace(account, REDACTED)
    return ACCOUNT_ID_RE.sub(REDACTED, text)


def redaction_leaks(text: str, accounts: Iterable[str] = ()) -> bool:
    """True if a rendered report still contains an account uid or 12-digit number."""
    return bool(ACCOUNT_ID_RE.search(text)) or any(a and a in text for a in accounts)


@dataclass(frozen=True, slots=True)
class Fmt:
    """Formats untrusted values: whitespace collapse, optional redaction, escaping."""

    accounts: tuple[str, ...] = ()
    redact: bool = False

    @classmethod
    def from_context(cls, ctx: ReportContext) -> "Fmt":
        return cls(ctx.accounts, ctx.redact)

    @property
    def multi_account(self) -> bool:
        return len(self.accounts) > 1

    def clean(self, value: object) -> str:
        """Collapsed and (if enabled) redacted, but not yet escaped."""
        text = " ".join(str(value).split())
        return redact_accounts(text, self.accounts) if self.redact else text

    def text(self, value: object) -> str:
        return _escape_clean(self.clean(value))

    def code(self, value: object) -> str:
        return _code_clean(self.clean(value))

    def link(self, url: str) -> str:
        clean = self.clean(url)
        return f"<{clean}>" if SAFE_URL_RE.fullmatch(clean) else _escape_clean(clean)


def escape(value: object) -> str:
    """Make an untrusted value safe as plain text in Markdown and HTML."""
    return Fmt().text(value)


def code(value: object) -> str:
    """An untrusted value as a code span, or as escaped text if it isn't code-safe."""
    return Fmt().code(value)


def link(url: str) -> str:
    """Render a plain https URL as an autolink; anything else as escaped text."""
    return Fmt().link(url)


def short_name(uid: str, *, multi_account: bool = False) -> str:
    """The part of an ARN after the account, e.g. user/admin; other uids unchanged.

    With several accounts the account is kept (account:user/admin) so rows from
    different accounts stay distinguishable.
    """
    parts = uid.split(":", 5)
    if len(parts) != 6 or parts[0] != "arn":
        return uid
    account, rest = parts[4], parts[5]
    return f"{account}:{rest}" if account and multi_account else rest


def severity_label(severity: str, fmt: Fmt | None = None) -> str:
    """Canonical name for known severities; the escaped raw value otherwise."""
    rank = severity_rank(severity)
    if rank == UNKNOWN_SEVERITY_RANK:
        return (fmt or Fmt()).text(severity)
    return SEVERITY_ORDER[rank].capitalize()


def _short_names(fmt: Fmt, finding: Finding) -> tuple[str, ...]:
    return tuple(short_name(u, multi_account=fmt.multi_account) for u in finding.resource_uids)


def _differing_parts(token_lists: Sequence[Sequence[str]], joiner: str) -> list[str]:
    """For each token list, the part that differs from the others, with … for cut parts."""
    shortest = min(len(t) for t in token_lists)
    pre = 0
    while pre < shortest and len({t[pre] for t in token_lists}) == 1:
        pre += 1
    suf = 0
    while suf < shortest - pre and len({t[len(t) - 1 - suf] for t in token_lists}) == 1:
        suf += 1
    parts = []
    for tokens in token_lists:
        middle = joiner.join(tokens[pre : len(tokens) - suf])
        if not middle:
            parts.append("")
            continue
        if len(middle) > NOTE_MAX:
            middle = middle[: NOTE_MAX - 1] + "…"
        lead = "…" + joiner if pre else ""
        tail = joiner + "…" if suf else ""
        parts.append(f"{lead}{middle}{tail}")
    return parts


def _distinct(parts: Sequence[str]) -> bool:
    return all(parts) and len(set(parts)) == len(parts)


def distinguishing_notes(fmt: Fmt, findings: Sequence[Finding]) -> list[str]:
    """Per finding, what tells it apart from others with the same check and short names.

    Uses the differing part of status_detail; if the details don't tell them apart,
    the differing part of the finding uid. Values are redacted before they are cut,
    so a cut never leaves part of an account ID. Returns '' where no note is needed.
    """
    groups: dict[tuple[str, tuple[str, ...]], list[int]] = {}
    for i, finding in enumerate(findings):
        groups.setdefault((finding.event_code, _short_names(fmt, finding)), []).append(i)
    notes = [""] * len(findings)
    for indexes in groups.values():
        if len(indexes) < 2:
            continue
        details = [fmt.clean(findings[i].status_detail).split() for i in indexes]
        parts = _differing_parts(details, " ")
        if not _distinct(parts):
            uids = [fmt.clean(findings[i].finding_uid).split("-") for i in indexes]
            parts = _differing_parts(uids, "-")
        if _distinct(parts):
            for i, part in zip(indexes, parts, strict=True):
                notes[i] = part
    return notes


def resource_cell(fmt: Fmt, finding: Finding, note: str = "") -> str:
    """Short resource names for a table cell, plus a distinguishing note if any."""
    lines = [fmt.code(name) for name in _short_names(fmt, finding)]
    if note:
        lines.append(fmt.text(note))
    return "<br>".join(lines)


def risk_source(fmt: Fmt, risk: AcceptedRisk) -> str:
    return f"{fmt.text(risk.source)} #{risk.position}"


def change(fmt: Fmt, values: tuple[str, str] | None) -> str:
    return "" if values is None else f"{fmt.text(values[0])} → {fmt.text(values[1])}"


def table(headers: Sequence[str], rows: Iterable[Sequence[str]]) -> list[str]:
    """A Markdown table; cells must already be escaped."""
    body = [f"| {' | '.join(row)} |" for row in rows]
    return [f"| {' | '.join(headers)} |", "|" + "---|" * len(headers), *body]


def section(heading: str, body: list[str]) -> list[str]:
    return [heading, "", *body, ""]


def legend(labels: Iterable[tuple[str, str]], used: Iterable[str]) -> list[str]:
    """Legend lines for the labels that appear in a table, in definition order."""
    used_set = set(used)
    lines = [f"- **{label}**: {text}" for label, text in labels if label in used_set]
    return ["", *lines] if lines else []


def _join(lines: list[str]) -> str:
    return "\n".join(lines).rstrip("\n") + "\n"


# --- shared parts ---------------------------------------------------------------


def _account_line(fmt: Fmt) -> list[str]:
    accounts = fmt.accounts
    if not accounts:
        return []
    if len(accounts) == 1:
        return [f"- Account: {fmt.text(accounts[0])}"]
    if fmt.redact:
        return [f"- Accounts: {len(accounts)} (redacted)"]
    return [f"- Accounts: {', '.join(fmt.text(a) for a in accounts)}"]


def header(title: str, ctx: ReportContext) -> list[str]:
    fmt = Fmt.from_context(ctx)
    gate = (
        f"**fail** (exit 1): {fmt.text('; '.join(ctx.gate))}" if ctx.gate else "**pass** (exit 0)"
    )
    return [
        f"# {title}",
        "",
        *(f"- {label}: {fmt.text(name)}" for label, name in ctx.scans),
        *_account_line(fmt),
        *([f"- Redaction: {REDACTION_NOTE}"] if ctx.redact else []),
        f"- Date: {ctx.today.isoformat()}",
        f"- Filters: status {fmt.text(', '.join(ctx.statuses))}; "
        f"minimum severity {fmt.text(ctx.min_severity)}",
        f"- Exceptions: {fmt.text(ctx.exceptions)}",
        f"- Gate: {gate}",
        "",
    ]


def _severity_order(labels: Iterable[str]) -> list[str]:
    return sorted(set(labels), key=lambda label: (severity_rank(label), label))


def warnings_section(fmt: Fmt, warnings: Sequence[str]) -> list[str]:
    if not warnings:
        return []
    return section("## Warnings", [f"- {fmt.text(w)}" for w in warnings])


# --- triage report ----------------------------------------------------------------


def _triage_summary(fmt: Fmt, result: TriageResult) -> list[str]:
    attention = Counter(severity_label(f.severity, fmt) for f in result.attention)
    accepted = Counter(severity_label(s.finding.severity, fmt) for s in result.accepted)
    rows = [
        [label, str(attention[label]), str(accepted[label])]
        for label in _severity_order([*attention, *accepted])
    ]
    rows.append(["**Total**", str(len(result.attention)), str(len(result.accepted))])
    return table(["Severity", "Needs attention", "Accepted"], rows)


def attention_block(fmt: Fmt, finding: Finding) -> list[str]:
    """One finding: heading, short resources and region, full uids, detail, remediation."""
    short = ", ".join(fmt.code(name) for name in _short_names(fmt, finding))
    lines = [
        f"- Resource: {short} ({fmt.text(finding.region)})",
        *(f"- UID: {fmt.code(uid)}" for uid in finding.resource_uids),
        f"- Detail: {fmt.text(finding.status_detail)}",
    ]
    if finding.remediation_references:
        lines.append(f"- Remediation: {fmt.link(finding.remediation_references[0])}")
    heading = f"### {severity_label(finding.severity, fmt)} · {fmt.text(finding.event_code)}"
    return section(heading, lines)


def _attention_section(fmt: Fmt, findings: Sequence[Finding]) -> list[str]:
    if not findings:
        return []
    lines = [f"## Needs attention ({len(findings)})", ""]
    for finding in findings:
        lines += attention_block(fmt, finding)
    return lines


RiskKey = tuple[str, int]  # (source, position)


def group_by_risk(accepted: Iterable[Suppressed]) -> list[tuple[AcceptedRisk, list[Finding]]]:
    """Accepted findings grouped by exception, sorted by expiry date, source, position."""
    groups: dict[RiskKey, tuple[AcceptedRisk, list[Finding]]] = {}
    for item in accepted:
        key = (item.risk.source, item.risk.position)
        groups.setdefault(key, (item.risk, []))[1].append(item.finding)
    return sorted(groups.values(), key=lambda g: (g[0].expires, g[0].source, g[0].position))


def _covered_line(fmt: Fmt, finding: Finding, note: str) -> str:
    names = ", ".join(fmt.code(name) for name in _short_names(fmt, finding))
    suffix = f" — {fmt.text(note)}" if note else ""
    return f"  - {names} ({fmt.text(finding.region)}){suffix}"


def risk_block(fmt: Fmt, risk: AcceptedRisk, findings: Sequence[Finding]) -> list[str]:
    notes = distinguishing_notes(fmt, findings)
    return section(
        f"### #{risk.position} · {fmt.text(risk.check_id)}",
        [
            f"- Expires: {risk.expires.isoformat()}",
            f"- Owner: {fmt.text(risk.owner)}",
            f"- Source: {risk_source(fmt, risk)}",
            f"- Reason: {fmt.text(risk.reason)}",
            f"- Covers ({len(findings)}):",
            *(_covered_line(fmt, f, n) for f, n in zip(findings, notes, strict=True)),
        ],
    )


def _accepted_section(fmt: Fmt, accepted: Sequence[Suppressed]) -> list[str]:
    if not accepted:
        return []
    groups = group_by_risk(accepted)
    rows = [
        [f"#{risk.position}", fmt.text(risk.check_id), str(len(fs)), risk.expires.isoformat()]
        for risk, fs in groups
    ]
    lines = section(
        f"## Accepted risks ({len(accepted)})", table(["#", "Check", "Findings", "Expires"], rows)
    )
    for risk, findings in groups:
        lines += risk_block(fmt, risk, findings)
    return lines


def render_triage(result: TriageResult, ctx: ReportContext) -> str:
    """Render a triage result as a Markdown report."""
    fmt = Fmt.from_context(ctx)
    return _join(
        [
            *header("CSPM triage report", ctx),
            *section("## Summary", _triage_summary(fmt, result)),
            *_attention_section(fmt, result.attention),
            *_accepted_section(fmt, result.accepted),
            *warnings_section(fmt, result.warnings),
        ]
    )


# --- diff report --------------------------------------------------------------------


def _shown(entry: DiffEntry) -> Finding:
    finding = entry.current if entry.current is not None else entry.baseline
    if finding is None:
        raise ValueError(f"diff entry {entry.key!r} has no finding on either side")
    return finding


def new_label(entry: DiffEntry) -> str:
    return "" if entry.new_reason is None else NEW_REASON_LABELS[entry.new_reason][0]


def gone_label(entry: DiffEntry) -> str:
    return "" if entry.gone_reason is None else GONE_REASON_LABELS[entry.gone_reason][0]


def _breakdown(labels: Iterable[str]) -> str:
    counts = Counter(label for label in labels if label)
    return "; ".join(f"{label}: {n}" for label, n in sorted(counts.items()))


def _diff_summary(result: DiffResult) -> list[str]:
    increased = sum(severity_increased(e) for e in result.persisting)
    status_changed = sum(e.status_change is not None for e in result.persisting)
    persisting = f"severity increased: {increased}; status changed: {status_changed}"
    rows = [
        ["New", str(len(result.new)), _breakdown(new_label(e) for e in result.new)],
        ["Persisting", str(len(result.persisting)), persisting],
        ["Resolved", str(len(result.resolved)), ""],
        ["Filtered out", str(len(result.filtered_out)), ""],
        ["Accepted", str(len(result.accepted)), ""],
        ["Gone", str(len(result.gone)), _breakdown(gone_label(e) for e in result.gone)],
    ]
    return table(["Category", "Count", "Breakdown"], rows)


def _status(finding: Finding | None) -> str:
    return "" if finding is None else finding.status


def _status_severity(fmt: Fmt, finding: Finding | None) -> str:
    if finding is None:
        return ""
    return f"{fmt.text(finding.status)} / {severity_label(finding.severity, fmt)}"


def _new_cells(fmt: Fmt, entry: DiffEntry) -> list[str]:
    reason = new_label(entry)
    if entry.accepted_by is not None:
        reason = f"{reason} (was {risk_source(fmt, entry.accepted_by)})"
    return [reason, fmt.text(_shown(entry).status_detail)]


def _accepted_cells(fmt: Fmt, entry: DiffEntry) -> list[str]:
    risk = entry.accepted_by
    if risk is None:
        return ["", "", "", ""]
    return [
        fmt.text(risk.owner),
        fmt.text(risk.reason),
        risk.expires.isoformat(),
        risk_source(fmt, risk),
    ]


Cells = Callable[[Fmt, DiffEntry], list[str]]


@dataclass(frozen=True, slots=True)
class _DiffSection:
    title: str
    columns: tuple[str, ...]
    cells: Cells
    legend: tuple[tuple[str, str], ...] = ()
    label: Callable[[DiffEntry], str] | None = None


DIFF_SECTIONS: dict[str, _DiffSection] = {
    "new": _DiffSection(
        "New",
        ("Reason", "Detail"),
        _new_cells,
        tuple(NEW_REASON_LABELS.values()),
        new_label,
    ),
    "persisting": _DiffSection(
        "Persisting",
        ("Status change", "Severity change"),
        lambda f, e: [change(f, e.status_change), change(f, e.severity_change)],
    ),
    "resolved": _DiffSection(
        "Resolved",
        ("Status",),
        lambda f, e: [change(f, (_status(e.baseline), _status(e.current)))],
    ),
    "filtered_out": _DiffSection(
        "Filtered out",
        ("Now (status / severity)",),
        lambda f, e: [_status_severity(f, e.current)],
    ),
    "accepted": _DiffSection("Accepted", ("Owner", "Reason", "Expires", "Source"), _accepted_cells),
    "gone": _DiffSection(
        "Gone",
        ("Reason",),
        lambda f, e: [gone_label(e)],
        tuple(GONE_REASON_LABELS.values()),
        gone_label,
    ),
}


def _diff_section(fmt: Fmt, spec: _DiffSection, entries: Sequence[DiffEntry]) -> list[str]:
    if not entries:
        return []
    findings = [_shown(e) for e in entries]
    notes = distinguishing_notes(fmt, findings)
    rows = [
        [
            severity_label(f.severity, fmt),
            fmt.text(f.event_code),
            resource_cell(fmt, f, note),
            fmt.text(f.region),
            *spec.cells(fmt, e),
        ]
        for e, f, note in zip(entries, findings, notes, strict=True)
    ]
    body = table(["Severity", "Check", "Resource", "Region", *spec.columns], rows)
    if spec.label is not None:
        body += legend(spec.legend, (spec.label(e) for e in entries))
    return section(f"## {spec.title} ({len(entries)})", body)


def render_diff(result: DiffResult, ctx: ReportContext) -> str:
    """Render a diff result as a Markdown report."""
    fmt = Fmt.from_context(ctx)
    lines = [*header("CSPM scan diff", ctx), *section("## Summary", _diff_summary(result))]
    for name, spec in DIFF_SECTIONS.items():
        lines += _diff_section(fmt, spec, getattr(result, name))
    lines += warnings_section(fmt, result.warnings)
    return _join(lines)
