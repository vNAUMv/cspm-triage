"""Tests for cspm_triage.report. All data is fake."""

import re
from dataclasses import replace
from datetime import date

import pytest

from cspm_triage.diff import Category, DiffEntry, DiffResult, GoneReason, NewReason, State
from cspm_triage.models import Finding
from cspm_triage.report import (
    GONE_REASON_LABELS,
    NEW_REASON_LABELS,
    REDACTION_NOTE,
    Fmt,
    ReportContext,
    code,
    distinguishing_notes,
    escape,
    group_by_risk,
    link,
    redact_accounts,
    redaction_leaks,
    render_diff,
    render_triage,
    short_name,
)
from cspm_triage.triage import AcceptedRisk, Suppressed, TriageResult

TODAY = date(2026, 6, 15)
ACCOUNT = "123456789012"
OTHER_ACCOUNT = "210987654321"
USER_ARN = f"arn:aws:iam::{ACCOUNT}:user/example-user"
HTML_ARN = f"arn:aws:iam::{ACCOUNT}:user/<img src=x onerror=alert(1)>"
BACKTICK_ARN = f"arn:aws:iam::{ACCOUNT}:user/evil`name"
POLICY_CHECK = "iam_policy_attached_only_to_group_or_roles"

FINDING = Finding(
    event_code="iam_user_hardware_mfa_enabled",
    status="FAIL",
    severity="High",
    title="IAM user has hardware MFA enabled",
    status_detail="User example-user does not have any type of MFA enabled.",
    finding_uid=f"prowler-aws-iam_user_hardware_mfa_enabled-{ACCOUNT}-us-east-1-example-user",
    account_uid=ACCOUNT,
    resource_uids=(USER_ARN,),
    region="us-east-1",
    remediation_desc="Enable hardware MFA.",
    remediation_references=("https://hub.prowler.com/check/iam_user_hardware_mfa_enabled",),
)
RISK = AcceptedRisk(
    check_id="iam_user_hardware_mfa_enabled",
    resources=(),
    region=None,
    reason="Break-glass user",
    owner="security-team@example.com",
    expires=date(2026, 12, 31),
    source="config/exceptions.toml",
    position=2,
)
CTX = ReportContext(
    scans=(("Scan", "scan.ocsf.json"),),
    today=TODAY,
    statuses=("FAIL",),
    min_severity="low",
    exceptions="config/exceptions.toml (1 entries)",
    gate=("1 finding(s) need attention",),
    accounts=(ACCOUNT,),
)
REDACTED_CTX = replace(CTX, redact=True)


def finding(**changes: object) -> Finding:
    return replace(FINDING, **changes)  # type: ignore[arg-type]


def policy_finding(policy: str) -> Finding:
    return finding(
        event_code=POLICY_CHECK,
        severity="Low",
        status_detail=f"User example-user has the policy {policy} attached.",
        finding_uid=f"prowler-aws-{POLICY_CHECK}-{ACCOUNT}-us-east-1-example-user-{policy}",
    )


def triage_report(
    attention: tuple[Finding, ...] = (),
    accepted: tuple[Suppressed, ...] = (),
    warnings: tuple[str, ...] = (),
    ctx: ReportContext = CTX,
) -> str:
    return render_triage(TriageResult(attention, accepted, warnings), ctx)


def entry(**changes: object) -> DiffEntry:
    base = DiffEntry(
        key=FINDING.finding_uid,
        category=Category.NEW,
        baseline=None,
        current=FINDING,
        baseline_state=State.ABSENT,
        current_state=State.ATTENTION,
        new_reason=NewReason.NEW_FINDING,
    )
    return replace(base, **changes)  # type: ignore[arg-type]


def empty_diff(**groups: tuple[DiffEntry, ...]) -> DiffResult:
    fields = dict.fromkeys(
        ("new", "persisting", "resolved", "filtered_out", "accepted", "gone", "warnings"), ()
    )
    return DiffResult(**{**fields, **groups})  # type: ignore[arg-type]


def headings(report: str, prefix: str = "#") -> list[str]:
    return [line for line in report.splitlines() if line.startswith(prefix)]


def outside_code_spans(text: str) -> str:
    """The text with well-formed single-backtick code spans removed."""
    return re.sub(r"(?<!\\)`[^`]+`", "", text)


def assert_no_html_outside_code(report: str) -> None:
    rest = outside_code_spans(report)
    assert re.findall(r"(?<!\\)`", rest) == [], "unbalanced or unescaped backtick"
    tags = re.findall(r"<(?!br>|https://|account>)[a-zA-Z/]", rest)
    assert tags == [], "raw HTML tag outside a code span"


# --- escaping, code spans, links -----------------------------------------------------


def test_escape_html_and_markdown() -> None:
    assert escape("<b>&</b>") == "&lt;b&gt;&amp;&lt;/b&gt;"
    assert escape("a|b") == "a\\|b"
    assert escape("[x](https://example.com)") == "\\[x\\](https://example.com)"
    assert escape("a`b\\c") == "a\\`b\\\\c"
    assert escape("line1\nline2\t x") == "line1 line2 x"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("user/admin", "`user/admin`"),
        ("a\\b *x*", "`a\\b *x*`"),  # backslash and emphasis are literal in code spans
        ("user/\n admin", "`user/ admin`"),
        ("evil`name", "evil\\`name"),  # backtick: escaped text, not a code span
        ("<img src=x>", "&lt;img src=x&gt;"),
        ("a|b", "a\\|b"),  # pipe can't be escaped reliably inside a code span in a table
        ("a&b", "a&amp;b"),
        ("", ""),
    ],
)
def test_code(value: str, expected: str) -> None:
    assert code(value) == expected


def test_code_keeps_redaction_placeholder_in_span() -> None:
    fmt = Fmt((ACCOUNT,), redact=True)
    assert fmt.code(USER_ARN) == "`arn:aws:iam::<account>:user/example-user`"


def test_link_only_for_plain_https() -> None:
    assert link("https://hub.prowler.com/check/x") == "<https://hub.prowler.com/check/x>"
    assert link("javascript:alert(1)") == "javascript:alert(1)"
    assert link("https://example.com/<script>") == "https://example.com/&lt;script&gt;"


# --- short names and distinguishing notes ------------------------------------------------


@pytest.mark.parametrize(
    ("uid", "expected"),
    [
        (USER_ARN, "user/example-user"),
        (f"arn:aws:iam::{ACCOUNT}:password-policy", "password-policy"),
        (f"arn:aws:cloudtrail:us-east-1:{ACCOUNT}:trail/main", "trail/main"),
        (f"arn:aws:logs:us-east-1:{ACCOUNT}:log-group:a:b", "log-group:a:b"),
        ("arn:aws:s3:::example-bucket", "example-bucket"),
        ("i-0123456789abcdef0", "i-0123456789abcdef0"),
    ],
)
def test_short_name(uid: str, expected: str) -> None:
    assert short_name(uid) == expected


def test_short_name_keeps_account_with_several_accounts() -> None:
    assert short_name(USER_ARN, multi_account=True) == f"{ACCOUNT}:user/example-user"
    assert short_name("arn:aws:s3:::b", multi_account=True) == "b"


def test_notes_show_differing_part_of_detail() -> None:
    findings = [policy_finding("ViewOnlyAccess"), FINDING, policy_finding("AdministratorAccess")]
    assert distinguishing_notes(Fmt(), findings) == [
        "… ViewOnlyAccess …",
        "",
        "… AdministratorAccess …",
    ]


def test_notes_fall_back_to_finding_uid_when_details_are_equal() -> None:
    a = finding(finding_uid="prowler-x-alpha")
    b = finding(finding_uid="prowler-x-beta")
    assert distinguishing_notes(Fmt(), [a, b]) == ["…-alpha", "…-beta"]


def test_notes_are_capped() -> None:
    a = policy_finding("A" * 100)
    b = policy_finding("B" * 100)
    notes = distinguishing_notes(Fmt(), [a, b])
    assert all(len(n) <= 60 + 4 for n in notes)
    assert notes[0].endswith("… …")


def test_notes_redact_before_cutting() -> None:
    a = finding(status_detail=f"Trusted by {ACCOUNT}.")
    b = finding(status_detail=f"Trusted by {OTHER_ACCOUNT}.")
    notes = distinguishing_notes(Fmt((ACCOUNT,), redact=True), [a, b])
    assert not any(re.search(r"\d{4}", n) for n in notes)


# --- triage report ----------------------------------------------------------------------


def test_triage_sections_in_order() -> None:
    report = triage_report((finding(),), (Suppressed(finding(severity="Low"), RISK),), ("w1",))
    assert headings(report) == [
        "# CSPM triage report",
        "## Summary",
        "## Needs attention (1)",
        "### High · iam_user_hardware_mfa_enabled",
        "## Accepted risks (1)",
        "### #2 · iam_user_hardware_mfa_enabled",
        "## Warnings",
    ]
    assert "- Gate: **fail** (exit 1): 1 finding(s) need attention" in report
    assert "- Exceptions: config/exceptions.toml (1 entries)" in report
    assert f"- Account: {ACCOUNT}" in report
    assert "- w1" in report


def test_triage_empty_sections_are_omitted() -> None:
    report = triage_report(ctx=replace(CTX, gate=(), exceptions="none (x not found)"))
    assert headings(report, "## ") == ["## Summary"]
    assert "| **Total** | 0 | 0 |" in report
    assert "- Gate: **pass** (exit 0)" in report


def test_attention_block() -> None:
    report = triage_report((finding(),))
    block = report.split("### High · iam_user_hardware_mfa_enabled\n\n")[1]
    assert block.splitlines()[:4] == [
        "- Resource: `user/example-user` (us-east-1)",
        f"- UID: `{USER_ARN}`",
        "- Detail: User example-user does not have any type of MFA enabled.",
        "- Remediation: <https://hub.prowler.com/check/iam_user_hardware_mfa_enabled>",
    ]


def test_attention_block_lists_every_uid_and_omits_missing_remediation() -> None:
    two = finding(resource_uids=(USER_ARN, USER_ARN + "-2"), remediation_references=())
    report = triage_report((two,))
    assert "- Resource: `user/example-user`, `user/example-user-2` (us-east-1)" in report
    assert report.count("- UID: ") == 2
    assert "Remediation" not in report


def test_attention_blocks_in_severity_order_unknown_first() -> None:
    findings = (finding(severity="Fatal"), finding(severity="critical"), finding(severity="Low"))
    assert [h.split(" · ")[0] for h in headings(triage_report(findings), "### ")] == [
        "### Fatal",
        "### Critical",
        "### Low",
    ]


def test_summary_counts_and_total() -> None:
    report = triage_report((finding(), finding(severity="Low")), (Suppressed(finding(), RISK),))
    assert "| High | 1 | 1 |" in report
    assert "| Low | 1 | 0 |" in report
    assert "| **Total** | 2 | 1 |" in report


def test_accepted_risks_grouped_by_exception_sorted_by_expiry() -> None:
    late = replace(RISK, position=1, expires=date(2027, 3, 1), check_id=POLICY_CHECK)
    accepted = (
        Suppressed(policy_finding("ViewOnlyAccess"), late),
        Suppressed(finding(), RISK),
        Suppressed(policy_finding("AdministratorAccess"), late),
    )
    report = triage_report(accepted=accepted)
    assert "| # | Check | Findings | Expires |" in report
    assert "| #2 | iam_user_hardware_mfa_enabled | 1 | 2026-12-31 |" in report
    assert f"| #1 | {POLICY_CHECK} | 2 | 2027-03-01 |" in report
    assert report.index("| #2 |") < report.index("| #1 |")
    assert headings(report, "### ") == [
        "### #2 · iam_user_hardware_mfa_enabled",
        f"### #1 · {POLICY_CHECK}",
    ]
    block = report.split(f"### #1 · {POLICY_CHECK}\n\n")[1]
    assert block.splitlines() == [
        "- Expires: 2027-03-01",
        "- Owner: security-team@example.com",
        "- Source: config/exceptions.toml #1",
        "- Reason: Break-glass user",
        "- Covers (2):",
        "  - `user/example-user` (us-east-1) — … ViewOnlyAccess …",
        "  - `user/example-user` (us-east-1) — … AdministratorAccess …",
    ]


def test_group_by_risk_tie_breaks_on_source_and_position() -> None:
    a = replace(RISK, position=3)
    b = replace(RISK, position=1)
    groups = group_by_risk([Suppressed(FINDING, a), Suppressed(FINDING, b)])
    assert [risk.position for risk, _ in groups] == [1, 3]


def test_untrusted_values_are_escaped_everywhere() -> None:
    hostile = finding(
        event_code="check<script>",
        resource_uids=(HTML_ARN, BACKTICK_ARN),
        status_detail="bad | cell\nnext <script>alert(1)</script> [x](https://evil.example)",
        remediation_references=("javascript:alert(1)",),
    )
    risk = replace(RISK, owner="<b>owner</b>", reason="reason `code` & more")
    report = triage_report((hostile,), (Suppressed(hostile, risk),), ("<i>warn</i>",))
    assert_no_html_outside_code(report)
    assert "<img" not in report and "<script" not in report
    assert "&lt;img src=x onerror=alert(1)&gt;" in report
    assert "user/evil\\`name" in report
    assert "bad \\| cell next" in report
    assert "\\[x\\](https://evil.example)" in report
    assert "<javascript" not in report
    assert "reason \\`code\\` &amp; more" in report


def test_scan_name_in_header_is_escaped() -> None:
    ctx = replace(CTX, scans=(("Scan", "<x>.json"),))
    assert "- Scan: &lt;x&gt;.json" in triage_report(ctx=ctx)


def test_report_is_deterministic() -> None:
    args = ((finding(), policy_finding("A")), (Suppressed(policy_finding("B"), RISK),))
    assert triage_report(*args) == triage_report(*args)


# --- redaction ---------------------------------------------------------------------------


def test_redact_accounts() -> None:
    assert redact_accounts(f"a {ACCOUNT} b") == "a <account> b"
    assert redact_accounts("x 1234567890123 y") == "x 1234567890123 y"  # 13 digits: not an ID
    assert redact_accounts("acct-abc and abc", ("acct-abc",)) == "<account> and abc"


def test_redaction_leaks() -> None:
    assert redaction_leaks(f"x{ACCOUNT}y")
    assert redaction_leaks("x acct-abc", ("acct-abc",))
    assert not redaction_leaks("2026-06-15 <account>", (ACCOUNT,))


def test_redacted_triage_report() -> None:
    hostile = finding(
        status_detail=f"Role trusts {OTHER_ACCOUNT} and {ACCOUNT}.",
        remediation_references=(f"https://example.com/{ACCOUNT}",),
    )
    risk = replace(RISK, owner=f"owner-{ACCOUNT}", source=f"{ACCOUNT}.toml")
    ctx = replace(REDACTED_CTX, scans=(("Scan", f"prowler-output-{ACCOUNT}.ocsf.json"),))
    report = triage_report((hostile,), (Suppressed(hostile, risk),), (f"w {ACCOUNT}",), ctx)
    assert not re.search(r"\d{12}", report)
    assert f"- Redaction: {REDACTION_NOTE}" in report
    assert "- Account: &lt;account&gt;" in report
    assert "- Scan: prowler-output-&lt;account&gt;.ocsf.json" in report
    assert "- UID: `arn:aws:iam::<account>:user/example-user`" in report
    assert "trusts &lt;account&gt; and &lt;account&gt;" in report
    assert "example-user" in report  # only account IDs are redacted
    assert "anonymi" not in report.lower()


def test_redaction_note_only_when_redacting() -> None:
    assert "Redaction" not in triage_report((finding(),))


def test_several_accounts_redacted_in_header() -> None:
    ctx = replace(REDACTED_CTX, accounts=(ACCOUNT, OTHER_ACCOUNT))
    report = triage_report((finding(),), ctx=ctx)
    assert "- Accounts: 2 (redacted)" in report
    assert "- Resource: `<account>:user/example-user`" in report
    plain = triage_report((finding(),), ctx=replace(ctx, redact=False))
    assert f"- Accounts: {ACCOUNT}, {OTHER_ACCOUNT}" in plain


# --- diff report ---------------------------------------------------------------------------


def all_categories() -> DiffResult:
    new = entry(new_reason=NewReason.NO_LONGER_ACCEPTED, accepted_by=RISK)
    persisting = entry(
        category=Category.PERSISTING, new_reason=None, severity_change=("High", "Critical")
    )
    resolved = entry(
        category=Category.RESOLVED,
        new_reason=None,
        baseline=FINDING,
        current=finding(status="PASS"),
    )
    filtered = entry(
        category=Category.FILTERED_OUT, new_reason=None, current=finding(status="MANUAL")
    )
    accepted = entry(category=Category.ACCEPTED, new_reason=None, accepted_by=RISK)
    gone = entry(
        category=Category.GONE,
        new_reason=None,
        baseline=FINDING,
        current=None,
        gone_reason=GoneReason.CHECK_PASSING,
    )
    return empty_diff(
        new=(new,),
        persisting=(persisting,),
        resolved=(resolved,),
        filtered_out=(filtered,),
        accepted=(accepted,),
        gone=(gone,),
        warnings=("w1",),
    )


def test_diff_sections_and_reasons() -> None:
    report = render_diff(
        all_categories(), replace(CTX, scans=(("Baseline", "a"), ("Current", "b")))
    )
    assert headings(report, "## ") == [
        "## Summary",
        "## New (1)",
        "## Persisting (1)",
        "## Resolved (1)",
        "## Filtered out (1)",
        "## Accepted (1)",
        "## Gone (1)",
        "## Warnings",
    ]
    assert "| exception ended (was config/exceptions.toml #2) |" in report
    assert "| High → Critical |" in report
    assert "| FAIL → PASS |" in report
    assert "| MANUAL / High |" in report
    assert "| security-team@example.com | Break-glass user | 2026-12-31 |" in report
    assert "| `user/example-user` | us-east-1 | likely fixed |" in report
    assert "| Gone | 1 | likely fixed: 1 |" in report
    assert "| Persisting | 1 | severity increased: 1; status changed: 0 |" in report
    assert "- Baseline: a" in report and "- Current: b" in report
    assert USER_ARN not in report  # tables use short names only


def test_legend_lists_only_used_labels() -> None:
    gone = (
        entry(category=Category.GONE, new_reason=None, gone_reason=GoneReason.CHECK_NOT_RUN),
        entry(category=Category.GONE, new_reason=None, gone_reason=GoneReason.CHECK_NOT_RUN),
    )
    new = (entry(new_reason=NewReason.CHECK_REGION_NOT_IN_BASELINE),)
    report = render_diff(empty_diff(new=new, gone=gone), CTX)
    legend_lines = [line for line in report.splitlines() if line.startswith("- **")]
    assert [line.split("**")[1] for line in legend_lines] == ["region not in baseline", "not run"]


def test_every_reason_has_a_short_label_and_legend() -> None:
    assert set(NEW_REASON_LABELS) == set(NewReason)
    assert set(GONE_REASON_LABELS) == set(GoneReason)
    labels = [label for label, _ in [*NEW_REASON_LABELS.values(), *GONE_REASON_LABELS.values()]]
    assert len(set(labels)) == len(labels)
    assert all(len(label) <= 25 and text for label, text in GONE_REASON_LABELS.values())


def test_diff_empty_categories_are_omitted() -> None:
    report = render_diff(empty_diff(), replace(CTX, gate=()))
    assert headings(report, "## ") == ["## Summary"]
    assert "| New | 0 |  |" in report


def test_diff_rows_with_same_check_and_resource_are_told_apart() -> None:
    new = tuple(
        entry(current=policy_finding(p), key=p) for p in ("ViewOnlyAccess", "AdministratorAccess")
    )
    report = render_diff(empty_diff(new=new), CTX)
    assert "`user/example-user`<br>… ViewOnlyAccess …" in report
    assert "`user/example-user`<br>… AdministratorAccess …" in report


def test_diff_untrusted_values_escaped() -> None:
    hostile = finding(resource_uids=(HTML_ARN, BACKTICK_ARN), status_detail="<script>")
    report = render_diff(empty_diff(new=(entry(current=hostile),)), CTX)
    assert_no_html_outside_code(report)
    assert "<img" not in report and "<script" not in report


def test_redacted_diff_report() -> None:
    result = all_categories()
    report = render_diff(result, replace(REDACTED_CTX, scans=(("Baseline", f"{ACCOUNT}.json"),)))
    assert not re.search(r"\d{12}", report)
    assert f"- Redaction: {REDACTION_NOTE}" in report
