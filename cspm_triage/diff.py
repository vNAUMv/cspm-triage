"""Compare two scans: new, resolved, and persisting findings.

Findings are matched by finding_info.uid (Finding.finding_uid). Prowler builds it
from provider, check, account, region and resource name, with no per-scan part,
so the same finding has the same uid in every scan. Both scans are triaged with
the same filters, accepted risks and date, which puts every uid in one state
per scan: needs attention, accepted, filtered out, or absent. Only changes into
or out of "needs attention" are reported:

- new:          not needing attention in the baseline, needing it now
- persisting:   needing attention in both (with status/severity changes)
- resolved:     needed attention; now present with status PASS
- filtered_out: needed attention; now present but excluded by the filters for
                another reason (e.g. FAIL -> MANUAL); not counted as resolved
- accepted:     needed attention; now covered by an accepted risk
- gone:         needed attention; now absent from the scan entirely

A finding accepted in both scans, or PASS in both, appears nowhere.
"""

from collections import defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, replace
from datetime import date
from enum import StrEnum

from cspm_triage.models import Finding
from cspm_triage.triage import (
    DEFAULT_MIN_SEVERITY,
    DEFAULT_STATUSES,
    AcceptedRisk,
    TriageResult,
    expired_warnings,
    severity_rank,
    sort_key,
    triage,
)

CheckKey = tuple[str, str]  # (event_code, region)


class State(StrEnum):
    """Where a finding stands in one scan after triage."""

    ATTENTION = "attention"
    ACCEPTED = "accepted"
    FILTERED_OUT = "filtered_out"
    ABSENT = "absent"


class Category(StrEnum):
    """How a finding changed between the scans."""

    NEW = "new"
    PERSISTING = "persisting"
    RESOLVED = "resolved"
    FILTERED_OUT = "filtered_out"
    ACCEPTED = "accepted"
    GONE = "gone"


class NewReason(StrEnum):
    """Why a finding is new."""

    # The baseline had no findings for this check in this region. A fact, not a cause:
    # the scan scope may have changed, or resources may have been created there.
    CHECK_REGION_NOT_IN_BASELINE = "check_region_not_in_baseline"
    NEW_FINDING = "new_finding"  # check ran in the baseline but did not report this finding
    REGRESSION = "regression"  # was PASS in the baseline
    NOW_MATCHES_FILTER = "now_matches_filter"  # was excluded by the filters for another reason
    NO_LONGER_ACCEPTED = "no_longer_accepted"  # an accepted risk matched it in the baseline


class GoneReason(StrEnum):
    """Why a finding is absent from the current scan."""

    CHECK_NOT_RUN = "check_not_run"  # no current findings for this check in this region
    CHECK_PASSING = "check_passing"  # check ran and all its findings PASS: likely fixed
    RESOURCE_NOT_REPORTED = "resource_not_reported"  # check ran; resource deleted or replaced


@dataclass(frozen=True, slots=True)
class DiffEntry:
    """One finding uid compared across the two scans."""

    key: str
    category: Category
    baseline: Finding | None
    current: Finding | None
    baseline_state: State
    current_state: State
    new_reason: NewReason | None = None
    gone_reason: GoneReason | None = None
    status_change: tuple[str, str] | None = None
    severity_change: tuple[str, str] | None = None
    # The matching exception: the current one for ACCEPTED entries, the baseline
    # one for NEW entries with reason NO_LONGER_ACCEPTED; otherwise None.
    accepted_by: AcceptedRisk | None = None


def severity_increased(entry: DiffEntry) -> bool:
    """True if the severity rose; an unknown severity ranks above Critical."""
    if entry.severity_change is None:
        return False
    before, after = entry.severity_change
    return severity_rank(after) < severity_rank(before)


@dataclass(frozen=True, slots=True)
class DiffResult:
    """Diff entries grouped by category, each sorted like triage output."""

    new: tuple[DiffEntry, ...]
    persisting: tuple[DiffEntry, ...]
    resolved: tuple[DiffEntry, ...]
    filtered_out: tuple[DiffEntry, ...]
    accepted: tuple[DiffEntry, ...]
    gone: tuple[DiffEntry, ...]
    warnings: tuple[str, ...]


# --- input checks -----------------------------------------------------------


def require_findings(findings: Sequence[Finding], side: str) -> None:
    """Raise ValueError if a scan has no findings.

    An empty scan usually means the scan failed (expired credentials, crash), and
    diffing against it would report everything as gone or new.
    """
    if not findings:
        raise ValueError(f"{side} scan has no findings; the scan probably failed")


def index_by_uid(findings: Iterable[Finding], side: str) -> dict[str, Finding]:
    """Map finding_uid to finding; raise ValueError if a uid repeats."""
    index: dict[str, Finding] = {}
    duplicates = 0
    for finding in findings:
        if finding.finding_uid in index:
            duplicates += 1
        index[finding.finding_uid] = finding
    if duplicates:
        raise ValueError(f"{side} scan has {duplicates} duplicate finding uid(s)")
    return index


def check_same_accounts(baseline: Iterable[Finding], current: Iterable[Finding]) -> None:
    """Raise ValueError if the scans cover different sets of accounts.

    The message gives counts only, never account IDs.
    """
    base = {f.account_uid for f in baseline}
    cur = {f.account_uid for f in current}
    if base != cur:
        raise ValueError(
            f"scans cover different accounts: baseline has {len(base)}, "
            f"current has {len(cur)}, {len(base & cur)} in common"
        )


# --- per-scan state ---------------------------------------------------------


def finding_states(index: dict[str, Finding], result: TriageResult) -> dict[str, State]:
    """Return the triage state of every finding in one scan."""
    states = dict.fromkeys(index, State.FILTERED_OUT)
    states.update(dict.fromkeys((f.finding_uid for f in result.attention), State.ATTENTION))
    states.update(dict.fromkeys((s.finding.finding_uid for s in result.accepted), State.ACCEPTED))
    return states


def accepted_risks_by_uid(result: TriageResult) -> dict[str, AcceptedRisk]:
    """Map each accepted finding's uid to the exception that matched it."""
    return {s.finding.finding_uid: s.risk for s in result.accepted}


def attach_risk(
    entry: DiffEntry,
    base_risks: dict[str, AcceptedRisk],
    cur_risks: dict[str, AcceptedRisk],
) -> DiffEntry:
    """Fill accepted_by for ACCEPTED and NO_LONGER_ACCEPTED entries."""
    if entry.category is Category.ACCEPTED:
        return replace(entry, accepted_by=cur_risks.get(entry.key))
    if entry.new_reason is NewReason.NO_LONGER_ACCEPTED:
        return replace(entry, accepted_by=base_risks.get(entry.key))
    return entry


def findings_by_check(findings: Iterable[Finding]) -> dict[CheckKey, list[Finding]]:
    """Group all findings of a scan by (check, region), whatever their status."""
    groups: dict[CheckKey, list[Finding]] = defaultdict(list)
    for finding in findings:
        groups[(finding.event_code, finding.region)].append(finding)
    return dict(groups)


def _check_key(finding: Finding) -> CheckKey:
    return (finding.event_code, finding.region)


def _is_pass(finding: Finding) -> bool:
    return finding.status.strip().upper() == "PASS"


def _change(before: str, after: str) -> tuple[str, str] | None:
    return None if before.strip().lower() == after.strip().lower() else (before, after)


# --- classification ---------------------------------------------------------


def new_reason(
    baseline: Finding | None,
    baseline_state: State,
    current: Finding,
    baseline_checks: dict[CheckKey, list[Finding]],
) -> NewReason:
    """Explain why a finding needs attention now but did not in the baseline."""
    if baseline_state is State.ACCEPTED:
        return NewReason.NO_LONGER_ACCEPTED
    if baseline is not None:
        return NewReason.REGRESSION if _is_pass(baseline) else NewReason.NOW_MATCHES_FILTER
    if _check_key(current) not in baseline_checks:
        return NewReason.CHECK_REGION_NOT_IN_BASELINE
    return NewReason.NEW_FINDING


def gone_reason(baseline: Finding, current_checks: dict[CheckKey, list[Finding]]) -> GoneReason:
    """Explain why a finding is absent from the current scan."""
    same_check = current_checks.get(_check_key(baseline), [])
    if not same_check:
        return GoneReason.CHECK_NOT_RUN
    if all(_is_pass(f) for f in same_check):
        return GoneReason.CHECK_PASSING
    return GoneReason.RESOURCE_NOT_REPORTED


def _left_attention(cur: Finding | None, cur_state: State) -> Category:
    if cur is None:
        return Category.GONE
    if cur_state is State.ACCEPTED:
        return Category.ACCEPTED
    return Category.RESOLVED if _is_pass(cur) else Category.FILTERED_OUT


def classify(
    key: str,
    pair: tuple[Finding | None, Finding | None],
    states: tuple[State, State],
    checks: tuple[dict[CheckKey, list[Finding]], dict[CheckKey, list[Finding]]],
) -> DiffEntry | None:
    """Build the diff entry for one uid, or None if it never needed attention.

    pair, states and checks are (baseline, current).
    """
    base, cur = pair
    base_state, cur_state = states
    entry = DiffEntry(key, Category.PERSISTING, base, cur, base_state, cur_state)
    if cur is not None and cur_state is State.ATTENTION:
        if base is not None and base_state is State.ATTENTION:
            return replace(
                entry,
                status_change=_change(base.status, cur.status),
                severity_change=_change(base.severity, cur.severity),
            )
        reason = new_reason(base, base_state, cur, checks[0])
        return replace(entry, category=Category.NEW, new_reason=reason)
    if base is None or base_state is not State.ATTENTION:
        return None
    category = _left_attention(cur, cur_state)
    reason = gone_reason(base, checks[1]) if category is Category.GONE else None
    return replace(entry, category=category, gone_reason=reason)


# --- public entry point -----------------------------------------------------


def _merge_warnings(
    base: TriageResult, cur: TriageResult, shared: Sequence[str]
) -> tuple[str, ...]:
    """Expired-risk warnings once; per-scan warnings prefixed with their side."""
    rest_base = [f"baseline: {w}" for w in base.warnings if w not in shared]
    rest_cur = [f"current: {w}" for w in cur.warnings if w not in shared]
    return (*shared, *rest_base, *rest_cur)


def _entry_sort_key(entry: DiffEntry) -> tuple[tuple[int, str, tuple[str, ...]], str]:
    finding = entry.current if entry.current is not None else entry.baseline
    if finding is None:
        raise ValueError(f"diff entry {entry.key!r} has no finding on either side")
    return (sort_key(finding), entry.key)


def diff_scans(
    baseline: Iterable[Finding],
    current: Iterable[Finding],
    risks: Sequence[AcceptedRisk],
    today: date,
    *,
    statuses: Iterable[str] = DEFAULT_STATUSES,
    min_severity: str = DEFAULT_MIN_SEVERITY,
) -> DiffResult:
    """Compare two scans, triaging both with the same filters, risks and date.

    Both scans are triaged with the same accepted risks and the same `today`, not
    with the exceptions file or date that applied when each scan ran. An exception
    that expired between the two scan dates is therefore not detected: it is either
    active for both scans or expired for both.

    Raises ValueError if either scan is empty, a scan repeats a finding uid, the
    scans cover different accounts, or a filter argument is invalid.
    """
    base_list, cur_list = list(baseline), list(current)
    require_findings(base_list, "baseline")
    require_findings(cur_list, "current")
    base_index = index_by_uid(base_list, "baseline")
    cur_index = index_by_uid(cur_list, "current")
    check_same_accounts(base_list, cur_list)
    statuses = list(statuses)
    base_result = triage(base_list, risks, today, statuses=statuses, min_severity=min_severity)
    cur_result = triage(cur_list, risks, today, statuses=statuses, min_severity=min_severity)
    base_states = finding_states(base_index, base_result)
    cur_states = finding_states(cur_index, cur_result)
    checks = (findings_by_check(base_list), findings_by_check(cur_list))
    base_risks = accepted_risks_by_uid(base_result)
    cur_risks = accepted_risks_by_uid(cur_result)

    groups: dict[Category, list[DiffEntry]] = {category: [] for category in Category}
    for key in base_index.keys() | cur_index.keys():
        entry = classify(
            key,
            (base_index.get(key), cur_index.get(key)),
            (base_states.get(key, State.ABSENT), cur_states.get(key, State.ABSENT)),
            checks,
        )
        if entry is not None:
            groups[entry.category].append(attach_risk(entry, base_risks, cur_risks))

    def ordered(category: Category) -> tuple[DiffEntry, ...]:
        return tuple(sorted(groups[category], key=_entry_sort_key))

    return DiffResult(
        new=ordered(Category.NEW),
        persisting=ordered(Category.PERSISTING),
        resolved=ordered(Category.RESOLVED),
        filtered_out=ordered(Category.FILTERED_OUT),
        accepted=ordered(Category.ACCEPTED),
        gone=ordered(Category.GONE),
        warnings=_merge_warnings(base_result, cur_result, expired_warnings(risks, today)),
    )
