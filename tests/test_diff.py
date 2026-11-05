"""Tests for cspm_triage.diff. Scans are derived from the sanitized fixture; all data is fake."""

from collections.abc import Iterable
from dataclasses import replace
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import pytest

from cspm_triage.diff import (
    DiffEntry,
    DiffResult,
    GoneReason,
    NewReason,
    State,
    diff_scans,
)
from cspm_triage.models import Finding
from cspm_triage.parser import load_findings
from cspm_triage.triage import AcceptedRisk

FIXTURE = Path(__file__).parent / "fixtures" / "sample_scan.ocsf.json"
BASELINE = tuple(load_findings(FIXTURE))
TODAY = date(2026, 6, 15)
FAKE_ACCOUNT = "123456789012"
OTHER_FAKE_ACCOUNT = "111122223333"  # AWS documentation example account

USER_CHECK = "iam_user_hardware_mfa_enabled"  # FAIL, High
ROOT_HW_CHECK = "iam_root_hardware_mfa_enabled"  # FAIL, Critical
BEDROCK_CHECK = "iam_user_access_not_stale_to_bedrock"  # FAIL, Medium
POLICY_CHECK = "iam_policy_attached_only_to_group_or_roles"  # FAIL, Low
ROOT_MFA_CHECK = "iam_root_mfa_enabled"  # PASS, Critical
KMS_CHECK = "kms_key_enclave_debug_attestation_detected"  # MANUAL, High
USER_ARN = "arn:aws:iam::123456789012:user/example-user"
OTHER_USER_ARN = "arn:aws:iam::123456789012:user/example-user-2"


def get(event_code: str) -> Finding:
    return next(f for f in BASELINE if f.event_code == event_code)


def edit(event_code: str, **changes: Any) -> list[Finding]:  # noqa: ANN401
    """The baseline with one finding changed (same uid)."""
    return [replace(f, **changes) if f.event_code == event_code else f for f in BASELINE]


def drop(event_code: str) -> list[Finding]:
    return [f for f in BASELINE if f.event_code != event_code]


def variant(of_check: str, suffix: str, **changes: Any) -> Finding:  # noqa: ANN401
    """A copy of a baseline finding with a different uid, i.e. a different finding."""
    original = get(of_check)
    return replace(original, finding_uid=original.finding_uid + suffix, **changes)


def accepted_risk(**changes: Any) -> AcceptedRisk:  # noqa: ANN401
    base = AcceptedRisk(
        check_id=USER_CHECK,
        resources=(USER_ARN,),
        region=None,
        reason="Accepted for testing",
        owner="security-team@example.com",
        expires=TODAY + timedelta(days=30),
        source="exceptions.toml",
        position=1,
    )
    return replace(base, **changes)


def run(current: Iterable[Finding], risks: Iterable[AcceptedRisk] = (), **kw: Any) -> DiffResult:  # noqa: ANN401
    return diff_scans(BASELINE, current, list(risks), TODAY, **kw)


def codes(entries: Iterable[DiffEntry]) -> list[str]:
    return [(e.current or e.baseline).event_code for e in entries]  # type: ignore[union-attr]


def only(entries: tuple[DiffEntry, ...]) -> DiffEntry:
    assert len(entries) == 1
    return entries[0]


# --- identical scans ----------------------------------------------------------


def test_identical_scans_are_all_persisting_without_changes() -> None:
    result = run(BASELINE)
    assert codes(result.persisting) == [ROOT_HW_CHECK, USER_CHECK, BEDROCK_CHECK, POLICY_CHECK]
    assert all(e.status_change is None and e.severity_change is None for e in result.persisting)
    assert not (result.new or result.resolved or result.filtered_out)
    assert not (result.accepted or result.gone or result.warnings)


# --- new ----------------------------------------------------------------------


def test_new_finding_where_check_ran_in_baseline() -> None:
    entry = only(run([*BASELINE, variant(USER_CHECK, "-2", resource_uids=(OTHER_USER_ARN,))]).new)
    assert entry.new_reason is NewReason.NEW_FINDING
    assert entry.baseline is None
    assert entry.baseline_state is State.ABSENT


def test_new_region_is_check_region_not_in_baseline() -> None:
    entry = only(run([*BASELINE, variant(USER_CHECK, "-eu", region="eu-north-1")]).new)
    assert entry.new_reason is NewReason.CHECK_REGION_NOT_IN_BASELINE


def test_new_check_is_check_region_not_in_baseline() -> None:
    new_check = variant(USER_CHECK, "-x", event_code="example_new_check")
    reason = only(run([*BASELINE, new_check]).new).new_reason
    assert reason is NewReason.CHECK_REGION_NOT_IN_BASELINE


def test_pass_to_fail_is_regression() -> None:
    entry = only(run(edit(ROOT_MFA_CHECK, status="FAIL")).new)
    assert entry.new_reason is NewReason.REGRESSION
    assert entry.baseline_state is State.FILTERED_OUT


def test_manual_to_fail_now_matches_filter() -> None:
    entry = only(run(edit(KMS_CHECK, status="FAIL")).new)
    assert entry.new_reason is NewReason.NOW_MATCHES_FILTER


def test_no_longer_accepted_when_risk_stops_matching() -> None:
    current = edit(USER_CHECK, resource_uids=(USER_ARN, OTHER_USER_ARN))
    entry = only(run(current, [accepted_risk()]).new)
    assert entry.new_reason is NewReason.NO_LONGER_ACCEPTED
    assert entry.baseline_state is State.ACCEPTED


def test_new_entries_sorted_by_severity() -> None:
    low = variant(USER_CHECK, "-low", severity="Low")
    critical = variant(USER_CHECK, "-crit", severity="Critical")
    result = run([*BASELINE, low, critical])
    assert [e.current.severity for e in result.new] == ["Critical", "Low"]  # type: ignore[union-attr]


# --- leaving attention ---------------------------------------------------------


def test_fail_to_pass_is_resolved() -> None:
    entry = only(run(edit(USER_CHECK, status="PASS")).resolved)
    assert entry.current_state is State.FILTERED_OUT
    assert USER_CHECK not in codes(run(edit(USER_CHECK, status="PASS")).persisting)


def test_fail_to_manual_is_filtered_out_not_resolved() -> None:
    result = run(edit(USER_CHECK, status="MANUAL"))
    assert codes(result.filtered_out) == [USER_CHECK]
    assert result.resolved == ()


def test_severity_below_minimum_is_filtered_out() -> None:
    result = run(edit(USER_CHECK, severity="Low"), min_severity="medium")
    assert codes(result.filtered_out) == [USER_CHECK]


def test_newly_accepted() -> None:
    baseline = [
        replace(f, resource_uids=(USER_ARN, OTHER_USER_ARN)) if f.event_code == USER_CHECK else f
        for f in BASELINE
    ]
    result = diff_scans(baseline, BASELINE, [accepted_risk()], TODAY)
    entry = only(result.accepted)
    assert entry.current_state is State.ACCEPTED
    assert result.resolved == ()


def test_accepted_in_both_scans_is_reported_nowhere() -> None:
    result = run(BASELINE, [accepted_risk(resources=())])
    assert USER_CHECK not in codes(result.persisting)
    assert not (result.new or result.resolved or result.accepted or result.gone)


# --- gone -----------------------------------------------------------------------


def test_gone_check_not_run() -> None:
    entry = only(run(drop(USER_CHECK)).gone)
    assert entry.gone_reason is GoneReason.CHECK_NOT_RUN
    assert entry.current is None


def test_gone_with_check_now_passing_on_new_uid() -> None:
    replacement = variant(USER_CHECK, "-new", status="PASS")
    result = run([*drop(USER_CHECK), replacement])
    assert only(result.gone).gone_reason is GoneReason.CHECK_PASSING
    assert result.resolved == ()
    assert result.new == ()


def test_gone_resource_not_reported() -> None:
    replacement = variant(USER_CHECK, "-new", status="MANUAL")
    result = run([*drop(USER_CHECK), replacement])
    assert only(result.gone).gone_reason is GoneReason.RESOURCE_NOT_REPORTED


# --- persisting changes -----------------------------------------------------------


def test_persisting_severity_change() -> None:
    result = run(edit(USER_CHECK, severity="Critical"))
    entry = next(e for e in result.persisting if e.key == get(USER_CHECK).finding_uid)
    assert entry.severity_change == ("High", "Critical")
    assert entry.status_change is None


def test_case_only_difference_is_not_a_change() -> None:
    result = run(edit(USER_CHECK, severity="HIGH"))
    assert all(e.severity_change is None for e in result.persisting)


def test_persisting_status_change_when_both_statuses_selected() -> None:
    result = run(edit(USER_CHECK, status="MANUAL"), statuses={"FAIL", "MANUAL"})
    entry = next(e for e in result.persisting if e.key == get(USER_CHECK).finding_uid)
    assert entry.status_change == ("FAIL", "MANUAL")


# --- warnings ----------------------------------------------------------------------


def test_warnings_expired_once_and_scan_specific_prefixed() -> None:
    expired = accepted_risk(position=2, expires=TODAY - timedelta(days=1))
    result = run(edit(USER_CHECK, severity="Fatal"), [expired])
    assert result.warnings == (
        f"exceptions.toml: exception #2 ({USER_CHECK}) expired on 2026-06-14; not applied",
        "current: 1 finding(s) with unrecognized severity 'Fatal' were kept and sorted first",
    )


# --- input validation ------------------------------------------------------------------


def test_duplicate_uid_raises_without_showing_it() -> None:
    with pytest.raises(ValueError, match="current scan has 1 duplicate finding uid") as exc:
        run([*BASELINE, get(USER_CHECK)])
    assert FAKE_ACCOUNT not in str(exc.value)


def test_different_accounts_raise_with_counts_only() -> None:
    current = [replace(f, account_uid=OTHER_FAKE_ACCOUNT) for f in BASELINE]
    with pytest.raises(ValueError, match="baseline has 1, current has 1, 0 in common") as exc:
        run(current)
    assert FAKE_ACCOUNT not in str(exc.value)
    assert OTHER_FAKE_ACCOUNT not in str(exc.value)


def test_extra_account_in_one_scan_raises() -> None:
    extra = variant(USER_CHECK, "-other", account_uid=OTHER_FAKE_ACCOUNT)
    with pytest.raises(ValueError, match="current has 2, 1 in common"):
        run([*BASELINE, extra])


def test_empty_baseline_raises() -> None:
    with pytest.raises(ValueError, match="baseline scan has no findings"):
        diff_scans([], BASELINE, [], TODAY)


def test_empty_current_raises() -> None:
    with pytest.raises(ValueError, match="current scan has no findings"):
        run([])


def test_empty_scan_checked_before_accounts() -> None:
    other = [replace(f, account_uid=OTHER_FAKE_ACCOUNT) for f in BASELINE]
    with pytest.raises(ValueError, match="baseline scan has no findings"):
        diff_scans([], other, [], TODAY)


def test_bad_filter_arguments_raise() -> None:
    with pytest.raises(ValueError, match="unknown minimum severity"):
        run(BASELINE, min_severity="urgent")
