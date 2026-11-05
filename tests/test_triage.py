"""Tests for cspm_triage.triage. All data is fake; "today" is fixed."""

from dataclasses import replace
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from cspm_triage.models import Finding
from cspm_triage.triage import (
    AcceptedRisk,
    filter_findings,
    is_active,
    load_accepted_risks,
    parse_accepted_risks,
    risk_matches,
    severity_rank,
    sort_findings,
    triage,
)

TODAY = date(2026, 6, 15)
EXAMPLE_FILE = Path(__file__).parent.parent / "config" / "exceptions.example.toml"
USER_ARN = "arn:aws:iam::123456789012:user/example-user"
ROLE_ARN = "arn:aws:iam::123456789012:role/example-role"

BASE_FINDING = Finding(
    event_code="iam_user_hardware_mfa_enabled",
    status="FAIL",
    severity="High",
    title="IAM user has hardware MFA enabled",
    status_detail="User example-user does not have any type of MFA enabled.",
    finding_uid="prowler-aws-iam_user_hardware_mfa_enabled-123456789012-us-east-1-example-user",
    resource_uids=(USER_ARN,),
    region="us-east-1",
    remediation_desc="Enable hardware MFA.",
    remediation_references=(),
)

BASE_RISK = AcceptedRisk(
    check_id="iam_user_hardware_mfa_enabled",
    resources=(),
    region=None,
    reason="Accepted for testing",
    owner="security-team@example.com",
    expires=TODAY + timedelta(days=30),
    source="exceptions.toml",
    position=1,
)


def finding(**changes: object) -> Finding:
    return replace(BASE_FINDING, **changes)  # type: ignore[arg-type]


def risk(**changes: object) -> AcceptedRisk:
    return replace(BASE_RISK, **changes)  # type: ignore[arg-type]


def entry(**changes: object) -> dict[str, Any]:
    """A valid decoded TOML exception entry."""
    data: dict[str, Any] = {
        "check_id": "iam_user_hardware_mfa_enabled",
        "reason": "Accepted for testing",
        "owner": "security-team@example.com",
        "expires": date(2026, 12, 31),
    }
    data.update(changes)
    return data


def parse_one(**changes: object) -> AcceptedRisk:
    return parse_accepted_risks({"exceptions": [entry(**changes)]}, "x.toml")[0]


# --- severity ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("severity", "rank"),
    [("Critical", 0), ("high", 1), ("MEDIUM", 2), ("Low", 3), ("Informational", 4), ("Fatal", -1)],
)
def test_severity_rank(severity: str, rank: int) -> None:
    assert severity_rank(severity) == rank


# --- filtering ---------------------------------------------------------------


def test_default_filter_keeps_fail_only() -> None:
    kept = filter_findings([finding(status=s) for s in ("FAIL", "PASS", "MANUAL")])
    assert [f.status for f in kept] == ["FAIL"]


def test_custom_statuses_ignore_case() -> None:
    kept = filter_findings(
        [finding(status=s) for s in ("FAIL", "PASS", "MANUAL")], {"fail", "manual"}
    )
    assert [f.status for f in kept] == ["FAIL", "MANUAL"]


def test_default_min_severity_drops_informational() -> None:
    kept = filter_findings([finding(severity="Low"), finding(severity="Informational")])
    assert [f.severity for f in kept] == ["Low"]


def test_min_severity_informational_keeps_all_known() -> None:
    severities = ["Critical", "High", "Medium", "Low", "Informational"]
    kept = filter_findings([finding(severity=s) for s in severities], min_severity="informational")
    assert len(kept) == 5


def test_min_severity_high() -> None:
    severities = ["Critical", "High", "Medium", "Low"]
    kept = filter_findings([finding(severity=s) for s in severities], min_severity="High")
    assert [f.severity for f in kept] == ["Critical", "High"]


def test_unknown_status_is_kept() -> None:
    assert filter_findings([finding(status="MUTED")]) == [finding(status="MUTED")]


def test_unknown_severity_is_kept_above_any_minimum() -> None:
    kept = filter_findings([finding(severity="Fatal")], min_severity="critical")
    assert kept == [finding(severity="Fatal")]


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"statuses": {"FAILED"}}, "unknown status filter value"),
        ({"statuses": set()}, "at least one status"),
        ({"min_severity": "urgent"}, "unknown minimum severity"),
    ],
)
def test_bad_filter_arguments_raise(kwargs: dict[str, Any], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        filter_findings([finding()], **kwargs)


# --- sorting -----------------------------------------------------------------


def test_sort_by_severity_then_check_then_resource() -> None:
    findings = [
        finding(severity="Low", event_code="a_check"),
        finding(severity="High", event_code="b_check", resource_uids=(ROLE_ARN,)),
        finding(severity="High", event_code="b_check", resource_uids=(USER_ARN,)),
        finding(severity="High", event_code="a_check"),
        finding(severity="Critical", event_code="z_check"),
        finding(severity="Fatal", event_code="z_check"),
    ]
    ordered = [(f.severity, f.event_code, f.resource_uids[0]) for f in sort_findings(findings)]
    assert ordered == [
        ("Fatal", "z_check", USER_ARN),
        ("Critical", "z_check", USER_ARN),
        ("High", "a_check", USER_ARN),
        ("High", "b_check", ROLE_ARN),
        ("High", "b_check", USER_ARN),
        ("Low", "a_check", USER_ARN),
    ]


# --- matching ----------------------------------------------------------------


def test_check_id_must_match_exactly() -> None:
    assert risk_matches(risk(), finding())
    assert not risk_matches(risk(check_id="iam_user_hardware_mfa"), finding())


def test_empty_resources_covers_whole_check() -> None:
    assert risk_matches(risk(resources=()), finding(resource_uids=(ROLE_ARN,)))


def test_resource_glob_pattern() -> None:
    pattern = risk(resources=("arn:aws:iam::123456789012:user/example-*",))
    assert risk_matches(pattern, finding())
    assert not risk_matches(pattern, finding(resource_uids=(ROLE_ARN,)))


def test_resource_pattern_is_case_sensitive() -> None:
    assert not risk_matches(risk(resources=(USER_ARN.upper(),)), finding())


def test_region_must_match_when_set() -> None:
    assert risk_matches(risk(region="us-east-1"), finding())
    assert not risk_matches(risk(region="eu-west-1"), finding())


def test_every_resource_must_match() -> None:
    two = finding(resource_uids=(USER_ARN, ROLE_ARN))
    assert not risk_matches(risk(resources=(USER_ARN,)), two)
    assert risk_matches(risk(resources=(USER_ARN, ROLE_ARN)), two)


def test_finding_without_resources_not_matched_by_resource_patterns() -> None:
    assert not risk_matches(risk(resources=("*",)), finding(resource_uids=()))


# --- expiry ------------------------------------------------------------------


@pytest.mark.parametrize(("offset", "active"), [(-1, False), (0, True), (1, True)])
def test_is_active_through_expiry_date(offset: int, active: bool) -> None:
    assert is_active(risk(expires=TODAY + timedelta(days=offset)), TODAY) is active


def test_expired_risk_does_not_suppress_and_warns() -> None:
    expired = risk(expires=TODAY - timedelta(days=1), position=2)
    result = triage([finding()], [expired], TODAY)
    assert result.attention == (finding(),)
    assert result.accepted == ()
    assert result.warnings == (
        "exceptions.toml: exception #2 (iam_user_hardware_mfa_enabled) expired on 2026-06-14; "
        "not applied",
    )


def test_expired_risk_warns_even_without_matching_findings() -> None:
    result = triage([], [risk(check_id="other_check", expires=date(2026, 1, 1))], TODAY)
    assert len(result.warnings) == 1


# --- triage ------------------------------------------------------------------


def test_triage_keeps_suppressed_findings_with_their_risk() -> None:
    accepted = risk(resources=(USER_ARN,))
    other = finding(event_code="iam_root_hardware_mfa_enabled", severity="Critical")
    result = triage([finding(), other, finding(status="PASS")], [accepted], TODAY)
    assert result.attention == (other,)
    assert len(result.accepted) == 1
    assert result.accepted[0].finding == finding()
    assert result.accepted[0].risk is accepted
    assert result.warnings == ()


def test_first_matching_active_risk_wins() -> None:
    expired = risk(position=1, expires=TODAY - timedelta(days=1))
    first = risk(position=2)
    second = risk(position=3)
    result = triage([finding()], [expired, first, second], TODAY)
    assert result.accepted[0].risk is first


def test_triage_sorts_both_lists() -> None:
    findings = [finding(severity="Low"), finding(severity="Critical", event_code="other")]
    covered = [
        finding(severity="Low", event_code="covered"),
        finding(severity="High", event_code="covered"),
    ]
    result = triage([*findings, *covered], [risk(check_id="covered")], TODAY)
    assert [f.severity for f in result.attention] == ["Critical", "Low"]
    assert [s.finding.severity for s in result.accepted] == ["High", "Low"]


def test_triage_warns_about_unknown_values_once_per_value() -> None:
    findings = [finding(severity="Fatal"), finding(severity="Fatal"), finding(status="MUTED")]
    result = triage(findings, [], TODAY)
    assert result.warnings == (
        "1 finding(s) with unrecognized status 'MUTED' were kept",
        "2 finding(s) with unrecognized severity 'Fatal' were kept and sorted first",
    )


def test_triage_passes_filter_options() -> None:
    result = triage(
        [finding(status="MANUAL", severity="Medium")],
        [],
        TODAY,
        statuses={"MANUAL"},
        min_severity="medium",
    )
    assert len(result.attention) == 1


# --- parsing accepted risks --------------------------------------------------


def test_parse_full_entry() -> None:
    parsed = parse_one(resources=[USER_ARN], region="us-east-1")
    assert parsed == AcceptedRisk(
        check_id="iam_user_hardware_mfa_enabled",
        resources=(USER_ARN,),
        region="us-east-1",
        reason="Accepted for testing",
        owner="security-team@example.com",
        expires=date(2026, 12, 31),
        source="x.toml",
        position=1,
    )


def test_parse_defaults_for_optional_fields() -> None:
    parsed = parse_one()
    assert parsed.resources == ()
    assert parsed.region is None


def test_parse_empty_data() -> None:
    assert parse_accepted_risks({}, "x.toml") == []


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"expiry": date(2026, 1, 1)}, "unknown field\\(s\\): expiry"),
        ({"check_id": ""}, "'check_id' must be a non-empty string"),
        ({"owner": 42}, "'owner' must be a non-empty string"),
        ({"resources": "arn:*"}, "'resources' must be a list of non-empty strings"),
        ({"resources": [""]}, "'resources' must be a list of non-empty strings"),
        ({"region": ""}, "'region' must be a non-empty string"),
        ({"expires": "2026-12-31"}, "'expires' must be a TOML date"),
        ({"expires": datetime(2026, 12, 31, 0, 0)}, "'expires' must be a TOML date"),
    ],
)
def test_parse_invalid_entry_names_source_and_position(
    changes: dict[str, Any], message: str
) -> None:
    data = {"exceptions": [entry(), entry(**changes)]}
    with pytest.raises(ValueError, match=f"^x.toml: exception #2: {message}"):
        parse_accepted_risks(data, "x.toml")


@pytest.mark.parametrize("field", ["check_id", "reason", "owner", "expires"])
def test_parse_missing_required_field(field: str) -> None:
    broken = entry()
    del broken[field]
    with pytest.raises(
        ValueError, match=f"x.toml: exception #1: missing required field\\(s\\): {field}"
    ):
        parse_accepted_risks({"exceptions": [broken]}, "x.toml")


def test_parse_unknown_top_level_key() -> None:
    with pytest.raises(ValueError, match="x.toml: unknown top-level key\\(s\\): exception"):
        parse_accepted_risks({"exception": [entry()]}, "x.toml")


def test_parse_exceptions_must_be_array_of_tables() -> None:
    with pytest.raises(ValueError, match="must be an array of tables"):
        parse_accepted_risks({"exceptions": {"check_id": "x"}}, "x.toml")


def test_parse_entry_must_be_table() -> None:
    with pytest.raises(ValueError, match="x.toml: exception #1: must be a table"):
        parse_accepted_risks({"exceptions": ["iam_user_hardware_mfa_enabled"]}, "x.toml")


# --- loading files -----------------------------------------------------------


TOML_ENTRY = '[[exceptions]]\ncheck_id = "c"\nreason = "r"\nowner = "o"\n'


def write_toml(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "exceptions.toml"
    path.write_text(text, encoding="utf-8")
    return path


def test_load_file_with_toml_date(tmp_path: Path) -> None:
    path = write_toml(tmp_path, TOML_ENTRY + "expires = 2026-12-31\n")
    [loaded] = load_accepted_risks(path)
    assert loaded.expires == date(2026, 12, 31)
    assert loaded.source == str(path)


def test_load_rejects_toml_datetime(tmp_path: Path) -> None:
    path = write_toml(tmp_path, TOML_ENTRY + "expires = 2026-12-31T00:00:00\n")
    with pytest.raises(ValueError, match="exception #1: 'expires' must be a TOML date"):
        load_accepted_risks(path)


def test_load_invalid_toml_names_file(tmp_path: Path) -> None:
    path = write_toml(tmp_path, "[[exceptions]\n")
    with pytest.raises(ValueError, match=f"^{path}: invalid TOML"):
        load_accepted_risks(path)


def test_load_empty_file(tmp_path: Path) -> None:
    assert load_accepted_risks(write_toml(tmp_path, "")) == []


def test_example_file_is_valid_and_uses_fake_data() -> None:
    risks = load_accepted_risks(EXAMPLE_FILE)
    assert len(risks) == 3
    assert all(is_active(r, TODAY) for r in risks)
    text = EXAMPLE_FILE.read_text(encoding="utf-8")
    assert "123456789012" in text
    assert "example-user" in text
    assert "example-role" in text
