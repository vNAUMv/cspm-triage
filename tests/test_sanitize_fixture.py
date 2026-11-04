"""Tests for scripts/sanitize_fixture.py. All identifiers here are made up."""

import json
from pathlib import Path
from typing import Any

import pytest

from cspm_triage.parser import parse_findings
from scripts.sanitize_fixture import (
    SanitizeError,
    Sanitizer,
    collect_account_ids,
    collect_iam_names,
    main,
    parse_pick,
    sanitize_scan,
    select_findings,
    strip_record,
)

# Fake inputs: AWS documentation example account, invented names, reserved IP/domain ranges.
ACCOUNT = "111122223333"
USER = "alice-test"
ROLE = "build-runner"
UUID = "c0ffee00-1234-4abc-8def-0123456789ab"
SG = "sg-0abc1234def567890"
EMAIL = "alice@corp.invalid"
IP = "203.0.113.7"


def make_record(status: str = "FAIL", severity: str = "High") -> dict[str, Any]:
    """A finding shaped like Prowler OCSF output, containing every kind of identifier."""
    user_arn = f"arn:aws:iam::{ACCOUNT}:user/{USER}"
    record: dict[str, Any] = {
        "metadata": {"event_code": "iam_user_hardware_mfa_enabled"},
        "status_code": status,
        "status": "New",
        "severity": severity,
        "finding_info": {
            "title": "IAM user has hardware MFA enabled",
            "uid": f"prowler-aws-iam_user_hardware_mfa_enabled-{ACCOUNT}-us-east-1-{USER}",
        },
        "status_detail": f"User {USER} does not have any type of MFA enabled.",
        "message": f"User {USER} uses {SG} from {IP}; contact {EMAIL}.",
        "resources": [
            {
                "uid": user_arn,
                "name": f"{USER}/ViewOnlyAccess",
                "region": "us-east-1",
                "data": {"details": "raw", "metadata": {f"arn:aws:iam::{ACCOUNT}:x": {}}},
            }
        ],
        "cloud": {"account": {"uid": ACCOUNT}, "region": "us-east-1"},
        "remediation": {"desc": "Enable MFA.", "references": ["https://example.com/doc"]},
        "unmapped": {"scan_id": UUID, "provider_uid": ACCOUNT, "compliance": {"CIS": ["1.1"]}},
    }
    return record


def sanitized(records: list[dict[str, Any]], pick: list[int] | None = None) -> str:
    text, _ = sanitize_scan(records, pick)
    return text


# --- collection --------------------------------------------------------------


def test_collect_account_ids_from_cloud_and_arns() -> None:
    other = "444455556666"
    record = make_record()
    record["resources"].append({"uid": f"arn:aws:s3:us-east-1:{other}:bucket"})
    assert collect_account_ids([record]) == [ACCOUNT, other]


def test_collect_iam_names_skips_aws_managed() -> None:
    texts = [
        f"arn:aws:iam::{ACCOUNT}:user/{USER}",
        f"arn:aws:iam::{ACCOUNT}:role/{ROLE}",
        f"arn:aws:iam::{ACCOUNT}:role/aws-service-role/support.amazonaws.com/SomeServiceRole",
        "arn:aws:iam::aws:policy/SecurityAudit",
    ]
    assert collect_iam_names([{"values": texts}]) == {
        USER: "example-user-1",
        ROLE: "example-role-1",
    }


# --- replacement ---------------------------------------------------------------


def test_account_and_user_replaced_in_free_text_and_uids() -> None:
    record = json.loads(sanitized([make_record()]))[0]
    assert record["finding_info"]["uid"] == (
        "prowler-aws-iam_user_hardware_mfa_enabled-123456789012-us-east-1-example-user-1"
    )
    assert record["status_detail"] == "User example-user-1 does not have any type of MFA enabled."
    assert record["resources"][0]["uid"] == "arn:aws:iam::123456789012:user/example-user-1"
    assert record["resources"][0]["name"] == "example-user-1/ViewOnlyAccess"
    assert record["cloud"]["account"]["uid"] == "123456789012"


def test_generated_identifiers_replaced() -> None:
    text = sanitized([make_record()])
    for original in (ACCOUNT, USER, UUID, SG, EMAIL, IP):
        assert original not in text
    message = json.loads(text)[0]["message"]
    assert message == (
        "User example-user-1 uses sg-00000000000000001 from 192.0.2.1; contact user1@example.com."
    )


def test_replacements_are_consistent() -> None:
    sanitizer = Sanitizer({})
    assert sanitizer.text(UUID) == sanitizer.text(f"x {UUID}").removeprefix("x ")


def test_names_replaced_only_as_whole_words() -> None:
    sanitizer = Sanitizer({USER: "example-user-1"})
    assert sanitizer.text(f"m{USER}er and {USER}") == f"m{USER}er and example-user-1"


def test_dictionary_keys_are_sanitized() -> None:
    sanitizer = Sanitizer({ACCOUNT: "123456789012"})
    assert sanitizer.value({f"arn:aws:x:{ACCOUNT}": 1}) == {"arn:aws:x:123456789012": 1}


def test_open_cidr_is_kept() -> None:
    assert Sanitizer({}).text("0.0.0.0/0") == "0.0.0.0/0"


def test_access_key_id_aborts() -> None:
    fake_key = "AKIA" + "X" * 16
    with pytest.raises(SanitizeError, match="access key"):
        Sanitizer({}).text(f"key {fake_key}")


# --- leak checks ---------------------------------------------------------------


def test_leak_check_refuses_and_hides_value() -> None:
    sanitizer = Sanitizer({USER: "example-user-1"})
    with pytest.raises(SanitizeError, match="1 original value") as exc:
        sanitizer.check_no_leaks(f"still has {USER}")
    assert USER not in str(exc.value)


def test_leak_check_refuses_unknown_twelve_digit_number() -> None:
    sanitizer = Sanitizer({ACCOUNT: "123456789012"})
    with pytest.raises(SanitizeError, match="12-digit"):
        sanitizer.check_no_leaks("id 999988887777")


# --- selection and stripping ---------------------------------------------------


def test_select_one_per_status_severity_pair_in_order() -> None:
    records = [
        make_record("PASS", "Low"),
        make_record("FAIL", "High"),
        make_record("FAIL", "High"),
        make_record("MANUAL", "Medium"),
        make_record("FAIL", "Critical"),
        make_record("FAIL", "Unknown"),
    ]
    picked = select_findings(records)
    assert [(r["status_code"], r["severity"]) for r in picked] == [
        ("FAIL", "Critical"),
        ("FAIL", "High"),
        ("FAIL", "Unknown"),
        ("PASS", "Low"),
        ("MANUAL", "Medium"),
    ]
    assert picked[1] is records[1]


def test_select_with_pick() -> None:
    records = [make_record("PASS"), make_record("FAIL")]
    assert select_findings(records, [1]) == [records[1]]


def test_select_with_bad_pick_raises() -> None:
    with pytest.raises(SanitizeError, match="between 0 and 0"):
        select_findings([make_record()], [5])


def test_strip_record_drops_raw_data_and_compliance() -> None:
    original = make_record()
    stripped = strip_record(original)
    assert stripped["resources"][0]["data"] == {"details": "", "metadata": {}}
    assert "compliance" not in stripped["unmapped"]
    assert original["resources"][0]["data"]["details"] == "raw"


def test_sanitize_scan_rejects_non_array() -> None:
    with pytest.raises(SanitizeError, match="JSON array"):
        sanitize_scan({"findings": []})


def test_parse_pick() -> None:
    assert parse_pick("3, 1,") == [3, 1]


# --- end to end ------------------------------------------------------------------


def test_main_writes_fixture_the_parser_accepts(tmp_path: Path) -> None:
    source = tmp_path / "scan.ocsf.json"
    output = tmp_path / "fixture.ocsf.json"
    source.write_text(json.dumps([make_record("FAIL"), make_record("PASS")]), encoding="utf-8")
    assert main([str(source), str(output)]) == 0
    findings = parse_findings(json.loads(output.read_text(encoding="utf-8")))
    assert [f.status for f in findings] == ["FAIL", "PASS"]
    assert ACCOUNT not in output.read_text(encoding="utf-8")


def test_main_reports_error_without_writing(tmp_path: Path) -> None:
    source = tmp_path / "scan.ocsf.json"
    output = tmp_path / "fixture.ocsf.json"
    source.write_text(json.dumps({"not": "a list"}), encoding="utf-8")
    assert main([str(source), str(output)]) == 1
    assert not output.exists()
