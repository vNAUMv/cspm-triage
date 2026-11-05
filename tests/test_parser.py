"""Tests for cspm_triage.parser."""

import copy
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

from cspm_triage.parser import load_findings, parse_finding, parse_findings

FIXTURE = Path(__file__).parent / "fixtures" / "sample_scan.ocsf.json"
FAKE_ACCOUNT = "123456789012"


def minimal_record() -> dict[str, Any]:
    """A record with only the fields the parser reads, shaped like the real OCSF output."""
    return {
        "metadata": {"event_code": "iam_user_hardware_mfa_enabled"},
        "status_code": "FAIL",
        "status": "New",
        "severity": "High",
        "finding_info": {
            "title": "IAM user has hardware MFA enabled",
            "uid": "prowler-aws-iam_user_hardware_mfa_enabled-123456789012-us-east-1-example-user",
        },
        "status_detail": "User example-user does not have any type of MFA enabled.",
        "resources": [{"uid": "arn:aws:iam::123456789012:user/example-user"}],
        "cloud": {"account": {"uid": "123456789012"}, "region": "us-east-1"},
        "remediation": {
            "desc": "Require hardware-backed MFA for all IAM users.",
            "references": ["https://hub.prowler.com/check/iam_user_hardware_mfa_enabled"],
        },
    }


# --- fixture ---------------------------------------------------------------


def test_fixture_contains_only_fake_account_id() -> None:
    text = FIXTURE.read_text(encoding="utf-8")
    assert set(re.findall(r"\b\d{12}\b", text)) == {FAKE_ACCOUNT}


def test_load_fixture_counts() -> None:
    findings = load_findings(FIXTURE)
    assert len(findings) == 8
    assert Counter(f.status for f in findings) == {"FAIL": 4, "PASS": 2, "MANUAL": 2}
    assert {f.severity for f in findings} == {"Critical", "High", "Medium", "Low"}


def test_load_fixture_maps_fields() -> None:
    finding = next(
        f for f in load_findings(FIXTURE) if f.event_code == "iam_user_hardware_mfa_enabled"
    )
    assert finding.status == "FAIL"
    assert finding.severity == "High"
    assert finding.status_detail == "User example-user does not have any type of MFA enabled."
    assert finding.finding_uid == (
        "prowler-aws-iam_user_hardware_mfa_enabled-123456789012-us-east-1-example-user"
    )
    assert finding.resource_uids == ("arn:aws:iam::123456789012:user/example-user",)
    assert finding.region == "us-east-1"
    assert finding.account_uid == FAKE_ACCOUNT
    assert finding.title
    assert finding.remediation_desc
    assert finding.remediation_references == (
        "https://hub.prowler.com/check/iam_user_hardware_mfa_enabled",
    )


# --- parse_finding ---------------------------------------------------------


def test_status_comes_from_status_code_not_status() -> None:
    assert parse_finding(minimal_record()).status == "FAIL"


def test_unknown_severity_is_kept_as_is() -> None:
    record = minimal_record()
    record["severity"] = "Informational"
    assert parse_finding(record).severity == "Informational"


def test_multiple_resources_keep_all_uids() -> None:
    record = minimal_record()
    record["resources"].append({"uid": "arn:aws:iam::123456789012:user/example-user-2"})
    assert parse_finding(record).resource_uids == (
        "arn:aws:iam::123456789012:user/example-user",
        "arn:aws:iam::123456789012:user/example-user-2",
    )


def test_empty_resources_raises() -> None:
    record = minimal_record()
    record["resources"] = []
    with pytest.raises(ValueError, match="resources must not be empty"):
        parse_finding(record)


def test_non_object_resource_raises() -> None:
    record = minimal_record()
    record["resources"] = ["arn:aws:iam::123456789012:root"]
    with pytest.raises(ValueError, match=r"resources\[0\] must be an object"):
        parse_finding(record)


@pytest.mark.parametrize(
    ("section", "key", "path"),
    [
        ("metadata", "event_code", "metadata.event_code"),
        ("finding_info", "uid", "finding_info.uid"),
        ("cloud", "region", "cloud.region"),
        ("cloud", "account", "cloud.account.uid"),
        ("remediation", "references", "remediation.references"),
    ],
)
def test_missing_nested_field_raises(section: str, key: str, path: str) -> None:
    record = minimal_record()
    del record[section][key]
    with pytest.raises(ValueError, match=f"missing field: {re.escape(path)}"):
        parse_finding(record)


def test_missing_top_level_field_raises() -> None:
    record = minimal_record()
    del record["status_code"]
    with pytest.raises(ValueError, match="missing field: status_code"):
        parse_finding(record)


def test_wrong_type_raises() -> None:
    record = minimal_record()
    record["severity"] = 4
    with pytest.raises(ValueError, match="severity must be str, got int"):
        parse_finding(record)


def test_non_string_reference_raises() -> None:
    record = minimal_record()
    record["remediation"]["references"] = [None]
    with pytest.raises(ValueError, match="remediation.references must contain only strings"):
        parse_finding(record)


# --- parse_findings / load_findings ----------------------------------------


def test_parse_findings_rejects_non_list() -> None:
    with pytest.raises(ValueError, match="scan must be a JSON array, got dict"):
        parse_findings({"findings": []})


def test_parse_findings_reports_index_of_bad_record() -> None:
    bad = copy.deepcopy(minimal_record())
    del bad["severity"]
    with pytest.raises(ValueError, match="finding #1: missing field: severity"):
        parse_findings([minimal_record(), bad])


def test_parse_findings_rejects_non_object_record() -> None:
    with pytest.raises(ValueError, match="finding #0: must be a JSON object"):
        parse_findings(["not a finding"])


def test_load_findings_empty_scan(tmp_path: Path) -> None:
    path = tmp_path / "empty.ocsf.json"
    path.write_text(json.dumps([]), encoding="utf-8")
    assert load_findings(path) == []
