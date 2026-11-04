"""Tests for cspm_triage.models."""

import dataclasses

import pytest

from cspm_triage.models import Finding


def make_finding() -> Finding:
    return Finding(
        event_code="iam_root_mfa_enabled",
        status="PASS",
        severity="Critical",
        title="Root account has MFA enabled",
        status_detail="MFA is enabled for root account.",
        finding_uid="prowler-aws-iam_root_mfa_enabled-123456789012-us-east-1-<root_account>",
        resource_uids=("arn:aws:iam::123456789012:root",),
        region="us-east-1",
        remediation_desc="Enable MFA for the root user.",
        remediation_references=("https://hub.prowler.com/check/iam_root_mfa_enabled",),
    )


def test_finding_is_frozen() -> None:
    finding = make_finding()
    with pytest.raises(dataclasses.FrozenInstanceError):
        finding.status = "FAIL"  # type: ignore[misc]


def test_findings_with_same_values_are_equal() -> None:
    assert make_finding() == make_finding()
