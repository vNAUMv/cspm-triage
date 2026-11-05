"""Load and normalize Prowler OCSF findings."""

import json
from pathlib import Path
from typing import Any

from cspm_triage.models import Finding


def _get(raw: dict[str, Any], path: str, expected: type) -> Any:  # noqa: ANN401
    """Return the value at a dotted path, checking that it exists and has the expected type."""
    value: Any = raw
    for key in path.split("."):
        if not isinstance(value, dict) or key not in value:
            raise ValueError(f"missing field: {path}")
        value = value[key]
    if not isinstance(value, expected):
        raise ValueError(f"field {path} must be {expected.__name__}, got {type(value).__name__}")
    return value


def _str_tuple(values: list[Any], path: str) -> tuple[str, ...]:
    """Convert a list to a tuple of strings, rejecting non-string items."""
    if not all(isinstance(v, str) for v in values):
        raise ValueError(f"field {path} must contain only strings")
    return tuple(values)


def _resource_uids(raw: dict[str, Any]) -> tuple[str, ...]:
    """Return the uid of every resource; a finding must have at least one."""
    resources = _get(raw, "resources", list)
    if not resources:
        raise ValueError("field resources must not be empty")
    uids: list[str] = []
    for index, resource in enumerate(resources):
        if not isinstance(resource, dict):
            raise ValueError(f"field resources[{index}] must be an object")
        uids.append(_get(resource, "uid", str))
    return tuple(uids)


def parse_finding(raw: dict[str, Any]) -> Finding:
    """Convert one raw OCSF finding record into a Finding."""
    resource_uids = _resource_uids(raw)
    return Finding(
        event_code=_get(raw, "metadata.event_code", str),
        status=_get(raw, "status_code", str),
        severity=_get(raw, "severity", str),
        title=_get(raw, "finding_info.title", str),
        status_detail=_get(raw, "status_detail", str),
        finding_uid=_get(raw, "finding_info.uid", str),
        account_uid=_get(raw, "cloud.account.uid", str),
        resource_uids=resource_uids,
        region=_get(raw, "cloud.region", str),
        remediation_desc=_get(raw, "remediation.desc", str),
        remediation_references=_str_tuple(
            _get(raw, "remediation.references", list), "remediation.references"
        ),
    )


def parse_findings(records: Any) -> list[Finding]:  # noqa: ANN401
    """Convert a decoded scan (a JSON array of findings) into Findings."""
    if not isinstance(records, list):
        raise ValueError(f"scan must be a JSON array, got {type(records).__name__}")
    findings: list[Finding] = []
    for index, raw in enumerate(records):
        if not isinstance(raw, dict):
            raise ValueError(f"finding #{index}: must be a JSON object")
        try:
            findings.append(parse_finding(raw))
        except ValueError as exc:
            raise ValueError(f"finding #{index}: {exc}") from exc
    return findings


def load_findings(path: Path) -> list[Finding]:
    """Load a Prowler OCSF JSON scan file into a list of Findings."""
    with path.open(encoding="utf-8") as fh:
        return parse_findings(json.load(fh))
