"""Filtering, prioritization, and accepted-risk exceptions.

Rules:
- Statuses PASS, FAIL and MANUAL are known. A finding with any other status is
  kept whatever the status filter says, and reported in a warning.
- Severities, highest first: Critical, High, Medium, Low, Informational. A
  finding with any other severity is kept whatever the minimum severity, sorted
  before Critical (OCSF has values above Critical, so it may be more severe),
  and reported in a warning.
- Status and severity comparisons ignore case.
- An accepted risk (exception) applies up to and including its expiry date. An
  expired exception suppresses nothing and is reported in a warning.
"""

import fnmatch
import tomllib
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any

from cspm_triage.models import Finding

KNOWN_STATUSES = frozenset({"PASS", "FAIL", "MANUAL"})
SEVERITY_ORDER = ("critical", "high", "medium", "low", "informational")
UNKNOWN_SEVERITY_RANK = -1  # sorts before Critical
DEFAULT_STATUSES = frozenset({"FAIL"})
DEFAULT_MIN_SEVERITY = "low"

TEXT_FIELDS = ("check_id", "reason", "owner")
REQUIRED_FIELDS = (*TEXT_FIELDS, "expires")
ALLOWED_FIELDS = frozenset({*REQUIRED_FIELDS, "resources", "region"})


@dataclass(frozen=True, slots=True)
class AcceptedRisk:
    """One entry of the exceptions file."""

    check_id: str
    resources: tuple[str, ...]  # glob patterns; empty means the whole check
    region: str | None
    reason: str
    owner: str
    expires: date
    source: str  # file the entry came from
    position: int  # 1-based position of the entry in that file


@dataclass(frozen=True, slots=True)
class Suppressed:
    """A finding hidden by an accepted risk, kept for reporting."""

    finding: Finding
    risk: AcceptedRisk


@dataclass(frozen=True, slots=True)
class TriageResult:
    """Findings that need attention, findings accepted as risks, and warnings."""

    attention: tuple[Finding, ...]
    accepted: tuple[Suppressed, ...]
    warnings: tuple[str, ...]


# --- severity and status -----------------------------------------------------


def severity_rank(severity: str) -> int:
    """Return 0 for Critical up to 4 for Informational; UNKNOWN_SEVERITY_RANK otherwise."""
    key = severity.strip().lower()
    return SEVERITY_ORDER.index(key) if key in SEVERITY_ORDER else UNKNOWN_SEVERITY_RANK


def _normalize_statuses(statuses: Iterable[str]) -> frozenset[str]:
    wanted = frozenset(s.strip().upper() for s in statuses)
    if not wanted:
        raise ValueError("statuses must contain at least one status")
    unknown = wanted - KNOWN_STATUSES
    if unknown:
        raise ValueError(f"unknown status filter value(s): {', '.join(sorted(unknown))}")
    return wanted


def _min_severity_rank(min_severity: str) -> int:
    rank = severity_rank(min_severity)
    if rank == UNKNOWN_SEVERITY_RANK:
        raise ValueError(f"unknown minimum severity: {min_severity!r}")
    return rank


def _status_selected(finding: Finding, wanted: frozenset[str]) -> bool:
    status = finding.status.strip().upper()
    return status in wanted or status not in KNOWN_STATUSES


# --- filtering and sorting ---------------------------------------------------


def filter_findings(
    findings: Iterable[Finding],
    statuses: Iterable[str] = DEFAULT_STATUSES,
    min_severity: str = DEFAULT_MIN_SEVERITY,
) -> list[Finding]:
    """Keep findings with a selected status and at least the minimum severity.

    Findings with an unknown status or severity are always kept.
    """
    wanted = _normalize_statuses(statuses)
    max_rank = _min_severity_rank(min_severity)
    # Unknown severities have rank -1, so they always pass the severity check.
    return [
        f for f in findings if _status_selected(f, wanted) and severity_rank(f.severity) <= max_rank
    ]


def sort_key(finding: Finding) -> tuple[int, str, tuple[str, ...]]:
    """Order by severity (unknown, then Critical first), check ID, resource UIDs."""
    return (severity_rank(finding.severity), finding.event_code, finding.resource_uids)


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Return findings sorted by sort_key."""
    return sorted(findings, key=sort_key)


# --- loading accepted risks --------------------------------------------------


def load_accepted_risks(path: Path) -> list[AcceptedRisk]:
    """Load accepted risks from a TOML file; raise ValueError on any problem."""
    try:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"{path}: invalid TOML: {exc}") from exc
    return parse_accepted_risks(data, str(path))


def parse_accepted_risks(data: dict[str, Any], source: str) -> list[AcceptedRisk]:
    """Validate decoded TOML data and convert it to AcceptedRisk entries."""
    unknown = set(data) - {"exceptions"}
    if unknown:
        raise ValueError(f"{source}: unknown top-level key(s): {', '.join(sorted(unknown))}")
    entries = data.get("exceptions", [])
    if not isinstance(entries, list):
        raise ValueError(f"{source}: 'exceptions' must be an array of tables ([[exceptions]])")
    return [_parse_entry(entry, source, pos) for pos, entry in enumerate(entries, start=1)]


def _parse_entry(entry: object, source: str, position: int) -> AcceptedRisk:
    where = f"{source}: exception #{position}"
    if not isinstance(entry, dict):
        raise ValueError(f"{where}: must be a table")
    _check_keys(entry, where)
    return AcceptedRisk(
        check_id=_text(entry, "check_id", where),
        resources=_resources(entry, where),
        region=_region(entry, where),
        reason=_text(entry, "reason", where),
        owner=_text(entry, "owner", where),
        expires=_expires(entry, where),
        source=source,
        position=position,
    )


def _check_keys(entry: dict[str, Any], where: str) -> None:
    unknown = set(entry) - ALLOWED_FIELDS
    if unknown:
        raise ValueError(f"{where}: unknown field(s): {', '.join(sorted(unknown))}")
    missing = [name for name in REQUIRED_FIELDS if name not in entry]
    if missing:
        raise ValueError(f"{where}: missing required field(s): {', '.join(missing)}")


def _text(entry: dict[str, Any], name: str, where: str) -> str:
    value = entry[name]
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{where}: '{name}' must be a non-empty string")
    return value


def _resources(entry: dict[str, Any], where: str) -> tuple[str, ...]:
    value = entry.get("resources", [])
    if not isinstance(value, list) or not all(isinstance(p, str) and p.strip() for p in value):
        raise ValueError(f"{where}: 'resources' must be a list of non-empty strings")
    return tuple(value)


def _region(entry: dict[str, Any], where: str) -> str | None:
    if "region" not in entry:
        return None
    return _text(entry, "region", where)


def _expires(entry: dict[str, Any], where: str) -> date:
    value = entry["expires"]
    # tomllib returns datetime for date-time values, and datetime is a date subclass.
    if isinstance(value, datetime) or not isinstance(value, date):
        raise ValueError(f"{where}: 'expires' must be a TOML date such as 2027-01-31")
    return value


# --- matching and triage -----------------------------------------------------


def is_active(risk: AcceptedRisk, today: date) -> bool:
    """An accepted risk applies up to and including its expiry date."""
    return today <= risk.expires


def risk_matches(risk: AcceptedRisk, finding: Finding) -> bool:
    """Check ID and region must match; every resource UID must match some pattern."""
    if risk.check_id != finding.event_code:
        return False
    if risk.region is not None and risk.region != finding.region:
        return False
    if not risk.resources:
        return True
    return bool(finding.resource_uids) and all(
        any(fnmatch.fnmatchcase(uid, pattern) for pattern in risk.resources)
        for uid in finding.resource_uids
    )


def expired_warnings(risks: Iterable[AcceptedRisk], today: date) -> list[str]:
    """Return one warning per accepted risk that has expired on the given date."""
    return [
        f"{r.source}: exception #{r.position} ({r.check_id}) expired on "
        f"{r.expires.isoformat()}; not applied"
        for r in risks
        if not is_active(r, today)
    ]


def _unknown_value_warnings(findings: Iterable[Finding]) -> list[str]:
    findings = list(findings)
    statuses = Counter(f.status for f in findings if f.status.strip().upper() not in KNOWN_STATUSES)
    severities = Counter(
        f.severity for f in findings if severity_rank(f.severity) == UNKNOWN_SEVERITY_RANK
    )
    return [
        *(
            f"{n} finding(s) with unrecognized status {v!r} were kept"
            for v, n in sorted(statuses.items())
        ),
        *(
            f"{n} finding(s) with unrecognized severity {v!r} were kept and sorted first"
            for v, n in sorted(severities.items())
        ),
    ]


def triage(
    findings: Iterable[Finding],
    risks: Sequence[AcceptedRisk],
    today: date,
    *,
    statuses: Iterable[str] = DEFAULT_STATUSES,
    min_severity: str = DEFAULT_MIN_SEVERITY,
) -> TriageResult:
    """Filter findings, split off those covered by active accepted risks, and sort both.

    The first active accepted risk in file order that matches a finding wins.
    """
    selected = filter_findings(findings, statuses, min_severity)
    active = [r for r in risks if is_active(r, today)]
    attention: list[Finding] = []
    accepted: list[Suppressed] = []
    for finding in selected:
        risk = next((r for r in active if risk_matches(r, finding)), None)
        if risk is None:
            attention.append(finding)
        else:
            accepted.append(Suppressed(finding, risk))
    return TriageResult(
        attention=tuple(sort_findings(attention)),
        accepted=tuple(sorted(accepted, key=lambda s: sort_key(s.finding))),
        warnings=(*expired_warnings(risks, today), *_unknown_value_warnings(selected)),
    )
