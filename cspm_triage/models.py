"""Data models for findings."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Finding:
    """One Prowler finding, reduced to the fields the tool uses.

    Source paths in the Prowler OCSF JSON are noted per field.
    """

    event_code: str  # metadata.event_code (Prowler check ID)
    status: str  # status_code: PASS / FAIL / MANUAL (not OCSF `status`, which is "New")
    severity: str  # severity, kept as free text so unknown values still parse
    title: str  # finding_info.title
    status_detail: str  # status_detail
    finding_uid: str  # finding_info.uid
    resource_uids: tuple[str, ...]  # resources[].uid
    region: str  # cloud.region
    remediation_desc: str  # remediation.desc
    remediation_references: tuple[str, ...]  # remediation.references[]
