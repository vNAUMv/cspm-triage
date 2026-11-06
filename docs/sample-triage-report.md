# CSPM triage report

- Scan: sample_scan.ocsf.json
- Account: &lt;account&gt;
- Redaction: Account IDs redacted; other identifiers are not.
- Date: 2026-06-15
- Filters: status FAIL; minimum severity low
- Exceptions: config/exceptions.example.toml (3 entries)
- Gate: **fail** (exit 1): 3 finding(s) need attention

## Summary

| Severity | Needs attention | Accepted |
|---|---|---|
| Critical | 1 | 0 |
| High | 0 | 1 |
| Medium | 1 | 0 |
| Low | 1 | 0 |
| **Total** | 3 | 1 |

## Needs attention (3)

### Critical · iam_root_hardware_mfa_enabled

- Resource: `mfa` (us-east-1)
- UID: `arn:aws:iam::<account>:mfa`
- Detail: Root account has a virtual MFA instead of a hardware MFA device enabled.
- Remediation: <https://hub.prowler.com/check/iam_root_hardware_mfa_enabled>

### Medium · iam_user_access_not_stale_to_bedrock

- Resource: `user/example-user` (us-east-1)
- UID: `arn:aws:iam::<account>:user/example-user`
- Detail: IAM User example-user has Bedrock permissions but has never used them.
- Remediation: <https://hub.prowler.com/check/iam_user_access_not_stale_to_bedrock>

### Low · iam_policy_attached_only_to_group_or_roles

- Resource: `user/example-user` (us-east-1)
- UID: `arn:aws:iam::<account>:user/example-user`
- Detail: User example-user has the policy ViewOnlyAccess attached.
- Remediation: <https://hub.prowler.com/check/iam_policy_attached_only_to_group_or_roles>

## Accepted risks (1)

| # | Check | Findings | Expires |
|---|---|---|---|
| #1 | iam_user_hardware_mfa_enabled | 1 | 2027-03-31 |

### #1 · iam_user_hardware_mfa_enabled

- Expires: 2027-03-31
- Owner: security-team@example.com
- Source: config/exceptions.example.toml #1
- Reason: Break-glass user; virtual MFA accepted until hardware keys arrive
- Covers (1):
  - `user/example-user` (us-east-1)
