"""Build a sanitized test fixture from a real Prowler OCSF scan.

Usage:
    python3 -I scripts/sanitize_fixture.py REAL_SCAN.ocsf.json OUTPUT.ocsf.json [--pick 3,17,42]

The input is a real Prowler scan (a JSON array of OCSF findings). By default the
script keeps the first finding for each (status_code, severity) pair; --pick takes
0-based finding indices instead. The selected findings are written with
identifying values replaced:

- AWS account IDs (cloud.account.uid and account fields of ARNs)
  -> 123456789012, 123456789013, ...
- IAM user, role, group and policy names from the account's own IAM ARNs
  -> example-user-1, example-role-1, ... (AWS service-linked roles and
  AWS-managed policies are left unchanged)
- UUIDs, EC2-style resource IDs (sg-, vpc-, subnet-, ...), email addresses
  and IPv4 addresses (0.0.0.0 is kept) -> fake values
- resources[].data is emptied and unmapped.compliance is dropped

Real values are read from the input only; none are stored in this script.
Replacement is applied to every string, including dictionary keys, so free-text
fields such as message and status_detail are covered. The script refuses to
write output if an original value is still present, if a 12-digit number other
than a fake account ID remains, or if it finds an AWS access key ID. Error
messages never print the values themselves.

The input is real scan output: keep it outside the repository and never commit
it. Review the output by hand before committing it.
"""

import argparse
import copy
import json
import re
import sys
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

FAKE_ACCOUNT_START = 123456789012
FAKE_EMAIL_DOMAIN = "example.com"
FAKE_IP_PREFIX = "192.0.2."  # TEST-NET-1, reserved for documentation (RFC 5737)
STATUS_ORDER = ("FAIL", "PASS", "MANUAL")
SEVERITY_ORDER = ("Critical", "High", "Medium", "Low")
SERVICE_ROLE_PREFIX = "aws-service-role/"

ARN_ACCOUNT_RE = re.compile(r"arn:aws[a-z-]*:[a-z0-9-]*:[a-z0-9-]*:(\d{12}):")
IAM_ARN_RE = re.compile(r"arn:aws[a-z-]*:iam::\d{12}:(user|role|group|policy)/([\w+=,.@/-]+)")
UUID_RE = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
AWS_ID_RE = re.compile(r"\b(sg|vpc|subnet|eni|igw|rtb|acl|nat|ami|vol|snap|i)-[0-9a-f]{8,17}\b")
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
ACCESS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
TWELVE_DIGITS_RE = re.compile(r"\b\d{12}\b")
WORD_EDGE_BEFORE = r"(?<![A-Za-z0-9_])"
WORD_EDGE_AFTER = r"(?![A-Za-z0-9_])"


class SanitizeError(ValueError):
    """Raised when the input cannot be sanitized safely."""


def iter_strings(obj: object) -> Iterator[str]:
    """Yield every string in a JSON value, including dictionary keys."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            yield str(key)
            yield from iter_strings(value)
    elif isinstance(obj, list):
        for item in obj:
            yield from iter_strings(item)
    elif isinstance(obj, str):
        yield obj


def collect_account_ids(records: list[Any]) -> list[str]:
    """Return the account IDs found in a scan, in first-seen order."""
    found: dict[str, None] = {}
    for record in records:
        uid = record.get("cloud", {}).get("account", {}).get("uid")
        if isinstance(uid, str) and re.fullmatch(r"\d{12}", uid):
            found[uid] = None
    for text in iter_strings(records):
        for match in ARN_ACCOUNT_RE.finditer(text):
            found[match.group(1)] = None
    return list(found)


def collect_iam_names(records: list[Any]) -> dict[str, str]:
    """Map customer IAM principal and policy names in the scan to fake names."""
    mapping: dict[str, str] = {}
    counts: dict[str, int] = {}
    for text in iter_strings(records):
        for match in IAM_ARN_RE.finditer(text):
            kind, path = match.group(1), match.group(2)
            if kind == "role" and path.startswith(SERVICE_ROLE_PREFIX):
                continue
            name = path.rstrip("/.,").split("/")[-1]
            if name and name not in mapping:
                counts[kind] = counts.get(kind, 0) + 1
                mapping[name] = f"example-{kind}-{counts[kind]}"
    return mapping


@dataclass
class Sanitizer:
    """Replaces identifying values in strings, keeping replacements consistent."""

    fixed: dict[str, str]
    generated: dict[str, dict[str, str]] = field(default_factory=dict)
    _pattern: re.Pattern[str] | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.fixed:
            alternatives = "|".join(
                re.escape(value) for value in sorted(self.fixed, key=len, reverse=True)
            )
            self._pattern = re.compile(f"{WORD_EDGE_BEFORE}(?:{alternatives}){WORD_EDGE_AFTER}")

    @classmethod
    def from_scan(cls, records: list[Any]) -> "Sanitizer":
        """Build a sanitizer from the account IDs and IAM names found in a scan."""
        fixed = {
            account: str(FAKE_ACCOUNT_START + index)
            for index, account in enumerate(collect_account_ids(records))
        }
        fixed.update(collect_iam_names(records))
        return cls(fixed)

    def fake_accounts(self) -> set[str]:
        """Return the fake account IDs this sanitizer writes."""
        return {fake for fake in self.fixed.values() if fake.isdigit()}

    def _fake(self, kind: str, original: str, fake: str) -> str:
        table = self.generated.setdefault(kind, {})
        return table.setdefault(original, fake)

    def _next(self, kind: str) -> int:
        return len(self.generated.get(kind, {})) + 1

    def _uuid(self, match: re.Match[str]) -> str:
        # The "ffff" keeps the last group from being a 12-digit, account-like number.
        fake = f"00000000-0000-4000-8000-ffff{self._next('uuid'):08d}"
        return self._fake("uuid", match.group(0), fake)

    def _aws_id(self, match: re.Match[str]) -> str:
        prefix = match.group(1)
        return self._fake(prefix, match.group(0), f"{prefix}-{self._next(prefix):017x}")

    def _email(self, match: re.Match[str]) -> str:
        fake = f"user{self._next('email')}@{FAKE_EMAIL_DOMAIN}"
        return self._fake("email", match.group(0), fake)

    def _ip(self, match: re.Match[str]) -> str:
        ip = match.group(0)
        octets = [int(part) for part in ip.split(".")]
        # Keep the unspecified address (as in 0.0.0.0/0 rules) and non-IP dotted numbers.
        if all(o == 0 for o in octets) or any(o > 255 for o in octets):
            return ip
        return self._fake("ip", ip, f"{FAKE_IP_PREFIX}{(self._next('ip') - 1) % 254 + 1}")

    def text(self, value: str) -> str:
        """Return a string with all identifying values replaced."""
        if ACCESS_KEY_RE.search(value):
            raise SanitizeError("found an AWS access key ID; refusing to continue")
        if self._pattern is not None:
            value = self._pattern.sub(lambda m: self.fixed[m.group(0)], value)
        value = UUID_RE.sub(self._uuid, value)
        value = AWS_ID_RE.sub(self._aws_id, value)
        value = EMAIL_RE.sub(self._email, value)
        return IPV4_RE.sub(self._ip, value)

    def value(self, obj: object) -> object:
        """Return a copy of a JSON value with every string (and key) sanitized."""
        if isinstance(obj, dict):
            return {self.text(str(k)): self.value(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.value(item) for item in obj]
        if isinstance(obj, str):
            return self.text(obj)
        return obj

    def check_no_leaks(self, text: str) -> None:
        """Raise SanitizeError if any original value or unknown account ID remains."""
        leaked = 0 if self._pattern is None else len(self._pattern.findall(text))
        leaked += sum(
            1 for table in self.generated.values() for original in table if original in text
        )
        if leaked:
            raise SanitizeError(f"{leaked} original value(s) still present; refusing to write")
        if set(TWELVE_DIGITS_RE.findall(text)) - self.fake_accounts():
            raise SanitizeError("a 12-digit number that is not a fake account ID remains")


def _rank(value: object, order: tuple[str, ...]) -> int:
    return order.index(value) if value in order else len(order)


def select_findings(records: list[Any], pick: list[int] | None = None) -> list[Any]:
    """Pick findings by index, or the first one per (status_code, severity) pair."""
    if pick is not None:
        if any(not 0 <= index < len(records) for index in pick):
            raise SanitizeError(f"--pick indices must be between 0 and {len(records) - 1}")
        return [records[index] for index in pick]
    firsts: dict[tuple[str, str], Any] = {}
    for record in records:
        key = (str(record.get("status_code")), str(record.get("severity")))
        firsts.setdefault(key, record)
    ordered = sorted(
        firsts, key=lambda k: (_rank(k[0], STATUS_ORDER), _rank(k[1], SEVERITY_ORDER), k)
    )
    return [firsts[key] for key in ordered]


def strip_record(record: dict[str, Any]) -> dict[str, Any]:
    """Return a copy without raw resource data and compliance mappings."""
    stripped = copy.deepcopy(record)
    for resource in stripped.get("resources", []):
        if isinstance(resource, dict):
            resource["data"] = {"details": "", "metadata": {}}
    unmapped = stripped.get("unmapped")
    if isinstance(unmapped, dict):
        unmapped.pop("compliance", None)
    return stripped


def sanitize_scan(records: object, pick: list[int] | None = None) -> tuple[str, int]:
    """Return the sanitized fixture JSON text and the number of findings in it."""
    if not isinstance(records, list) or not all(isinstance(r, dict) for r in records):
        raise SanitizeError("input must be a JSON array of finding objects")
    sanitizer = Sanitizer.from_scan(records)
    selected = [strip_record(record) for record in select_findings(records, pick)]
    text = json.dumps(sanitizer.value(selected), indent=2, ensure_ascii=False) + "\n"
    sanitizer.check_no_leaks(text)
    return text, len(selected)


def parse_pick(value: str) -> list[int]:
    """Parse a comma-separated list of finding indices."""
    try:
        return [int(part) for part in value.split(",") if part.strip()]
    except ValueError as exc:
        raise argparse.ArgumentTypeError("--pick must be comma-separated integers") from exc


def main(argv: list[str] | None = None) -> int:
    """Command-line entry point; returns the process exit code."""
    parser = argparse.ArgumentParser(description="Build a sanitized Prowler OCSF fixture.")
    parser.add_argument("input", type=Path, help="real Prowler OCSF JSON scan (never commit it)")
    parser.add_argument("output", type=Path, help="where to write the sanitized fixture")
    parser.add_argument("--pick", type=parse_pick, help="comma-separated 0-based indices")
    args = parser.parse_args(argv)
    try:
        records = json.loads(args.input.read_text(encoding="utf-8"))
        text, count = sanitize_scan(records, args.pick)
    except (OSError, json.JSONDecodeError, SanitizeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    args.output.write_text(text, encoding="utf-8")
    print(f"wrote {count} sanitized findings to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
