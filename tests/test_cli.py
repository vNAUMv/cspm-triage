"""Tests for cspm_triage.cli, using the sanitized fixture and tmp_path. No real scans."""

import copy
import json
import re
from pathlib import Path
from typing import Any

import pytest

from cspm_triage import cli
from cspm_triage.cli import main

FIXTURE = Path(__file__).parent / "fixtures" / "sample_scan.ocsf.json"
RECORDS: list[dict[str, Any]] = json.loads(FIXTURE.read_text(encoding="utf-8"))
TODAY = "2026-06-15"
FAIL_CHECKS = (
    "iam_root_hardware_mfa_enabled",
    "iam_user_hardware_mfa_enabled",
    "iam_user_access_not_stale_to_bedrock",
    "iam_policy_attached_only_to_group_or_roles",
)
NO_EXCEPTIONS = "exceptions: none (config/exceptions.toml not found)"


@pytest.fixture(autouse=True)
def isolated_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Run every test in tmp_path so a real config/exceptions.toml is never picked up."""
    monkeypatch.chdir(tmp_path)


def write_scan(path: Path, records: list[dict[str, Any]]) -> Path:
    path.write_text(json.dumps(records), encoding="utf-8")
    return path


def edited(event_code: str, **changes: Any) -> list[dict[str, Any]]:  # noqa: ANN401
    """Fixture records with top-level fields of one finding changed."""
    records = copy.deepcopy(RECORDS)
    for record in records:
        if record["metadata"]["event_code"] == event_code:
            record.update(changes)
    return records


def with_new_finding() -> list[dict[str, Any]]:
    records = copy.deepcopy(RECORDS)
    extra = copy.deepcopy(next(r for r in records if r["status_code"] == "FAIL"))
    extra["finding_info"]["uid"] += "-2"
    return [*records, extra]


def write_exceptions(path: Path, checks: tuple[str, ...], expires: str = "2027-01-01") -> Path:
    entries = [
        f'[[exceptions]]\ncheck_id = "{check}"\nreason = "Accepted for testing"\n'
        f'owner = "security-team@example.com"\nexpires = {expires}\n'
        for check in checks
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(entries), encoding="utf-8")
    return path


def run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


# --- triage ---------------------------------------------------------------------------


def test_triage_to_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, err = run(capsys, "triage", str(FIXTURE), "--today", TODAY)
    assert code == 1
    assert out.startswith("# CSPM triage report")
    assert "## Needs attention (4)" in out
    assert err.strip() == (
        f"triage: 4 need attention, 0 accepted, 0 warning(s); {NO_EXCEPTIONS}; exit 1"
    )


def test_triage_to_file(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    output = tmp_path / "triage.md"
    code, out, err = run(capsys, "triage", str(FIXTURE), "--today", TODAY, "--output", str(output))
    assert code == 1
    assert out == ""
    assert "## Needs attention (4)" in output.read_text(encoding="utf-8")
    assert NO_EXCEPTIONS in err
    assert f"report: {output}" in err


def test_triage_default_exceptions_file_used(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    write_exceptions(tmp_path / "config" / "exceptions.toml", FAIL_CHECKS)
    code, out, err = run(capsys, "triage", str(FIXTURE), "--today", TODAY)
    assert code == 0
    assert "## Accepted risks (4)" in out
    assert "- Gate: **pass** (exit 0)" in out
    assert "exceptions: config/exceptions.toml (4 entries, default)" in err


def test_triage_explicit_exceptions_file(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    path = write_exceptions(tmp_path / "risks.toml", FAIL_CHECKS[:1])
    code, _, err = run(capsys, "triage", str(FIXTURE), "--today", TODAY, "--exceptions", str(path))
    assert code == 1
    assert f"exceptions: {path.as_posix()} (1 entries)" in err


def test_today_controls_expiry(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    write_exceptions(tmp_path / "config" / "exceptions.toml", FAIL_CHECKS, expires="2026-06-15")
    assert run(capsys, "triage", str(FIXTURE), "--today", "2026-06-15")[0] == 0
    code, out, _ = run(capsys, "triage", str(FIXTURE), "--today", "2026-06-16")
    assert code == 1
    assert "expired on 2026-06-15; not applied" in out


def test_status_and_min_severity_filters(capsys: pytest.CaptureFixture[str]) -> None:
    _, out, _ = run(
        capsys, "triage", str(FIXTURE), "--today", TODAY, "--status", "pass",
        "--min-severity", "CRITICAL",
    )  # fmt: skip
    assert "## Needs attention (1)" in out
    assert "iam_root_mfa_enabled" in out
    _, out, _ = run(capsys, "triage", str(FIXTURE), "--today", TODAY, "--status", "FAIL,MANUAL")
    assert "## Needs attention (6)" in out


# --- diff -------------------------------------------------------------------------------


def diff(capsys: pytest.CaptureFixture[str], current: Path, *extra: str) -> tuple[int, str, str]:
    return run(capsys, "diff", str(FIXTURE), str(current), "--today", TODAY, *extra)


def test_diff_identical_passes(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    code, out, err = diff(capsys, write_scan(tmp_path / "cur.json", RECORDS))
    assert code == 0
    assert "- Gate: **pass** (exit 0)" in out
    assert "## Persisting (4)" in out
    assert err.startswith("diff: 0 new, 4 persisting (0 severity increased)")
    assert NO_EXCEPTIONS in err


def test_diff_new_finding_fails(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    code, out, _ = diff(capsys, write_scan(tmp_path / "cur.json", with_new_finding()))
    assert code == 1
    assert "## New (1)" in out
    assert "1 new finding(s)" in out


def test_diff_resolved_only_passes(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    current = edited("iam_user_hardware_mfa_enabled", status_code="PASS")
    code, out, _ = diff(capsys, write_scan(tmp_path / "cur.json", current))
    assert code == 0
    assert "## Resolved (1)" in out


def test_diff_severity_increase_fails(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    current = edited("iam_user_hardware_mfa_enabled", severity="Critical")
    code, out, err = diff(capsys, write_scan(tmp_path / "cur.json", current))
    assert code == 1
    assert "## New" not in out
    assert "1 persisting finding(s) with increased severity" in out
    assert "(1 severity increased)" in err


def test_diff_severity_decrease_passes(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    current = edited("iam_user_hardware_mfa_enabled", severity="Medium")
    assert diff(capsys, write_scan(tmp_path / "cur.json", current))[0] == 0


def test_diff_expired_exception_fails(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    write_exceptions(tmp_path / "config" / "exceptions.toml", FAIL_CHECKS[:1], "2026-01-01")
    code, out, err = diff(capsys, write_scan(tmp_path / "cur.json", RECORDS))
    assert code == 1
    assert "## New" not in out
    assert "1 expired exception(s)" in out
    assert "1 expired exception(s); exceptions: config/exceptions.toml (1 entries, default)" in err


def test_diff_active_exception_passes(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    write_exceptions(tmp_path / "config" / "exceptions.toml", FAIL_CHECKS[:1])
    code, out, _ = diff(capsys, write_scan(tmp_path / "cur.json", RECORDS))
    assert code == 0
    assert "## Persisting (3)" in out


# --- errors (exit 2) ------------------------------------------------------------------------


def test_empty_scan_is_an_error(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    empty = write_scan(tmp_path / "empty.json", [])
    code, out, err = run(capsys, "triage", str(empty))
    assert (code, out) == (2, "")
    assert "error: scan has no findings; the scan probably failed" in err


@pytest.mark.parametrize(("side", "label"), [(0, "baseline scan"), (1, "current scan")])
def test_diff_empty_scan_is_an_error(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, side: int, label: str
) -> None:
    scans = [str(FIXTURE), str(FIXTURE)]
    scans[side] = str(write_scan(tmp_path / "empty.json", []))
    code, _, err = run(capsys, "diff", *scans)
    assert code == 2
    assert f"error: {label} has no findings" in err


def test_missing_explicit_exceptions_file(capsys: pytest.CaptureFixture[str]) -> None:
    code, _, err = run(capsys, "triage", str(FIXTURE), "--exceptions", "nope.toml")
    assert code == 2
    assert "error: exceptions file not found: nope.toml" in err


def test_invalid_exceptions_file(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    path = tmp_path / "bad.toml"
    path.write_text('[[exceptions]]\ncheck_id = "x"\n', encoding="utf-8")
    code, _, err = run(capsys, "triage", str(FIXTURE), "--exceptions", str(path))
    assert code == 2
    assert f"{path}: exception #1: missing required field(s)" in err


@pytest.mark.parametrize(
    ("content", "message"),
    [(None, "No such file"), ("{not json", "error: "), ('[{"status_code": "FAIL"}]', "finding #0")],
)
def test_bad_scan_input(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, content: str | None, message: str
) -> None:
    path = tmp_path / "scan.json"
    if content is not None:
        path.write_text(content, encoding="utf-8")
    code, out, err = run(capsys, "triage", str(path))
    assert (code, out) == (2, "")
    assert message in err


def test_missing_output_directory(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    output = tmp_path / "reports" / "triage.md"
    code, _, err = run(capsys, "triage", str(FIXTURE), "--output", str(output))
    assert code == 2
    assert "mkdir reports" in err


@pytest.mark.parametrize(
    "args",
    [
        ["--today", "15/06/2026"],
        ["--status", "FAILED"],
        ["--status", ","],
        ["--min-severity", "urgent"],
    ],
)
def test_bad_options_exit_2(capsys: pytest.CaptureFixture[str], args: list[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["triage", str(FIXTURE), *args])
    assert exc.value.code == 2


def test_help_documents_exit_codes(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["diff", "--help"])
    out = capsys.readouterr().out
    assert exc.value.code == 0
    assert "severity" in out and "increased" in out
    assert "expired exception" in out
    assert "empty scan" in out


def test_output_is_reproducible(capsys: pytest.CaptureFixture[str]) -> None:
    first = run(capsys, "triage", str(FIXTURE), "--today", TODAY)
    second = run(capsys, "triage", str(FIXTURE), "--today", TODAY)
    assert first == second


# --- --redact-account ----------------------------------------------------------------------

TWELVE_DIGITS = re.compile(r"(?<!\d)\d{12}(?!\d)")


def input_accounts(*paths: Path) -> set[str]:
    """Every standalone 12-digit number anywhere in the input files."""
    return {m for p in paths for m in TWELVE_DIGITS.findall(p.read_text(encoding="utf-8"))}


def two_account_scan(path: Path) -> Path:
    """Fixture plus a copy of each finding in a second account; one detail names a third."""
    records = copy.deepcopy(RECORDS)
    other = json.loads(json.dumps(RECORDS).replace("123456789012", "210987654321"))
    other[0]["status_detail"] = "Role trusts external account 999988887777."
    return write_scan(path, [*records, *other])


def test_triage_redact_account_removes_every_input_account(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    scan = two_account_scan(tmp_path / "prowler-output-123456789012.ocsf.json")
    accounts = input_accounts(scan)
    assert len(accounts) == 3
    code, out, _ = run(
        capsys, "triage", str(scan), "--today", TODAY, "--redact-account", "--status", "FAIL,MANUAL"
    )
    assert code == 1
    assert not any(account in out for account in accounts)
    assert TWELVE_DIGITS.search(out) is None
    assert "- Redaction: Account IDs redacted; other identifiers are not." in out
    assert "- Accounts: 2 (redacted)" in out
    assert "example-user" in out  # names stay: only account IDs are redacted


def test_diff_redact_account(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    current = write_scan(tmp_path / "cur-123456789012.json", with_new_finding())
    code, out, _ = diff(capsys, current, "--redact-account")
    assert code == 1
    assert not any(account in out for account in input_accounts(FIXTURE, current))
    assert "Account IDs redacted; other identifiers are not." in out


def test_no_redaction_by_default(capsys: pytest.CaptureFixture[str]) -> None:
    _, out, _ = run(capsys, "triage", str(FIXTURE), "--today", TODAY)
    assert "- Account: 123456789012" in out
    assert "Redaction" not in out


def test_redaction_leak_check_refuses_to_write(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cli, "render_triage", lambda *_: "leaked 123456789012\n")
    output = tmp_path / "triage.md"
    code, out, err = run(
        capsys, "triage", str(FIXTURE), "--redact-account", "--output", str(output)
    )
    assert (code, out) == (2, "")
    assert "redaction check failed" in err
    assert "123456789012" not in err
    assert not output.exists()


def test_help_says_redaction_is_account_ids_only(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        main(["triage", "--help"])
    out = " ".join(capsys.readouterr().out.split())
    assert "--redact-account" in out
    assert "Account IDs only" in out
    assert "are NOT removed" in out
    assert "anonym" not in out.lower()
