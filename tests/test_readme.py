"""The README sample report must be real CLI output, not hand-written."""

import re
from pathlib import Path

import pytest

from cspm_triage.cli import main

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
SAMPLE = ROOT / "docs" / "sample-triage-report.md"
SAMPLE_ARGS = [
    "triage",
    "tests/fixtures/sample_scan.ocsf.json",
    "--exceptions",
    "config/exceptions.example.toml",
    "--today",
    "2026-06-15",
    "--redact-account",
]
REGENERATE = (
    "regenerate it: cspm-triage " + " ".join(SAMPLE_ARGS) + " --output docs/sample-triage-report.md"
)
EXCERPT_RE = re.compile(
    r"<!-- excerpt:start -->\n```markdown\n(.*?)```\n<!-- excerpt:end -->", re.DOTALL
)


@pytest.fixture
def cli_output(capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> str:
    # Run from the repo root so paths in the report header match the documented command.
    # --exceptions is explicit, so a local config/exceptions.toml is never read.
    monkeypatch.chdir(ROOT)
    assert main(SAMPLE_ARGS) == 1
    return capsys.readouterr().out


def test_sample_report_matches_cli_output(cli_output: str) -> None:
    assert SAMPLE.read_text(encoding="utf-8") == cli_output, REGENERATE


def test_readme_excerpts_are_taken_from_the_sample() -> None:
    sample = SAMPLE.read_text(encoding="utf-8")
    excerpts = EXCERPT_RE.findall(README.read_text(encoding="utf-8"))
    assert excerpts, "no excerpts found in README.md"
    for excerpt in excerpts:
        assert excerpt in sample, f"README excerpt not found verbatim in {SAMPLE.name}"


def test_readme_documents_the_sample_command() -> None:
    readme = " ".join(README.read_text(encoding="utf-8").replace("\\\n", " ").split())
    assert "cspm-triage " + " ".join(SAMPLE_ARGS) in readme
    assert "(docs/sample-triage-report.md)" in readme


def test_sample_has_no_account_ids() -> None:
    assert re.search(r"(?<!\d)\d{12}(?!\d)", SAMPLE.read_text(encoding="utf-8")) is None
