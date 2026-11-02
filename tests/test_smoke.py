"""Placeholder test: verifies the package imports."""

import importlib


def test_package_imports() -> None:
    module = importlib.import_module("cspm_triage")
    assert module.__name__ == "cspm_triage"
