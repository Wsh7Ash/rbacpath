"""Shared fixtures: paths to the example exports."""

from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent
EXAMPLES = ROOT / "examples"


@pytest.fixture
def risky_export() -> str:
    return str(EXAMPLES / "export-risky.json")


@pytest.fixture
def clean_export() -> str:
    return str(EXAMPLES / "export-clean.json")
