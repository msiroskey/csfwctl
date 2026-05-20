"""Shared pytest fixtures for csfwctl tests."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

FIXTURES_ROOT = Path(__file__).parent / "fixtures" / "config_repos"


@pytest.fixture
def minimal_repo_path() -> Path:
    """Filesystem path to the ``minimal`` fixture config repo."""
    return FIXTURES_ROOT / "minimal"


@pytest.fixture
def realistic_repo_path() -> Path:
    """Filesystem path to the ``realistic`` fixture config repo."""
    return FIXTURES_ROOT / "realistic"


@pytest.fixture
def minimal_repo_copy(tmp_path: Path) -> Path:
    """Writable copy of the minimal fixture, suitable for mutation tests."""
    dest = tmp_path / "minimal"
    shutil.copytree(FIXTURES_ROOT / "minimal", dest)
    return dest


@pytest.fixture
def realistic_repo_copy(tmp_path: Path) -> Path:
    """Writable copy of the realistic fixture."""
    dest = tmp_path / "realistic"
    shutil.copytree(FIXTURES_ROOT / "realistic", dest)
    return dest
