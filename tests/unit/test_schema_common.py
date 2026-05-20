"""Tests for shared schema primitives."""

from __future__ import annotations

import pytest

from csfwctl.schema._common import DISPLAY_NAME_RE, SLUG_RE


@pytest.mark.parametrize(
    "slug",
    [
        "abc01-endpoints-windows",
        "windows-baseline",
        "corp-vpn",
        "abc",
        "a1",
        "x9-y0-z",
    ],
)
def test_slug_regex_accepts_valid(slug: str) -> None:
    assert SLUG_RE.match(slug)


@pytest.mark.parametrize(
    "slug",
    [
        "",
        "A",
        "abc--def",
        "-abc",
        "abc-",
        "abc_def",
        "ABC",
        "1abc",
        "abc.def",
    ],
)
def test_slug_regex_rejects_invalid(slug: str) -> None:
    assert SLUG_RE.match(slug) is None


@pytest.mark.parametrize(
    "name",
    [
        "ABC01-Endpoints-Windows",
        "Research-Lab-7-Windows",
        "Endpoints",
        "Ab",
    ],
)
def test_display_name_regex_accepts_valid(name: str) -> None:
    assert DISPLAY_NAME_RE.match(name)


@pytest.mark.parametrize(
    "name",
    [
        "abc",
        "abc-def",
        "ABC--DEF",
        "ABC_DEF",
        "ABC.DEF",
        "-ABC",
        "ABC-",
    ],
)
def test_display_name_regex_rejects_invalid(name: str) -> None:
    assert DISPLAY_NAME_RE.match(name) is None
