"""Meta-test: only ``csfwctl/falcon/`` may import ``falconpy``.

CLAUDE.md hard rule: every CrowdStrike API call goes through
``csfwctl/falcon/client.py``. This test walks the package source and
asserts no other module imports the third-party library, so the rule
is enforceable at CI time rather than only at review time.
"""

from __future__ import annotations

import ast
from pathlib import Path

PKG_ROOT = Path(__file__).resolve().parents[2] / "csfwctl"
ALLOWED_DIR = PKG_ROOT / "falcon"


def _module_imports_falconpy(path: Path) -> bool:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "falconpy" or alias.name.startswith("falconpy."):
                    return True
        elif isinstance(node, ast.ImportFrom):
            if node.module and (node.module == "falconpy" or node.module.startswith("falconpy.")):
                return True
    return False


def test_only_falcon_subpackage_imports_falconpy() -> None:
    offenders: list[Path] = []
    for path in PKG_ROOT.rglob("*.py"):
        if ALLOWED_DIR in path.parents or path == ALLOWED_DIR:
            continue
        if _module_imports_falconpy(path):
            offenders.append(path.relative_to(PKG_ROOT))
    assert not offenders, (
        "These modules import falconpy directly; route them through "
        f"csfwctl.falcon.client instead: {offenders}"
    )
