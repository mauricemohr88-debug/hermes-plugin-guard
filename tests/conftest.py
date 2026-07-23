from __future__ import annotations

import shutil
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def safe_plugin() -> Path:
    return FIXTURES / "safe_plugin"


@pytest.fixture
def risky_plugin(tmp_path: Path) -> Path:
    """Copy the executable-looking fixture so tests can prove it stays inert."""

    destination = tmp_path / "risky_plugin"
    shutil.copytree(FIXTURES / "risky_plugin", destination)
    return destination


def make_clean_plugin(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "plugin.yaml").write_text(
        "\n".join(
            [
                "name: clean-fixture",
                "version: 1.0.0",
                "description: A minimal test plugin",
                "kind: standalone",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (root / "__init__.py").write_text(
        "def register(ctx):\n    return None\n",
        encoding="utf-8",
    )
    (root / "LICENSE").write_text("Fixture license\n", encoding="utf-8")
    (root / "SECURITY.md").write_text("Fixture policy\n", encoding="utf-8")
    tests = root / "tests"
    tests.mkdir()
    (tests / "test_fixture.py").write_text("def test_fixture():\n    pass\n", encoding="utf-8")
    return root
