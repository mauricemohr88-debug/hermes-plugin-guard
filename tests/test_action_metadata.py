"""Keep external-consumer setup independent of caller dependency files."""

from pathlib import Path

import yaml


def test_composite_action_does_not_hash_dependencies_outside_workspace() -> None:
    metadata = yaml.safe_load(
        (Path(__file__).parents[1] / "action.yml").read_text(encoding="utf-8")
    )
    python_setup = metadata["runs"]["steps"][0]

    # setup-python hashes only workspace files; downloaded actions live elsewhere.
    assert python_setup["with"]["python-version"] == "3.11"
    assert "cache" not in python_setup["with"]
    assert "cache-dependency-path" not in python_setup["with"]
