from __future__ import annotations

from pathlib import Path

from hermes_plugin_guard.dependency_scan import inspect_dependencies


def test_requirements_find_remote_mutability_and_unbounded_packages(
    tmp_path: Path,
) -> None:
    (tmp_path / "requirements.txt").write_text(
        "\n".join(
            [
                "# ignored",
                "safe-package>=1.0,<2",
                "open-package>=3",
                "git+https://github.com/example/repo.git@main",
                "exact-package==4.2.0",
                "",
            ]
        ),
        encoding="utf-8",
    )

    findings = inspect_dependencies(tmp_path, tmp_path)

    assert [(item.rule_id, item.line) for item in findings] == [
        ("HPG203", 3),
        ("HPG202", 4),
    ]


def test_full_git_sha_and_local_dependencies_are_not_reported(tmp_path: Path) -> None:
    sha = "a" * 40
    (tmp_path / "requirements-dev.txt").write_text(
        "\n".join(
            [
                f"git+https://github.com/example/repo.git@{sha}",
                "-e ../local-package",
                "./vendored",
                "bounded~=1.4",
                "",
            ]
        ),
        encoding="utf-8",
    )

    assert inspect_dependencies(tmp_path, tmp_path) == []


def test_pyproject_main_optional_and_build_dependencies_are_checked(
    tmp_path: Path,
) -> None:
    (tmp_path / "pyproject.toml").write_text(
        "\n".join(
            [
                "[build-system]",
                'requires = ["setuptools>=70"]',
                'build-backend = "setuptools.build_meta"',
                "",
                "[project]",
                'name = "fixture"',
                'version = "1.0.0"',
                'dependencies = ["requests>=2,<3"]',
                "",
                "[project.optional-dependencies]",
                'dev = ["pytest>=8"]',
                "",
            ]
        ),
        encoding="utf-8",
    )

    findings = inspect_dependencies(tmp_path, tmp_path)

    assert [(item.rule_id, item.evidence) for item in findings] == [
        ("HPG203", "pytest>=8"),
        ("HPG203", "setuptools>=70"),
    ]
