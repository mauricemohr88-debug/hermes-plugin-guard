# Releasing Hermes Plugin Guard

GitHub Releases are the single release trigger. Publishing a GitHub Release whose tag matches the
package version starts `.github/workflows/publish.yml`, which checks and builds the wheel and
source distribution. The PyPI job remains safely skipped until the repository variable
`PYPI_PUBLISH` is deliberately set to `true`. Once enabled, publishing uses a short-lived OpenID
Connect identity; no PyPI API token is stored in GitHub.

## One-time trusted-publisher setup

Complete these settings before publishing the first PyPI release:

1. In the GitHub repository settings, create an environment named `pypi`. Restrict deployments to
   protected tags matching `v*` and add a required reviewer when the repository plan supports it.
2. In the PyPI account's publishing settings, add a pending GitHub publisher with these exact
   values:

   | Field | Value |
   | --- | --- |
   | PyPI project name | `hermes-plugin-guard` |
   | GitHub owner | `mauricemohr88-debug` |
   | GitHub repository | `hermes-plugin-guard` |
   | Workflow filename | `publish.yml` |
   | Environment | `pypi` |

A pending publisher can create the PyPI project on its first successful publication. If the
project already exists, configure the same publisher from that project's Publishing settings.
Only after the publisher and GitHub environment exist, create the repository Actions variable
`PYPI_PUBLISH` with the exact value `true`. An unset variable leaves the publish job skipped, so a
GitHub Release cannot fail merely because PyPI has not been configured yet.

The workflow's publish job requests only `id-token: write`; the build job has read-only repository
access. The publishing action also generates and uploads a PEP 740 attestation for each
distribution.

## Release checklist

1. Update the version in `pyproject.toml` and `src/hermes_plugin_guard/__init__.py`.
2. Move the relevant changelog entries from `Unreleased` into the dated release section.
3. Run the local release checks:

   ```bash
   python3 -m pip install -e ".[dev]" "twine>=6,<7"
   ruff check .
   ruff format --check .
   pytest
   python3 -m build
   python3 -m twine check dist/*
   ```

4. Merge the release commit and wait for CI to pass on the default branch.
5. Create and publish a GitHub Release using a matching `vMAJOR.MINOR.PATCH` tag. For package
   version `0.1.1`, the tag must be `v0.1.1`.
6. Confirm that the `Publish to PyPI` workflow completed successfully. When publishing is enabled,
   also confirm that the project page lists both the wheel and source distribution. Before then,
   the publish job should show as skipped.
7. Test the public package in a clean environment:

   ```bash
   pipx run hermes-plugin-guard --version
   ```

The workflow rejects mismatched release tags, `pyproject.toml` versions, and module versions. It
also reruns linting and tests, validates distribution metadata, and separates the unprivileged
build job from the OIDC-enabled publish job.

## Recovery

PyPI releases are immutable: a file or version cannot be replaced after publication. If
publication succeeds but the release is defective, fix it in a new patch version. If the workflow
fails before upload, correct the cause and rerun the failed job; do not create another release with
the same version unless no files reached PyPI.
