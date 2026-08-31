# I turned a Hermes plugin scanner into a Hermes plugin. It still cannot be an admission gate.

After I released the first version of Hermes Plugin Guard, Teknium asked a fair
question in a reply on X:

> Have you considered re-implementing this as a plugin? Then it can hard enforce the scans.

I tried it.

Hermes Plugin Guard v0.2.0 now loads as a native Hermes v0.20 directory plugin.
It adds operator commands, a narrow review tool, and a stricter scan path for an
installed plugin that is still disabled.

The interesting result was not that the scanner worked inside Hermes. It was
that a third-party plugin still cannot honestly claim to be a hard admission
gate.

That is not a scanner problem. It is an authority problem.

## Why scan a plugin without running it?

A Hermes plugin is Python code running with the permissions of the Hermes
process. It can register tools, hooks, middleware, schedulers, memory providers,
or other runtime behavior. Installing code and importing it just to decide
whether it looks safe would defeat the point of a pre-enable review.

Hermes Plugin Guard therefore reads target files as data. It parses manifests,
Python syntax trees, dependency declarations, and likely secret material without
importing or executing the target plugin.

The standalone command remains simple:

```bash
pipx install hermes-plugin-guard
hpg scan /path/to/a/plugin --fail-on high
```

The scanner reports stable rule IDs rather than claiming that a finding proves
malice. It can flag risky execution primitives, load-time work, sensitive-path
access, concrete network calls, remote installers, mutable dependencies, likely
credentials, and declaration drift. It can also emit JSON, SARIF, and GitHub
annotations.

Static analysis has obvious limits. Dynamically assembled names, behavior in
native extensions, dependency internals, and runtime-only paths can escape it.
No findings is not the same as safe.

## What changed in v0.2.0

The same repository can now be installed as a native Hermes plugin while still
remaining useful as a standalone CLI:

```bash
hermes plugins install mauricemohr88-debug/hermes-plugin-guard/src --no-enable
hermes plugins enable hermes-plugin-guard --no-allow-tool-override
```

Compatibility update: Hermes v0.20.5 added a host-owned install scanner. The repository contains
intentionally adversarial fixtures for testing this scanner, so current releases install the slim
runtime tree through the `/src` suffix shown above. This keeps the original no-duplication design:
the native shim and packaged CLI still use the same implementation. Because Hermes v0.20.5 and
v0.20.6 do not retain Git metadata for subdirectory installs, first run
`hermes plugins disable hermes-plugin-guard`, then reinstall with
`hermes plugins install mauricemohr88-debug/hermes-plugin-guard/src --force --no-enable` and review
before enabling it again. `--no-enable` alone does not disable an already enabled installation.

Operators receive three commands:

```bash
hermes plugin-guard rules
hermes plugin-guard scan /path/to/a/plugin --fail-on high
hermes plugin-guard installed plugin-name --fail-on high
```

Hermes also receives one read-only model tool,
`plugin_guard_review_candidate`. That tool deliberately accepts much less than
the general CLI:

- only one exact installed candidate below `HERMES_HOME/plugins`;
- only while the candidate is disabled;
- no arbitrary path, rule exclusion, output file, or threshold override;
- one resource-bounded worker and one concurrent review;
- strict limits on files, bytes, depth, lines, findings, and output size;
- rejection of symlinks, special files, executable content, unsupported
  archives, and case or Unicode path collisions;
- failure when analysis is incomplete or the candidate changes during review.

The model does not receive filenames, source, finding messages, evidence,
dependency strings, secrets, absolute paths, or internal tree digests. It gets a
bounded projection: rule ID, severity, an opaque location ID, a bounded line
number, and counts.

That privacy boundary matters because a model-tool response becomes part of the
Hermes conversation and may be sent to the configured model provider.

## The enforcement gap

The native review path works. The admission gate does not exist.

Hermes v0.20 does not expose a core-owned third-party lifecycle hook that runs
fail-closed across all of these operations:

- installation;
- staged update;
- enablement;
- load and reload;
- activation paths outside the general `plugins.enabled` list.

Memory providers, cron schedulers, and model providers can follow different
activation paths. The review tool rejects those candidates instead of
pretending that they are safely disabled.

A security plugin also cannot make itself impossible to bypass. The operator can
enable another plugin manually, use another Hermes path, or stop loading the
guard. A before-and-after digest can detect endpoint drift during one review,
but it is not an atomic filesystem snapshot or an OS sandbox.

So v0.2.0 says exactly what it is: a review aid. The activation decision remains
with the operator.

## What hard enforcement would require

Real admission control belongs in the component that owns plugin state. Hermes
core would need one policy decision that covers every supported plugin surface
and runs before code becomes active. That decision would need to be fail-closed,
versioned, testable, and shared by the CLI, installer, updater, and loader.

I added the implementation evidence to the
[existing Hermes plugin-interface proposal](https://github.com/NousResearch/hermes-agent/issues/64182)
rather than opening a duplicate issue.

The point is not that Hermes is uniquely broken. The same architectural rule
applies to extension systems generally: a third-party extension can provide
analysis, but only the host can provide universal admission authority.

## Verification and an invitation

The v0.2.0 release passed 162 tests across Python 3.11, 3.12, and 3.13, plus Ruff,
CodeQL, wheel and source builds, and a loader test against Hermes tag
`v2026.8.3` / v0.20.0. The v0.2.1 compatibility patch additionally checks the
runtime-only install tree against the host scanners from Hermes v0.20.5 and
v0.20.6. Those checks establish what was tested. They do not turn a heuristic
scanner into a malware detector or a security guarantee.

If you maintain or use a Hermes plugin, the most useful next result is one real
scan:

```bash
pipx install hermes-plugin-guard
hpg scan /path/to/your/plugin --fail-on none
```

If a rule is useful, noisy, or misses a minimal reproducible pattern, report the
rule ID in the
[beta-test issue](https://github.com/mauricemohr88-debug/hermes-plugin-guard/issues/2).
Do not upload private source, credentials, or unsanitized paths.

- [Code](https://github.com/mauricemohr88-debug/hermes-plugin-guard)
- [PyPI](https://pypi.org/project/hermes-plugin-guard/)
- [v0.2.0 release](https://github.com/mauricemohr88-debug/hermes-plugin-guard/releases/tag/v0.2.0)
