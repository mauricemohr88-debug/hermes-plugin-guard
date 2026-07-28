"""Rule catalog for stable IDs, help text, and SARIF metadata."""

from __future__ import annotations

from .models import Rule, Severity


def _rule(
    rule_id: str,
    title: str,
    description: str,
    remediation: str,
    severity: Severity,
    category: str,
) -> Rule:
    return Rule(
        id=rule_id,
        title=title,
        description=description,
        remediation=remediation,
        default_severity=severity,
        category=category,
    )


RULES: dict[str, Rule] = {
    "HPG001": _rule(
        "HPG001",
        "Plugin declaration missing",
        (
            "Hermes directory plugins use plugin.yaml; pip-distributed plugins use the "
            "hermes_agent.plugins entry-point group."
        ),
        (
            "Add plugin.yaml to a directory plugin or declare "
            '[project.entry-points."hermes_agent.plugins"] in pyproject.toml.'
        ),
        Severity.HIGH,
        "manifest",
    ),
    "HPG002": _rule(
        "HPG002",
        "Plugin manifest is invalid",
        "An unreadable or non-mapping manifest cannot be interpreted safely.",
        "Fix the YAML syntax and keep the root value as a mapping.",
        Severity.HIGH,
        "manifest",
    ),
    "HPG003": _rule(
        "HPG003",
        "Required plugin metadata missing",
        "Name, version, and description make plugins identifiable and reviewable.",
        "Add the missing metadata to plugin.yaml or the pyproject.toml project table.",
        Severity.MEDIUM,
        "manifest",
    ),
    "HPG004": _rule(
        "HPG004",
        "Unknown plugin kind",
        "Unknown plugin kinds are coerced by Hermes and may use the wrong loader.",
        "Use standalone, backend, exclusive, platform, or model-provider.",
        Severity.MEDIUM,
        "manifest",
    ),
    "HPG005": _rule(
        "HPG005",
        "Plugin entry point missing",
        "Directory plugins need __init__.py; dashboard plugins need their declared bundle.",
        "Add the missing entry file and expose the loader expected by the plugin kind.",
        Severity.HIGH,
        "manifest",
    ),
    "HPG006": _rule(
        "HPG006",
        "Hook declaration mismatch",
        "Literal hook registrations should match the hooks declared by the manifest.",
        "Update plugin.yaml or the ctx.register_hook call so they agree.",
        Severity.MEDIUM,
        "manifest",
    ),
    "HPG101": _rule(
        "HPG101",
        "Dynamic code execution",
        (
            "eval, exec, compile, and direct __import__ calls can execute or obscure "
            "content that static review cannot fully bound."
        ),
        "Use normal imports, a parser, or a narrow allow-listed dispatcher.",
        Severity.HIGH,
        "python",
    ),
    "HPG102": _rule(
        "HPG102",
        "Unsafe deserialization",
        "pickle and unsafe YAML loaders can execute attacker-controlled code.",
        "Use JSON, yaml.safe_load, or an explicitly safe loader.",
        Severity.HIGH,
        "python",
    ),
    "HPG103": _rule(
        "HPG103",
        "Direct process execution",
        "Direct process APIs bypass Hermes' terminal approval and output-safety pipeline.",
        "Use ctx.dispatch_tool('terminal', ...) or strictly constrain arguments and shell=False.",
        Severity.HIGH,
        "python",
    ),
    "HPG104": _rule(
        "HPG104",
        "Sensitive path reference",
        "The plugin references a path commonly containing credentials or private keys.",
        "Remove the access or document and constrain it to the minimum required file.",
        Severity.HIGH,
        "python",
    ),
    "HPG105": _rule(
        "HPG105",
        "Unrestricted network listener",
        "Binding to all interfaces can expose an unauthenticated plugin service.",
        "Bind to loopback by default and require explicit authentication for remote use.",
        Severity.HIGH,
        "python",
    ),
    "HPG106": _rule(
        "HPG106",
        "Network capability",
        "The plugin imports a networking client or socket module.",
        "Review destinations, TLS verification, timeouts, and data sent off-device.",
        Severity.INFO,
        "python",
    ),
    "HPG107": _rule(
        "HPG107",
        "Undeclared secret environment access",
        (
            "A secret-like environment variable is read but not declared in requires_env "
            "or optional_env."
        ),
        ("Declare it in plugin.yaml so users see the credential requirement before enablement."),
        Severity.MEDIUM,
        "python",
    ),
    "HPG108": _rule(
        "HPG108",
        "Destructive filesystem operation",
        "Deletion APIs can remove user or workspace data when paths are not constrained.",
        "Constrain targets to a plugin-owned directory and add refusal checks.",
        Severity.MEDIUM,
        "python",
    ),
    "HPG109": _rule(
        "HPG109",
        "TLS verification disabled",
        "Disabling certificate verification permits machine-in-the-middle attacks.",
        "Keep TLS verification enabled or trust a narrowly scoped custom CA.",
        Severity.HIGH,
        "python",
    ),
    "HPG110": _rule(
        "HPG110",
        "Privileged plugin surface",
        "Tool overrides, pre-auth gateway hooks, and message injection can alter core control flow.",
        "Remove the privileged option or document why it is required and gate it explicitly.",
        Severity.HIGH,
        "python",
    ),
    "HPG111": _rule(
        "HPG111",
        "Load-time side effect",
        "Process, network, or destructive calls during import/register run when a plugin is enabled.",
        "Move the action behind an explicit tool or user-triggered command.",
        Severity.HIGH,
        "python",
    ),
    "HPG112": _rule(
        "HPG112",
        "Outbound network egress",
        "A concrete outbound connection or request can send plugin or user data off-device.",
        (
            "Document and constrain destinations, send only required data, use encrypted "
            "transport, and make network access visible to users."
        ),
        Severity.MEDIUM,
        "python",
    ),
    "HPG201": _rule(
        "HPG201",
        "Secret material committed",
        "Private keys, tokens, and credential files must not ship with a plugin.",
        "Revoke the credential, remove it from history, and use requires_env instead.",
        Severity.CRITICAL,
        "secrets",
    ),
    "HPG202": _rule(
        "HPG202",
        "Unpinned remote dependency",
        "Mutable Git or URL dependencies can change without a plugin code review.",
        "Pin Git dependencies to a full commit SHA and verify the source.",
        Severity.HIGH,
        "dependencies",
    ),
    "HPG203": _rule(
        "HPG203",
        "Dependency has no upper bound",
        "An open-ended dependency range increases supply-chain and compatibility risk.",
        "Add a compatible upper bound, for example >=1.2,<2.",
        Severity.LOW,
        "dependencies",
    ),
    "HPG204": _rule(
        "HPG204",
        "Remote installer executes without verification",
        (
            "Downloading a mutable script and piping it directly to a shell executes code "
            "that was not part of the reviewed plugin."
        ),
        (
            "Pin a versioned artifact, verify its checksum or signature, and execute it only "
            "after verification."
        ),
        Severity.HIGH,
        "dependencies",
    ),
    "HPG301": _rule(
        "HPG301",
        "Open-source license missing",
        "A public repository without a license is not safely reusable or contributable.",
        "Add an OSI-approved LICENSE file.",
        Severity.MEDIUM,
        "project",
    ),
    "HPG302": _rule(
        "HPG302",
        "Security policy missing",
        "Maintainers need a private path for reporting plugin vulnerabilities.",
        "Add SECURITY.md with supported versions and a reporting channel.",
        Severity.LOW,
        "project",
    ),
    "HPG303": _rule(
        "HPG303",
        "Tests missing",
        "Plugins with full agent privileges should have repeatable safety tests.",
        "Add automated tests covering registration and high-risk paths.",
        Severity.LOW,
        "project",
    ),
}


def get_rule(rule_id: str) -> Rule:
    return RULES[rule_id]
