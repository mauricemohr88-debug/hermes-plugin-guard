"""AST-based capability and risk checks for Python plugin code."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

from .catalog import get_rule
from .models import Finding, Severity

NETWORK_MODULES = {
    "aiohttp",
    "ftplib",
    "grpc",
    "http.client",
    "httpx",
    "requests",
    "socket",
    "urllib.request",
    "websockets",
}
SENSITIVE_PATH_PARTS = {
    "/.aws/",
    "/.config/gcloud/",
    "/.docker/config.json",
    "/.gnupg/",
    "/.kube/config",
    "/.netrc",
    "/.ssh/",
    "/auth.json",
    "/credentials.json",
    "/id_rsa",
    "/id_ed25519",
}
SECRET_NAME_RE = re.compile(
    r"(?:API[_-]?KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|PRIVATE[_-]?KEY)",
    re.IGNORECASE,
)
STANDARD_ENV = {
    "CI",
    "HOME",
    "HERMES_HOME",
    "LANG",
    "LOGNAME",
    "PATH",
    "PWD",
    "SHELL",
    "TEMP",
    "TMP",
    "TMPDIR",
    "USER",
}


@dataclass(slots=True)
class PythonInspection:
    findings: list[Finding]
    literal_hooks: dict[str, tuple[str, int]]


class _Analyzer(ast.NodeVisitor):
    def __init__(self, relative_path: str, declared_env: set[str]) -> None:
        self.relative_path = relative_path
        self.declared_env = declared_env
        self.findings: list[Finding] = []
        self.literal_hooks: dict[str, tuple[str, int]] = {}
        self.aliases: dict[str, str] = {}
        self._network_reported: set[str] = set()
        self._function_stack: list[str] = []

    def add(
        self,
        rule_id: str,
        node: ast.AST,
        message: str,
        *,
        severity: Severity | None = None,
        evidence: str | None = None,
    ) -> None:
        rule = get_rule(rule_id)
        self.findings.append(
            Finding(
                rule_id=rule_id,
                severity=severity or rule.default_severity,
                message=message,
                path=self.relative_path,
                line=getattr(node, "lineno", 1),
                column=getattr(node, "col_offset", 0) + 1,
                evidence=evidence,
            )
        )

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            local = alias.asname or alias.name.split(".")[0]
            self.aliases[local] = alias.name
            self._check_network_module(alias.name, node)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            local = alias.asname or alias.name
            self.aliases[local] = f"{module}.{alias.name}".strip(".")
        self._check_network_module(module, node)
        self.generic_visit(node)

    def _check_network_module(self, module: str, node: ast.AST) -> None:
        match = next(
            (
                candidate
                for candidate in NETWORK_MODULES
                if module == candidate or module.startswith(candidate + ".")
            ),
            None,
        )
        if match and match not in self._network_reported:
            self._network_reported.add(match)
            self.add(
                "HPG106",
                node,
                f"Plugin imports network-capable module {match!r}; review outbound data flow.",
                evidence=match,
            )

    def visit_Call(self, node: ast.Call) -> None:
        name = self._qualified_name(node.func)

        if name in {
            "__import__",
            "builtins.__import__",
            "builtins.compile",
            "builtins.eval",
            "builtins.exec",
            "compile",
            "eval",
            "exec",
            "runpy.run_module",
            "runpy.run_path",
        }:
            self.add("HPG101", node, f"Dynamic execution via {name}().", evidence=name)

        if name in {
            "cloudpickle.load",
            "cloudpickle.loads",
            "dill.load",
            "dill.loads",
            "joblib.load",
            "marshal.load",
            "marshal.loads",
            "pickle.load",
            "pickle.loads",
        }:
            self.add("HPG102", node, f"Unsafe deserialization via {name}().", evidence=name)
        elif name == "torch.load" and not self._keyword_is_true(node, "weights_only"):
            self.add(
                "HPG102",
                node,
                "torch.load() is used without weights_only=True.",
                evidence=name,
            )
        elif name == "numpy.load" and self._keyword_is_true(node, "allow_pickle"):
            self.add(
                "HPG102",
                node,
                "numpy.load() enables pickle deserialization.",
                evidence=name,
            )
        elif name in {"yaml.load", "ruamel.yaml.load"} and not self._uses_safe_yaml_loader(node):
            self.add(
                "HPG102",
                node,
                f"{name}() is used without an explicitly safe loader.",
                evidence=name,
            )

        if self._is_shell_call(name):
            shell_true = any(
                keyword.arg == "shell"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is True
                for keyword in node.keywords
            )
            severity = Severity.CRITICAL if shell_true else Severity.HIGH
            suffix = " with shell=True" if shell_true else ""
            self.add(
                "HPG103",
                node,
                f"Operating-system command execution via {name}(){suffix}.",
                severity=severity,
                evidence=name,
            )
            self._flag_load_time_side_effect(node, name)

        if self._is_destructive_call(name):
            self.add(
                "HPG108",
                node,
                f"Destructive filesystem operation via {name}(); verify path confinement.",
                evidence=name,
            )
            self._flag_load_time_side_effect(node, name)

        if self._tls_verification_disabled(name, node):
            self.add(
                "HPG109",
                node,
                "TLS certificate verification is disabled.",
                evidence=name or "verify=False",
            )

        if self._is_unrestricted_listener(name, node):
            self.add(
                "HPG105",
                node,
                "Network service appears to bind to all interfaces.",
                evidence=name,
            )

        if self._is_network_call(name):
            self._flag_load_time_side_effect(node, name)

        override = self._register_tool_override(name, node)
        if override is not False and override is not None:
            tool_name = (
                self._string_value(node.args[0])
                if node.args
                else self._keyword_string(node, "name")
            ) or "<dynamic>"
            severity = Severity.CRITICAL if override is True else Severity.HIGH
            verb = "overrides" if override is True else "may dynamically override"
            self.add(
                "HPG110",
                node,
                f"Plugin {verb} registered tool {tool_name!r}.",
                severity=severity,
                evidence=tool_name,
            )

        if name.endswith(".inject_message"):
            self.add(
                "HPG110",
                node,
                "Plugin can inject a message and start or interrupt an agent turn.",
                evidence=name,
            )

        env_name = self._environment_read(name, node)
        if (
            env_name
            and env_name not in self.declared_env
            and env_name not in STANDARD_ENV
            and SECRET_NAME_RE.search(env_name)
        ):
            self.add(
                "HPG107",
                node,
                f"Secret-like environment variable {env_name!r} is read but not declared in requires_env.",
                evidence=env_name,
            )

        hook_name = self._registered_hook(name, node)
        if hook_name:
            self.literal_hooks[hook_name] = (self.relative_path, node.lineno)

        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        target = self._qualified_name(node.value)
        if target in {"os.environ", "environ"}:
            env_name = self._string_value(node.slice)
            if (
                env_name
                and env_name not in self.declared_env
                and env_name not in STANDARD_ENV
                and SECRET_NAME_RE.search(env_name)
            ):
                self.add(
                    "HPG107",
                    node,
                    f"Secret-like environment variable {env_name!r} is read but not declared in requires_env.",
                    evidence=env_name,
                )
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function_definition_expressions(node)
        self._function_stack.append(node.name)
        for statement in node.body:
            self.visit(statement)
        self._function_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function_definition_expressions(node)
        self._function_stack.append(node.name)
        for statement in node.body:
            self.visit(statement)
        self._function_stack.pop()

    def visit_Lambda(self, node: ast.Lambda) -> None:
        self._visit_argument_defaults(node.args)
        self._function_stack.append("<lambda>")
        self.visit(node.body)
        self._function_stack.pop()

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str):
            normalized = "/" + node.value.replace("\\", "/").lower().lstrip("/")
            match = next(
                (part for part in SENSITIVE_PATH_PARTS if part in normalized),
                None,
            )
            if match:
                self.add(
                    "HPG104",
                    node,
                    f"String literal references sensitive path pattern {match!r}.",
                    evidence=match,
                )
        self.generic_visit(node)

    def _qualified_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            parent = self._qualified_name(node.value)
            return f"{parent}.{node.attr}".strip(".")
        return ""

    @staticmethod
    def _uses_safe_yaml_loader(node: ast.Call) -> bool:
        for keyword in node.keywords:
            if keyword.arg in {"Loader", "loader"}:
                value = keyword.value
                if isinstance(value, ast.Attribute) and value.attr in {
                    "SafeLoader",
                    "CSafeLoader",
                }:
                    return True
                if isinstance(value, ast.Name) and value.id in {
                    "SafeLoader",
                    "CSafeLoader",
                }:
                    return True
        return False

    @staticmethod
    def _keyword_is_true(node: ast.Call, keyword_name: str) -> bool:
        return any(
            keyword.arg == keyword_name
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
            for keyword in node.keywords
        )

    @staticmethod
    def _is_shell_call(name: str) -> bool:
        return name in {
            "os.popen",
            "os.system",
            "subprocess.call",
            "subprocess.check_call",
            "subprocess.check_output",
            "subprocess.Popen",
            "subprocess.run",
            "asyncio.create_subprocess_exec",
            "asyncio.create_subprocess_shell",
        }

    def _register_tool_override(self, name: str, node: ast.Call) -> bool | str | None:
        if not name.endswith(".register_tool"):
            return None
        for keyword in node.keywords:
            if keyword.arg != "override":
                continue
            if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, bool):
                return keyword.value.value
            return "dynamic"
        # Hermes' PluginContext.register_tool places override at positional index 9.
        if len(node.args) > 9:
            value = node.args[9]
            if isinstance(value, ast.Constant) and isinstance(value.value, bool):
                return value.value
            return "dynamic"
        return False

    def _visit_function_definition_expressions(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        self._visit_argument_defaults(node.args)
        if node.returns is not None:
            self.visit(node.returns)

    def _visit_argument_defaults(self, arguments: ast.arguments) -> None:
        for default in (*arguments.defaults, *arguments.kw_defaults):
            if default is not None:
                self.visit(default)

    @staticmethod
    def _is_destructive_call(name: str) -> bool:
        return name in {
            "os.remove",
            "os.removedirs",
            "os.rmdir",
            "os.unlink",
            "shutil.rmtree",
        } or name.endswith((".unlink", ".rmdir"))

    @staticmethod
    def _tls_verification_disabled(name: str, node: ast.Call) -> bool:
        if name in {"ssl._create_unverified_context", "urllib3.disable_warnings"}:
            return True
        return any(
            keyword.arg in {"verify", "ssl_verify"}
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is False
            for keyword in node.keywords
        )

    @staticmethod
    def _string_value(node: ast.AST | None) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return None

    def _is_unrestricted_listener(self, name: str, node: ast.Call) -> bool:
        host_values: list[str] = []
        for keyword in node.keywords:
            if keyword.arg in {"host", "hostname", "bind"}:
                value = self._string_value(keyword.value)
                if value:
                    host_values.append(value)
        if name.endswith(".bind") and node.args:
            target = node.args[0]
            if isinstance(target, (ast.Tuple, ast.List)) and target.elts:
                value = self._string_value(target.elts[0])
                if value:
                    host_values.append(value)
        return any(value in {"0.0.0.0", "::", "[::]"} for value in host_values)

    @staticmethod
    def _is_network_call(name: str) -> bool:
        return any(
            name == prefix or name.startswith(prefix + ".")
            for prefix in (
                "aiohttp",
                "ftplib",
                "grpc",
                "http.client",
                "httpx",
                "requests",
                "socket",
                "urllib.request",
                "websockets",
            )
        )

    def _flag_load_time_side_effect(self, node: ast.Call, name: str) -> None:
        context = self._function_stack[-1] if self._function_stack else "<module import>"
        if not self._function_stack or context == "register":
            self.add(
                "HPG111",
                node,
                f"{name}() runs during {context}; enabling the plugin can trigger it immediately.",
                evidence=name,
            )

    def _environment_read(self, name: str, node: ast.Call) -> str | None:
        if name in {"os.getenv", "os.environ.get", "environ.get", "getenv"} and node.args:
            return self._string_value(node.args[0])
        return None

    def _registered_hook(self, name: str, node: ast.Call) -> str | None:
        if not name.endswith(".register_hook"):
            return None
        if node.args:
            return self._string_value(node.args[0])
        return self._keyword_string(node, "hook_name") or self._keyword_string(node, "name")

    def _keyword_string(self, node: ast.Call, keyword_name: str) -> str | None:
        for keyword in node.keywords:
            if keyword.arg == keyword_name:
                return self._string_value(keyword.value)
        return None


def inspect_python(
    path: Path,
    repository_root: Path,
    declared_env: set[str],
) -> PythonInspection:
    relative = _relative(path, repository_root)
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        rule = get_rule("HPG002")
        return PythonInspection(
            findings=[
                Finding(
                    rule_id="HPG002",
                    severity=rule.default_severity,
                    message=f"Python source could not be read: {exc}",
                    path=relative,
                )
            ],
            literal_hooks={},
        )

    try:
        tree = ast.parse(source, filename=relative)
    except SyntaxError as exc:
        rule = get_rule("HPG002")
        return PythonInspection(
            findings=[
                Finding(
                    rule_id="HPG002",
                    severity=rule.default_severity,
                    message=f"Python source contains a syntax error: {exc.msg}",
                    path=relative,
                    line=exc.lineno or 1,
                    column=exc.offset or 1,
                )
            ],
            literal_hooks={},
        )

    analyzer = _Analyzer(relative, declared_env)
    analyzer.visit(tree)
    return PythonInspection(analyzer.findings, analyzer.literal_hooks)


def _relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()
