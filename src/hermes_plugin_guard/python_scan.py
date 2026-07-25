"""AST-based capability and risk checks for Python plugin code."""

from __future__ import annotations

import ast
import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from .catalog import get_rule
from .models import Finding, Severity

NETWORK_MODULES = {
    "aiohttp",
    "anthropic",
    "boto3",
    "ftplib",
    "grpc",
    "http.client",
    "httpx",
    "openai",
    "requests",
    "socket",
    "smtplib",
    "urllib3",
    "urllib.request",
    "websocket",
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
HTTP_METHODS = {
    "delete",
    "get",
    "head",
    "options",
    "patch",
    "post",
    "put",
    "request",
    "send",
    "stream",
}
DIRECT_EGRESS_ARGUMENTS: dict[str, int] = {
    **{
        f"{module}.{method}": 1 if method in {"request", "stream"} else 0
        for module in ("httpx", "requests")
        for method in HTTP_METHODS - {"send"}
    },
    "aiohttp.request": 1,
    "asyncio.open_connection": 0,
    "ftplib.FTP": 0,
    "ftplib.FTP_TLS": 0,
    "grpc.aio.insecure_channel": 0,
    "grpc.aio.secure_channel": 0,
    "grpc.insecure_channel": 0,
    "grpc.secure_channel": 0,
    "smtplib.SMTP": 0,
    "smtplib.SMTP_SSL": 0,
    "socket.create_connection": 0,
    "urllib.request.urlopen": 0,
    "urllib.request.urlretrieve": 0,
    "websocket.create_connection": 0,
    "websockets.connect": 0,
    "websockets.legacy.client.connect": 0,
    "websockets.sync.client.connect": 0,
}
OPTIONAL_DESTINATION_CALLS = {
    "ftplib.FTP",
    "ftplib.FTP_TLS",
    "smtplib.SMTP",
    "smtplib.SMTP_SSL",
}
NETWORK_INSTANCE_TYPES = {
    "aiohttp.ClientSession",
    "ftplib.FTP",
    "ftplib.FTP_TLS",
    "http.client.HTTPConnection",
    "http.client.HTTPSConnection",
    "httpx.AsyncClient",
    "httpx.Client",
    "requests.Session",
    "smtplib.SMTP",
    "smtplib.SMTP_SSL",
    "socket.socket",
    "urllib.request.Request",
    "urllib3.PoolManager",
    "urllib3.ProxyManager",
}
NETWORK_INSTANCE_FACTORIES = {
    "urllib.request.build_opener": "urllib.request.OpenerDirector",
}
CONSTRUCTOR_DESTINATION_ARGUMENTS: dict[str, int | None] = {
    "aiohttp.ClientSession": 0,
    "ftplib.FTP": 0,
    "ftplib.FTP_TLS": 0,
    "http.client.HTTPConnection": 0,
    "http.client.HTTPSConnection": 0,
    "httpx.AsyncClient": None,
    "httpx.Client": None,
    "requests.Session": None,
    "smtplib.SMTP": 0,
    "smtplib.SMTP_SSL": 0,
    "socket.socket": None,
    "urllib.request.Request": 0,
    "urllib3.PoolManager": None,
    "urllib3.ProxyManager": 0,
}
CONSTRUCTOR_DESTINATION_KEYWORDS: dict[str, tuple[str, ...]] = {
    "aiohttp.ClientSession": ("base_url",),
    "httpx.AsyncClient": ("base_url",),
    "httpx.Client": ("base_url",),
    "urllib.request.Request": ("url",),
    "urllib3.ProxyManager": ("proxy_url",),
}
CONSTRUCTOR_PORT_ARGUMENTS = {
    "http.client.HTTPConnection": 1,
    "http.client.HTTPSConnection": 1,
    "smtplib.SMTP": 1,
    "smtplib.SMTP_SSL": 1,
}
INSTANCE_EGRESS_ARGUMENTS: dict[str, int | None] = {
    **{
        f"{client}.{method}": 1 if method in {"request", "stream"} else 0
        for client in (
            "aiohttp.ClientSession",
            "httpx.AsyncClient",
            "httpx.Client",
            "requests.Session",
        )
        for method in HTTP_METHODS
    },
    "aiohttp.ClientSession.ws_connect": 0,
    "ftplib.FTP.connect": 0,
    "ftplib.FTP_TLS.connect": 0,
    "http.client.HTTPConnection.connect": None,
    "http.client.HTTPConnection.request": 1,
    "http.client.HTTPSConnection.connect": None,
    "http.client.HTTPSConnection.request": 1,
    "smtplib.SMTP.connect": 0,
    "smtplib.SMTP_SSL.connect": 0,
    "socket.socket.connect": 0,
    "socket.socket.connect_ex": 0,
    "socket.socket.sendto": 1,
    "urllib3.PoolManager.request": 1,
    "urllib3.ProxyManager.request": 1,
    "urllib.request.OpenerDirector.open": 0,
}
CALL_PORT_ARGUMENTS = {
    "asyncio.open_connection": 1,
    "ftplib.FTP.connect": 1,
    "ftplib.FTP_TLS.connect": 1,
    "smtplib.SMTP": 1,
    "smtplib.SMTP.connect": 1,
    "smtplib.SMTP_SSL": 1,
    "smtplib.SMTP_SSL.connect": 1,
}
DESTINATION_KEYWORDS = ("url", "uri", "target", "host", "hostname", "address")
METADATA_HOSTS = {
    "169.254.169.254",
    "fd00:ec2::254",
    "metadata.google.internal",
}
CLEARTEXT_SCHEMES = {"ftp", "grpc", "http", "ws"}


@dataclass(slots=True)
class PythonInspection:
    findings: list[Finding]
    literal_hooks: dict[str, tuple[str, int]]


@dataclass(frozen=True, slots=True)
class _NetworkInstance:
    qualified_type: str
    destination: str | None = None


@dataclass(slots=True)
class _BindingState:
    alias_scopes: list[dict[str, str | None]]
    network_instance_scopes: list[dict[str, _NetworkInstance | None]]
    class_alias_scopes: list[dict[str, str | None]]
    class_network_instance_scopes: list[dict[str, _NetworkInstance | None]]


class _Analyzer(ast.NodeVisitor):
    def __init__(self, relative_path: str, declared_env: set[str]) -> None:
        self.relative_path = relative_path
        self.declared_env = declared_env
        self.findings: list[Finding] = []
        self.literal_hooks: dict[str, tuple[str, int]] = {}
        self._alias_scopes: list[dict[str, str | None]] = [{}]
        self._class_alias_scopes: list[dict[str, str | None]] = []
        self._code_scope_stack = ["module"]
        self._network_reported: set[str] = set()
        self._function_stack: list[str] = []
        self._network_instance_scopes: list[dict[str, _NetworkInstance | None]] = [{}]
        self._class_network_instance_scopes: list[dict[str, _NetworkInstance | None]] = []

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
            self._current_alias_scope()[local] = alias.name if alias.asname else local
            self._check_network_module(alias.name, node)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        if node.level:
            for alias in node.names:
                local = alias.asname or alias.name
                self._current_alias_scope()[local] = None
            self.generic_visit(node)
            return
        for alias in node.names:
            local = alias.asname or alias.name
            self._current_alias_scope()[local] = f"{module}.{alias.name}".strip(".")
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

        if self._check_network_egress(name, node):
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

    def visit_Assign(self, node: ast.Assign) -> None:
        self.generic_visit(node)
        instance = self._network_instance(node.value)
        alias = self._copied_alias(node.value)
        for target in node.targets:
            self._bind_network_instance(target, instance)
            self._bind_alias(target, alias)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self.generic_visit(node)
        instance = self._network_instance(node.value)
        self._bind_network_instance(node.target, instance)
        self._bind_alias(node.target, self._copied_alias(node.value))

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.visit(node.value)
        self._bind_network_instance(node.target, self._network_instance(node.value))
        self._bind_alias(node.target, self._copied_alias(node.value))

    def visit_If(self, node: ast.If) -> None:
        self.visit(node.test)
        baseline = self._capture_binding_state()
        branches: list[_BindingState] = []
        for statements in (node.body, node.orelse):
            self._restore_binding_state(baseline)
            for statement in statements:
                self.visit(statement)
            branches.append(self._capture_binding_state())
        self._merge_binding_states(branches)

    def visit_IfExp(self, node: ast.IfExp) -> None:
        self.visit(node.test)
        baseline = self._capture_binding_state()
        branches: list[_BindingState] = []
        for expression in (node.body, node.orelse):
            self._restore_binding_state(baseline)
            self.visit(expression)
            branches.append(self._capture_binding_state())
        self._merge_binding_states(branches)

    def visit_For(self, node: ast.For) -> None:
        self._visit_loop(node.target, node.iter, node.body, node.orelse)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self._visit_loop(node.target, node.iter, node.body, node.orelse)

    def visit_While(self, node: ast.While) -> None:
        self.visit(node.test)
        baseline = self._capture_binding_state()
        for statement in node.body:
            self.visit(statement)
        body_state = self._capture_binding_state()
        self._merge_binding_states([baseline, body_state])
        for statement in node.orelse:
            self.visit(statement)
        after_else = self._capture_binding_state()
        self._merge_binding_states([body_state, after_else])

    def visit_Try(self, node: ast.Try) -> None:
        self._visit_try(node.body, node.handlers, node.orelse, node.finalbody)

    def visit_TryStar(self, node: ast.TryStar) -> None:
        self._visit_try(node.body, node.handlers, node.orelse, node.finalbody)

    def visit_Match(self, node: ast.Match) -> None:
        self.visit(node.subject)
        baseline = self._capture_binding_state()
        branches = [baseline]
        for case in node.cases:
            self._restore_binding_state(baseline)
            self.visit(case.pattern)
            for name in self._pattern_names(case.pattern):
                self._current_alias_scope()[name] = None
                self._current_network_scope()[name] = None
            if case.guard is not None:
                self.visit(case.guard)
            for statement in case.body:
                self.visit(statement)
            branches.append(self._capture_binding_state())
        self._merge_binding_states(branches)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.type is not None:
            self.visit(node.type)
        if node.name:
            self._current_alias_scope()[node.name] = None
            self._current_network_scope()[node.name] = None
        for statement in node.body:
            self.visit(statement)

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self._visit_comprehension(node.generators, [node.elt])

    def visit_SetComp(self, node: ast.SetComp) -> None:
        self._visit_comprehension(node.generators, [node.elt])

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        self._visit_comprehension(node.generators, [node.elt])

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self._visit_comprehension(node.generators, [node.key, node.value])

    def visit_With(self, node: ast.With) -> None:
        self._visit_with_items(node.items, node.body)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        self._visit_with_items(node.items, node.body)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        for base in node.bases:
            self.visit(base)
        for keyword in node.keywords:
            self.visit(keyword.value)
        self._current_alias_scope()[node.name] = None
        self._current_network_scope()[node.name] = None
        self._class_alias_scopes.append({})
        self._class_network_instance_scopes.append({})
        self._code_scope_stack.append("class")
        try:
            self._seed_class_network_instances(node.body)
            for statement in node.body:
                self.visit(statement)
        finally:
            self._code_scope_stack.pop()
            self._class_network_instance_scopes.pop()
            self._class_alias_scopes.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function_definition_expressions(node)
        self._current_alias_scope()[node.name] = None
        self._current_network_scope()[node.name] = None
        shadowed_names = self._argument_names(node.args)
        self._function_stack.append(node.name)
        self._alias_scopes.append(dict.fromkeys(shadowed_names))
        self._network_instance_scopes.append(dict.fromkeys(shadowed_names))
        self._code_scope_stack.append("function")
        try:
            for statement in node.body:
                self.visit(statement)
        finally:
            self._code_scope_stack.pop()
            self._network_instance_scopes.pop()
            self._alias_scopes.pop()
            self._function_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function_definition_expressions(node)
        self._current_alias_scope()[node.name] = None
        self._current_network_scope()[node.name] = None
        shadowed_names = self._argument_names(node.args)
        self._function_stack.append(node.name)
        self._alias_scopes.append(dict.fromkeys(shadowed_names))
        self._network_instance_scopes.append(dict.fromkeys(shadowed_names))
        self._code_scope_stack.append("function")
        try:
            for statement in node.body:
                self.visit(statement)
        finally:
            self._code_scope_stack.pop()
            self._network_instance_scopes.pop()
            self._alias_scopes.pop()
            self._function_stack.pop()

    def visit_Lambda(self, node: ast.Lambda) -> None:
        self._visit_argument_defaults(node.args)
        shadowed_names = self._argument_names(node.args)
        self._function_stack.append("<lambda>")
        self._alias_scopes.append(dict.fromkeys(shadowed_names))
        self._network_instance_scopes.append(dict.fromkeys(shadowed_names))
        self._code_scope_stack.append("function")
        try:
            self.visit(node.body)
        finally:
            self._code_scope_stack.pop()
            self._network_instance_scopes.pop()
            self._alias_scopes.pop()
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
            instance = self._lookup_network_instance(node.id)
            if instance:
                return instance.qualified_type
            return self._resolved_alias(node.id)
        if isinstance(node, ast.Attribute):
            reference = self._raw_reference(node)
            instance = self._lookup_network_instance(reference)
            if instance:
                return instance.qualified_type
            parent = self._qualified_name(node.value)
            return f"{parent}.{node.attr}".strip(".")
        if isinstance(node, ast.Call):
            instance = self._network_instance(node)
            return instance.qualified_type if instance else ""
        if isinstance(node, ast.NamedExpr):
            instance = self._network_instance(node.value)
            return instance.qualified_type if instance else self._qualified_name(node.value)
        return ""

    @classmethod
    def _raw_reference(cls, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = cls._raw_reference(node.value)
            return f"{parent}.{node.attr}".strip(".")
        return ""

    def _lookup_network_instance(self, reference: str) -> _NetworkInstance | None:
        if not reference:
            return None
        if (
            self._code_scope_stack[-1] == "class"
            and self._class_network_instance_scopes
            and reference in self._class_network_instance_scopes[-1]
        ):
            return self._class_network_instance_scopes[-1][reference]
        for scope in reversed(self._network_instance_scopes):
            if reference in scope:
                return scope[reference]
        if reference.startswith(("cls.", "self.")):
            for scope in reversed(self._class_network_instance_scopes):
                if reference in scope:
                    return scope[reference]
        return None

    def _resolved_alias(self, name: str) -> str:
        found, alias = self._alias_entry(name)
        if found:
            return alias if alias is not None else f"<local>.{name}"
        return name

    def _copied_alias(self, node: ast.AST | None) -> str | None:
        if not isinstance(node, (ast.Attribute, ast.Name)):
            return None
        reference = self._raw_reference(node)
        root = reference.split(".", 1)[0]
        found, alias = self._alias_entry(root)
        if found:
            if alias is None:
                return None
            return self._qualified_name(node)
        return None

    def _bind_alias(self, target: ast.AST, alias: str | None) -> None:
        if isinstance(target, (ast.List, ast.Tuple)):
            for element in target.elts:
                self._bind_alias(element, None)
            return
        if isinstance(target, ast.Name):
            self._current_alias_scope()[target.id] = alias

    def _has_import_provenance(self, node: ast.AST) -> bool:
        if isinstance(node, ast.NamedExpr):
            return self._has_import_provenance(node.value)
        reference = self._raw_reference(node)
        if not reference:
            return False
        root = reference.split(".", 1)[0]
        found, alias = self._alias_entry(root)
        return found and alias is not None

    def _shadow_target(self, target: ast.AST) -> None:
        self._bind_network_instance(target, None)
        self._bind_alias(target, None)

    def _alias_entry(self, name: str) -> tuple[bool, str | None]:
        if (
            self._code_scope_stack[-1] == "class"
            and self._class_alias_scopes
            and name in self._class_alias_scopes[-1]
        ):
            return True, self._class_alias_scopes[-1][name]
        for scope in reversed(self._alias_scopes):
            if name in scope:
                return True, scope[name]
        return False, None

    def _current_alias_scope(self) -> dict[str, str | None]:
        if self._code_scope_stack[-1] == "class" and self._class_alias_scopes:
            return self._class_alias_scopes[-1]
        return self._alias_scopes[-1]

    def _current_network_scope(self) -> dict[str, _NetworkInstance | None]:
        if self._code_scope_stack[-1] == "class" and self._class_network_instance_scopes:
            return self._class_network_instance_scopes[-1]
        return self._network_instance_scopes[-1]

    def _capture_binding_state(self) -> _BindingState:
        return _BindingState(
            alias_scopes=[scope.copy() for scope in self._alias_scopes],
            network_instance_scopes=[scope.copy() for scope in self._network_instance_scopes],
            class_alias_scopes=[scope.copy() for scope in self._class_alias_scopes],
            class_network_instance_scopes=[
                scope.copy() for scope in self._class_network_instance_scopes
            ],
        )

    def _restore_binding_state(self, state: _BindingState) -> None:
        self._alias_scopes = [scope.copy() for scope in state.alias_scopes]
        self._network_instance_scopes = [scope.copy() for scope in state.network_instance_scopes]
        self._class_alias_scopes = [scope.copy() for scope in state.class_alias_scopes]
        self._class_network_instance_scopes = [
            scope.copy() for scope in state.class_network_instance_scopes
        ]

    def _merge_binding_states(self, states: list[_BindingState]) -> None:
        if not states:
            return
        self._alias_scopes = [
            self._merge_alias_maps([state.alias_scopes[index] for state in states])
            for index in range(len(states[0].alias_scopes))
        ]
        self._network_instance_scopes = [
            self._merge_network_maps([state.network_instance_scopes[index] for state in states])
            for index in range(len(states[0].network_instance_scopes))
        ]
        self._class_alias_scopes = [
            self._merge_alias_maps([state.class_alias_scopes[index] for state in states])
            for index in range(len(states[0].class_alias_scopes))
        ]
        self._class_network_instance_scopes = [
            self._merge_network_maps(
                [state.class_network_instance_scopes[index] for state in states]
            )
            for index in range(len(states[0].class_network_instance_scopes))
        ]

    @staticmethod
    def _merge_alias_maps(
        scopes: list[dict[str, str | None]],
    ) -> dict[str, str | None]:
        merged: dict[str, str | None] = {}
        keys = set().union(*(scope.keys() for scope in scopes))
        for key in keys:
            aliases = sorted({alias for scope in scopes if (alias := scope.get(key)) is not None})
            if aliases:
                merged[key] = aliases[0]
            elif all(key in scope for scope in scopes):
                merged[key] = None
        return merged

    @staticmethod
    def _merge_network_maps(
        scopes: list[dict[str, _NetworkInstance | None]],
    ) -> dict[str, _NetworkInstance | None]:
        merged: dict[str, _NetworkInstance | None] = {}
        keys = set().union(*(scope.keys() for scope in scopes))
        for key in keys:
            instances = {instance for scope in scopes if (instance := scope.get(key)) is not None}
            if instances:
                ordered = sorted(
                    instances,
                    key=lambda instance: (
                        instance.qualified_type,
                        instance.destination or "",
                    ),
                )
                selected = ordered[0]
                destination = (
                    selected.destination
                    if all(instance.destination == selected.destination for instance in ordered)
                    else None
                )
                merged[key] = _NetworkInstance(selected.qualified_type, destination)
            elif all(key in scope for scope in scopes):
                merged[key] = None
        return merged

    def _visit_loop(
        self,
        target: ast.AST,
        iterator: ast.AST,
        body: list[ast.stmt],
        orelse: list[ast.stmt],
    ) -> None:
        self.visit(iterator)
        baseline = self._capture_binding_state()
        self._shadow_target(target)
        for statement in body:
            self.visit(statement)
        body_state = self._capture_binding_state()
        self._merge_binding_states([baseline, body_state])
        for statement in orelse:
            self.visit(statement)
        after_else = self._capture_binding_state()
        self._merge_binding_states([body_state, after_else])

    def _visit_try(
        self,
        body: list[ast.stmt],
        handlers: list[ast.ExceptHandler],
        orelse: list[ast.stmt],
        finalbody: list[ast.stmt],
    ) -> None:
        baseline = self._capture_binding_state()
        possible_handler_states = [baseline]
        for statement in body:
            self.visit(statement)
            possible_handler_states.append(self._capture_binding_state())
        for statement in orelse:
            self.visit(statement)
        branches = [self._capture_binding_state()]

        self._merge_binding_states(possible_handler_states)
        handler_baseline = self._capture_binding_state()
        for handler in handlers:
            self._restore_binding_state(handler_baseline)
            self.visit(handler)
            branches.append(self._capture_binding_state())

        self._merge_binding_states(branches)
        for statement in finalbody:
            self.visit(statement)

    @staticmethod
    def _pattern_names(pattern: ast.pattern) -> set[str]:
        names: set[str] = set()
        for node in ast.walk(pattern):
            if isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
                names.add(node.name)
            elif isinstance(node, ast.MatchMapping) and node.rest:
                names.add(node.rest)
        return names

    def _visit_comprehension(
        self,
        generators: list[ast.comprehension],
        result_nodes: list[ast.AST],
    ) -> None:
        if not generators:
            for result_node in result_nodes:
                self.visit(result_node)
            return

        self.visit(generators[0].iter)
        self._alias_scopes.append({})
        self._network_instance_scopes.append({})
        self._code_scope_stack.append("comprehension")
        try:
            first, *remaining = generators
            self._shadow_target(first.target)
            for condition in first.ifs:
                self.visit(condition)
            for generator in remaining:
                self.visit(generator.iter)
                self._shadow_target(generator.target)
                for condition in generator.ifs:
                    self.visit(condition)
            for result_node in result_nodes:
                self.visit(result_node)
        finally:
            self._code_scope_stack.pop()
            self._network_instance_scopes.pop()
            self._alias_scopes.pop()

    @staticmethod
    def _argument_names(arguments: ast.arguments) -> set[str]:
        names = {
            argument.arg
            for argument in (
                *arguments.posonlyargs,
                *arguments.args,
                *arguments.kwonlyargs,
            )
        }
        if arguments.vararg:
            names.add(arguments.vararg.arg)
        if arguments.kwarg:
            names.add(arguments.kwarg.arg)
        return names

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

    def _check_network_egress(self, name: str, node: ast.Call) -> bool:
        instance = self._instance_for_callable(node.func)
        if name in DIRECT_EGRESS_ARGUMENTS:
            if not self._has_import_provenance(node.func):
                return False
            argument_index = DIRECT_EGRESS_ARGUMENTS[name]
        elif instance and name in INSTANCE_EGRESS_ARGUMENTS:
            argument_index = INSTANCE_EGRESS_ARGUMENTS[name]
        else:
            return False

        argument = self._call_argument(
            node,
            argument_index,
            DESTINATION_KEYWORDS,
        )
        if name in OPTIONAL_DESTINATION_CALLS and (
            argument is None or self._string_value(argument) == ""
        ):
            return False

        destination = self._destination_from_node(
            argument,
            scheme_hint=self._scheme_hint(name),
            port_override=self._literal_port(node, CALL_PORT_ARGUMENTS.get(name)),
        )
        if destination is None and instance:
            destination = instance.destination

        severity, risk = self._egress_risk(name, destination)
        if destination is None:
            message = (
                f"Outbound network call via {name}() uses a dynamic destination "
                "that static review cannot bound."
            )
            evidence_destination = "<dynamic destination>"
        elif risk == "metadata":
            message = (
                f"Outbound network call via {name}() targets link-local or cloud "
                f"metadata destination {destination!r}."
            )
            evidence_destination = destination
        elif risk == "loopback":
            message = (
                f"Outbound network call via {name}() targets loopback destination {destination!r}."
            )
            evidence_destination = destination
        elif risk == "cleartext":
            message = (
                f"Outbound network call via {name}() uses an unencrypted transport "
                f"to {destination!r}."
            )
            evidence_destination = destination
        else:
            message = f"Outbound network call via {name}() targets {destination!r}."
            evidence_destination = destination

        self.add(
            "HPG112",
            node,
            message,
            severity=severity,
            evidence=f"{name} -> {evidence_destination}",
        )
        return True

    def _instance_for_callable(self, node: ast.AST) -> _NetworkInstance | None:
        reference = self._raw_reference(node)
        if reference:
            stored = self._lookup_network_instance(reference)
            if stored and stored.qualified_type in INSTANCE_EGRESS_ARGUMENTS:
                return stored
        if not isinstance(node, ast.Attribute):
            return None
        parent_reference = self._raw_reference(node.value)
        if parent_reference:
            return self._lookup_network_instance(parent_reference)
        return self._network_instance(node.value)

    def _network_instance(self, node: ast.AST | None) -> _NetworkInstance | None:
        if node is None:
            return None
        if isinstance(node, ast.NamedExpr):
            return self._network_instance(node.value)
        reference = self._raw_reference(node)
        if reference:
            existing = self._lookup_network_instance(reference)
            if existing:
                return existing
        if isinstance(node, ast.Attribute):
            parent = self._instance_for_callable(node)
            qualified_name = self._qualified_name(node)
            if parent and qualified_name in INSTANCE_EGRESS_ARGUMENTS:
                return _NetworkInstance(qualified_name, parent.destination)
        if not isinstance(node, ast.Call):
            return None

        constructor_name = self._qualified_name(node.func)
        qualified_type = NETWORK_INSTANCE_FACTORIES.get(
            constructor_name,
            constructor_name,
        )
        if (
            qualified_type not in NETWORK_INSTANCE_TYPES
            and constructor_name not in NETWORK_INSTANCE_FACTORIES
        ):
            return None
        if not self._has_import_provenance(node.func):
            return None
        if constructor_name in NETWORK_INSTANCE_FACTORIES:
            return _NetworkInstance(qualified_type)
        argument = self._call_argument(
            node,
            CONSTRUCTOR_DESTINATION_ARGUMENTS[qualified_type],
            CONSTRUCTOR_DESTINATION_KEYWORDS.get(qualified_type, DESTINATION_KEYWORDS),
        )
        destination = self._destination_from_node(
            argument,
            scheme_hint=self._scheme_hint(qualified_type),
            port_override=self._literal_port(
                node,
                CONSTRUCTOR_PORT_ARGUMENTS.get(qualified_type),
            ),
        )
        return _NetworkInstance(qualified_type, destination)

    def _bind_network_instance(
        self,
        target: ast.AST,
        instance: _NetworkInstance | None,
    ) -> None:
        if isinstance(target, (ast.List, ast.Tuple)):
            for element in target.elts:
                self._bind_network_instance(element, None)
            return
        reference = self._raw_reference(target)
        if not reference:
            return
        if reference.startswith(("cls.", "self.")) and self._class_network_instance_scopes:
            if self._function_stack:
                self._network_instance_scopes[-1][reference] = instance
                if instance is not None:
                    self._class_network_instance_scopes[-1][reference] = instance
            else:
                self._class_network_instance_scopes[-1][reference] = instance
            return
        self._current_network_scope()[reference] = instance

    def _seed_class_network_instances(self, body: list[ast.stmt]) -> None:
        if not self._class_network_instance_scopes or not self._class_alias_scopes:
            return
        baseline_network = self._class_network_instance_scopes[-1].copy()
        baseline_aliases = self._class_alias_scopes[-1].copy()
        finding_count = len(self.findings)
        literal_hooks = self.literal_hooks.copy()
        network_reported = self._network_reported.copy()

        for member in body:
            if isinstance(member, (ast.AsyncFunctionDef, ast.FunctionDef)):
                self.visit(member)

        network_scope = self._class_network_instance_scopes[-1]
        seeded_instances = {
            reference: instance
            for reference, instance in network_scope.items()
            if reference.startswith(("cls.", "self.")) and instance is not None
        }
        network_scope.clear()
        network_scope.update(baseline_network)
        network_scope.update(seeded_instances)
        self._class_alias_scopes[-1].clear()
        self._class_alias_scopes[-1].update(baseline_aliases)
        del self.findings[finding_count:]
        self.literal_hooks = literal_hooks
        self._network_reported = network_reported

    def _visit_with_items(
        self,
        items: list[ast.withitem],
        body: list[ast.stmt],
    ) -> None:
        for item in items:
            self.visit(item.context_expr)
            if item.optional_vars is not None:
                self._bind_network_instance(
                    item.optional_vars,
                    self._network_instance(item.context_expr),
                )
                self._bind_alias(item.optional_vars, None)
        for statement in body:
            self.visit(statement)

    @staticmethod
    def _call_argument(
        node: ast.Call,
        positional_index: int | None,
        keyword_names: tuple[str, ...],
    ) -> ast.AST | None:
        if positional_index is not None and len(node.args) > positional_index:
            return node.args[positional_index]
        for keyword in node.keywords:
            if keyword.arg in keyword_names:
                return keyword.value
        return None

    def _destination_from_node(
        self,
        node: ast.AST | None,
        *,
        scheme_hint: str | None,
        port_override: int | None = None,
    ) -> str | None:
        if node is None:
            return None
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return self._sanitize_destination(
                node.value,
                scheme_hint=scheme_hint,
                port_override=port_override,
            )
        if isinstance(node, (ast.List, ast.Tuple)) and node.elts:
            host = self._string_value(node.elts[0])
            port = (
                node.elts[1].value
                if len(node.elts) > 1
                and isinstance(node.elts[1], ast.Constant)
                and isinstance(node.elts[1].value, int)
                else None
            )
            if host:
                return self._sanitize_destination(
                    host,
                    scheme_hint=scheme_hint,
                    port_override=port if port is not None else port_override,
                )
            return None
        instance = self._network_instance(node)
        return instance.destination if instance else None

    @staticmethod
    def _literal_port(node: ast.Call, positional_index: int | None) -> int | None:
        value: ast.AST | None = None
        if positional_index is not None and len(node.args) > positional_index:
            value = node.args[positional_index]
        if value is None:
            for keyword in node.keywords:
                if keyword.arg == "port":
                    value = keyword.value
                    break
        if (
            isinstance(value, ast.Constant)
            and isinstance(value.value, int)
            and 0 < value.value <= 65_535
        ):
            return value.value
        return None

    @staticmethod
    def _sanitize_destination(
        value: str,
        *,
        scheme_hint: str | None,
        port_override: int | None = None,
    ) -> str | None:
        literal = value.strip()
        if not literal or len(literal) > 2_048 or literal.startswith(("/", ".", "?", "#")):
            return None
        if literal.casefold().startswith("dns:///"):
            literal = literal[7:]

        has_explicit_scheme = "://" in literal
        if not has_explicit_scheme and scheme_hint is None:
            host_candidate = literal.rsplit("@", 1)[-1].split("/", 1)[0]
            if (
                "." not in host_candidate
                and ":" not in host_candidate
                and host_candidate.casefold() != "localhost"
            ):
                return None

        bare_ipv6: ipaddress.IPv6Address | None = None
        if not has_explicit_scheme and ":" in literal:
            try:
                candidate_address = ipaddress.ip_address(literal)
                if isinstance(candidate_address, ipaddress.IPv6Address):
                    bare_ipv6 = candidate_address
            except ValueError:
                pass
        if bare_ipv6:
            host = bare_ipv6.compressed
            parsed_port = None
            parsed_scheme = ""
        else:
            try:
                parsed = urlsplit(literal if has_explicit_scheme else f"//{literal}")
                host = parsed.hostname
                parsed_port = parsed.port
                parsed_scheme = parsed.scheme
            except ValueError:
                return None
        if not host or any(character.isspace() for character in host):
            return None

        host = host.casefold().rstrip(".")
        if "%" in host:
            return None
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            return None
        if (
            not host
            or len(host) > 253
            or (":" not in host and re.fullmatch(r"[a-z0-9_][a-z0-9._-]*", host) is None)
        ):
            return None
        if ":" in host:
            try:
                ipaddress.ip_address(host)
            except ValueError:
                return None
        display_host = f"[{host}]" if ":" in host else host
        port = port_override if port_override is not None else parsed_port
        port_suffix = f":{port}" if port is not None and 0 < port <= 65_535 else ""
        scheme = parsed_scheme.casefold() if parsed_scheme else scheme_hint
        if scheme:
            return f"{scheme}://{display_host}{port_suffix}"
        return f"{display_host}{port_suffix}"

    @staticmethod
    def _scheme_hint(name: str) -> str | None:
        if "HTTPSConnection" in name:
            return "https"
        if "HTTPConnection" in name:
            return "http"
        if "FTP_TLS" in name:
            return "ftps"
        if ".FTP" in name:
            return "ftp"
        if "SMTP_SSL" in name:
            return "smtps"
        if ".SMTP" in name:
            return "smtp"
        if "insecure_channel" in name:
            return "grpc"
        if "secure_channel" in name:
            return "grpcs"
        if name.startswith(("asyncio.open_connection", "socket.")):
            return "tcp"
        return None

    @staticmethod
    def _egress_risk(
        name: str,
        destination: str | None,
    ) -> tuple[Severity, str]:
        if destination is None:
            if "insecure_channel" in name:
                return Severity.HIGH, "cleartext"
            return Severity.MEDIUM, "standard"

        try:
            parsed = urlsplit(destination if "://" in destination else f"//{destination}")
            host = (parsed.hostname or "").casefold()
            scheme = parsed.scheme.casefold()
        except ValueError:
            return Severity.MEDIUM, "standard"

        if host in METADATA_HOSTS:
            return Severity.HIGH, "metadata"
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            address = None
        if address and address.is_link_local:
            return Severity.HIGH, "metadata"
        if host == "localhost" or host.endswith(".localhost") or (address and address.is_loopback):
            return Severity.LOW, "loopback"
        if scheme in CLEARTEXT_SCHEMES or "insecure_channel" in name:
            return Severity.HIGH, "cleartext"
        return Severity.MEDIUM, "standard"

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
