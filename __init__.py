"""Hermes directory-plugin entry point.

Hermes loads a Git-installed plugin directly from the repository root.  Keep
this shim relative so it always uses the scanner shipped in the same checkout
instead of an unrelated globally installed package.
"""

if __package__:
    from .src.hermes_plugin_guard.hermes_plugin import register
else:  # Imported directly by repository tooling such as pytest collection.
    from hermes_plugin_guard.hermes_plugin import register

__all__ = ["register"]
