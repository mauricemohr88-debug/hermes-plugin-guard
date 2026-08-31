"""Slim Hermes directory-plugin entry point.

Hermes scans only this runtime tree when the repository is installed through
its ``/src`` subdirectory.  The implementation remains in the packaged
``hermes_plugin_guard`` module.
"""

from .hermes_plugin_guard.hermes_plugin import register

__all__ = ["register"]
