"""A benign plugin used to keep false positives visible in tests."""

from __future__ import annotations

import os


def register(ctx):
    def echo(text: str) -> str:
        token_configured = bool(os.getenv("SAFE_PLUGIN_TOKEN"))
        return f"{text} (configured={token_configured})"

    def on_session_start(event):
        return event

    ctx.register_tool(
        name="safe_echo",
        fn=echo,
        description="Return text without invoking external capabilities.",
    )
    ctx.register_hook("on_session_start", on_session_start)
