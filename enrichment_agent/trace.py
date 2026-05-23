"""Visible trace logging for the agentic loop.

The output of this module is what makes the agent's behavior legible to a
human reviewer. Every (thought, action, observation) tuple is rendered with
clear labels — invaluable for debugging and for live demos where you
want to point at the screen and say 'see, that's the agent deciding'.
"""
from __future__ import annotations

import json
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.text import Text


class Tracer:
    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()

    def log_session_start(self, bundle_id: str, model: str) -> None:
        self.console.rule(
            f"[bold cyan]Enrichment session — model={model} — bundle={bundle_id}",
            style="cyan",
        )

    def log_step_start(self, step: int, max_steps: int) -> None:
        self.console.print()
        self.console.rule(f"[bold yellow]Step {step}/{max_steps}", style="yellow")

    def log_thought(self, content: str) -> None:
        if not content:
            return
        self.console.print(
            Panel(
                Text(content, style="white"),
                title="[bold green]THOUGHT",
                border_style="green",
            )
        )

    def log_action(self, tool_name: str, args: dict[str, Any]) -> None:
        args_pretty = json.dumps(args, indent=2, default=str)
        self.console.print(
            Panel(
                f"[bold]{tool_name}[/]\n\n{args_pretty}",
                title="[bold blue]ACTION",
                border_style="blue",
            )
        )

    def log_observation(self, raw_result: str) -> None:
        # raw_result is JSON string from Tools.execute
        try:
            parsed = json.loads(raw_result)
            pretty = json.dumps(parsed, indent=2, default=str)
        except Exception:
            pretty = raw_result
        truncated = pretty if len(pretty) <= 1500 else pretty[:1500] + "\n... [truncated]"
        self.console.print(
            Panel(
                truncated,
                title="[bold magenta]OBSERVATION",
                border_style="magenta",
            )
        )

    def log_done(self, final_message: str, additions_count: int) -> None:
        self.console.print()
        self.console.rule(
            f"[bold green]Agent finished — {additions_count} enrichment(s) added",
            style="green",
        )
        if final_message:
            self.console.print(
                Panel(
                    final_message,
                    title="[bold green]FINAL SUMMARY",
                    border_style="green",
                )
            )

    def log_timeout(self, max_steps: int) -> None:
        self.console.print()
        self.console.rule(
            f"[bold red]Agent stopped — exceeded max_steps ({max_steps})",
            style="red",
        )

    def log_error(self, message: str) -> None:
        self.console.print(
            Panel(
                message,
                title="[bold red]ERROR",
                border_style="red",
            )
        )
