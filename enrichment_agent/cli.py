"""Command-line entry point for the enrichment agent.

Modes:
    one-shot:  python -m enrichment_agent.cli enrich --input X --output Y
    watch:     python -m enrichment_agent.cli watch
        Watches the inbox for new bundles dropped by an upstream STIX producer,
        enriches each, and writes the result to the outbox. Processed inputs
        move to inbox/processed/ to avoid reprocessing.
"""
from __future__ import annotations

import argparse
import shutil
import sys
import time
from pathlib import Path

from rich.console import Console
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from .agent import EnrichmentAgent
from .config import Config
from .llm import LLMClient
from .stix_io import EnrichmentSession, load_bundle, save_bundle, summarize_bundle
from .tools import Tools
from .trace import Tracer


def _enrich_one(input_path: Path, output_path: Path, cfg: Config, tracer: Tracer) -> bool:
    """Run the agent on a single bundle. Returns True on success."""
    try:
        bundle = load_bundle(input_path)
    except Exception as e:
        tracer.log_error(f"Failed to load bundle {input_path}: {e}")
        return False

    summary = summarize_bundle(bundle)
    session = EnrichmentSession(original_bundle=bundle)

    llm = LLMClient(host=cfg.ollama_host, model=cfg.ollama_model)
    if not llm.health_check():
        tracer.log_error(
            f"Ollama health check failed at {cfg.ollama_host} for model "
            f"'{cfg.ollama_model}'. Is Ollama running and the model pulled?"
        )
        return False

    tools = Tools(mock_data_dir=cfg.mock_data_dir, session=session)
    agent = EnrichmentAgent(llm=llm, tools=tools, tracer=tracer, max_steps=cfg.max_agent_steps)

    final_session = agent.enrich(bundle_summary=summary, bundle_id=bundle.id)

    enriched = final_session.to_bundle()
    save_bundle(enriched, output_path)
    tracer.console.print(f"[green]✔ Enriched bundle written to: {output_path}[/]")
    return True


# ──────────────────────────────────────────────────────────────────────────
# Watch mode
# ──────────────────────────────────────────────────────────────────────────


class _InboxHandler(FileSystemEventHandler):
    def __init__(self, cfg: Config, tracer: Tracer) -> None:
        self.cfg = cfg
        self.tracer = tracer
        self.processed_dir = cfg.inbox_dir / "processed"
        self.processed_dir.mkdir(parents=True, exist_ok=True)

    def on_created(self, event) -> None:
        if event.is_directory:
            return
        path = Path(event.src_path)
        if path.suffix.lower() != ".json":
            return
        # Wait briefly to ensure the file is fully written
        time.sleep(0.5)
        self._process(path)

    def _process(self, input_path: Path) -> None:
        out_name = input_path.stem + ".enriched.json"
        output_path = self.cfg.outbox_dir / out_name
        ok = _enrich_one(input_path, output_path, self.cfg, self.tracer)

        if ok:
            try:
                shutil.move(str(input_path), str(self.processed_dir / input_path.name))
            except Exception as e:
                self.tracer.log_error(f"Failed to move processed file: {e}")


def _cmd_watch(cfg: Config, tracer: Tracer) -> int:
    cfg.inbox_dir.mkdir(parents=True, exist_ok=True)
    cfg.outbox_dir.mkdir(parents=True, exist_ok=True)

    handler = _InboxHandler(cfg=cfg, tracer=tracer)
    observer = Observer()
    observer.schedule(handler, str(cfg.inbox_dir), recursive=False)
    observer.start()

    tracer.console.print(
        f"[bold cyan]Watching {cfg.inbox_dir} — drop STIX bundles here. "
        f"Press Ctrl+C to stop.[/]"
    )
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
    return 0


# ──────────────────────────────────────────────────────────────────────────
# Argument parsing
# ──────────────────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="enrichment-agent",
        description="STIX 2.1 Submission Enrichment Agent (Ollama-backed).",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_enrich = sub.add_parser("enrich", help="Enrich a single bundle.")
    p_enrich.add_argument("--input", "-i", required=True, type=Path, help="Input bundle path.")
    p_enrich.add_argument("--output", "-o", required=True, type=Path, help="Output bundle path.")

    sub.add_parser("watch", help="Watch the inbox directory for new bundles.")

    args = parser.parse_args(argv)
    cfg = Config.from_env()
    tracer = Tracer(console=Console())

    if args.cmd == "enrich":
        ok = _enrich_one(args.input, args.output, cfg, tracer)
        return 0 if ok else 1
    if args.cmd == "watch":
        return _cmd_watch(cfg, tracer)

    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
