"""Smoke test that runs the agent loop end-to-end with a scripted fake LLM.

Validates:
  - config loads
  - sample bundle parses
  - bundle summarization works
  - tool definitions and dispatch work
  - the agent loop processes tool calls correctly
  - mutation tools modify the session
  - final bundle serializes correctly

Does NOT validate Ollama connectivity (no LLM call). Run this after a fresh
clone to confirm the static code is healthy. To exercise the full loop with
a real LLM, run:
    python -m enrichment_agent.cli enrich -i samples/thin_bundle.json -o outbox/out.json
"""
from __future__ import annotations

import sys
from pathlib import Path

# Allow running from project root without install
sys.path.insert(0, str(Path(__file__).parent))

from enrichment_agent.agent import EnrichmentAgent, SYSTEM_PROMPT  # noqa: E402
from enrichment_agent.config import Config  # noqa: E402
from enrichment_agent.stix_io import (  # noqa: E402
    EnrichmentSession,
    load_bundle,
    save_bundle,
    summarize_bundle,
)
from enrichment_agent.tools import Tools  # noqa: E402
from enrichment_agent.trace import Tracer  # noqa: E402


class FakeLLM:
    """A scripted LLM that returns canned tool calls in sequence, to verify
    the agent loop without requiring Ollama."""

    def __init__(self, indicator_id: str) -> None:
        self.indicator_id = indicator_id
        self._step = 0
        self._added_attack_pattern_id: str | None = None
        self.model = "fake-llm-for-tests"

    def chat(self, messages, tools=None):
        self._step += 1

        # Step 1: lookup MITRE for "powershell"
        if self._step == 1:
            return {
                "message": {
                    "content": "I'll start by looking up MITRE ATT&CK techniques related to PowerShell.",
                    "tool_calls": [
                        {
                            "function": {
                                "name": "mitre_attack_lookup",
                                "arguments": {"query": "powershell"},
                            }
                        }
                    ],
                }
            }

        # Step 2: add the attack pattern based on the lookup
        if self._step == 2:
            return {
                "message": {
                    "content": "Strong match for T1059.001 (PowerShell). Adding it.",
                    "tool_calls": [
                        {
                            "function": {
                                "name": "add_attack_pattern",
                                "arguments": {
                                    "name": "PowerShell",
                                    "mitre_id": "T1059.001",
                                    "description": "Adversaries may abuse PowerShell commands and scripts for execution.",
                                },
                            }
                        }
                    ],
                }
            }

        # Step 3: capture the new attack-pattern id from history and add a relationship
        if self._step == 3:
            # Inspect last tool result message to extract the id
            for m in reversed(messages):
                if m.get("role") == "tool" and m.get("name") == "add_attack_pattern":
                    import json as _json
                    parsed = _json.loads(m["content"])
                    self._added_attack_pattern_id = parsed.get("id")
                    break
            return {
                "message": {
                    "content": "Linking the indicator to the attack-pattern.",
                    "tool_calls": [
                        {
                            "function": {
                                "name": "add_relationship",
                                "arguments": {
                                    "source_ref": self.indicator_id,
                                    "target_ref": self._added_attack_pattern_id,
                                    "relationship_type": "indicates",
                                },
                            }
                        }
                    ],
                }
            }

        # Step 4: assess completeness
        if self._step == 4:
            return {
                "message": {
                    "content": "Checking if I've added enough.",
                    "tool_calls": [
                        {"function": {"name": "assess_completeness", "arguments": {}}}
                    ],
                }
            }

        # Step 5: Final summary, no tool calls — agent stops
        return {
            "message": {
                "content": (
                    "Enrichment complete. Added MITRE T1059.001 (PowerShell) "
                    "as the technique indicated by the observed encoded "
                    "PowerShell execution, with a linking relationship from "
                    "the indicator. Confidence: high. No threat-actor "
                    "attribution — single-indicator evidence is insufficient."
                ),
            }
        }

    def health_check(self):
        return True


def main() -> int:
    project_root = Path(__file__).resolve().parent
    cfg = Config.from_env(project_root=project_root)

    sample_path = project_root / "samples" / "thin_bundle.json"
    print(f"Loading sample: {sample_path}")
    bundle = load_bundle(sample_path)
    print(f"Loaded bundle with {len(bundle.objects)} object(s)")

    summary = summarize_bundle(bundle)
    print("\n--- Bundle summary ---")
    print(summary)
    print("--- end summary ---\n")

    # Find the indicator id for the fake LLM to reference
    indicator_id = next(
        (o.id for o in bundle.objects if o.type == "indicator"), None
    )
    assert indicator_id, "Sample bundle must contain an indicator"

    session = EnrichmentSession(original_bundle=bundle)
    tools = Tools(mock_data_dir=cfg.mock_data_dir, session=session)
    fake_llm = FakeLLM(indicator_id=indicator_id)
    tracer = Tracer()

    agent = EnrichmentAgent(llm=fake_llm, tools=tools, tracer=tracer, max_steps=10)
    final_session = agent.enrich(bundle_summary=summary, bundle_id=bundle.id)

    enriched = final_session.to_bundle()
    out_path = project_root / "outbox" / "smoke_test_output.json"
    save_bundle(enriched, out_path)
    print(f"\nWrote enriched bundle to: {out_path}")
    print(f"Original objects: {len(bundle.objects)}")
    print(f"Final objects:    {len(enriched.objects)}")
    print(f"Added: {len(final_session.added_objects)}")

    # Validate added types
    added_types = sorted(o.type for o in final_session.added_objects)
    print(f"Added types: {added_types}")
    expected = ["attack-pattern", "relationship"]
    assert added_types == expected, f"Expected {expected}, got {added_types}"

    print("\n✔ Smoke test passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
