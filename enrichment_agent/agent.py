"""The Submission Enrichment Agent — ReAct-style loop using Ollama tool calls.

Loop semantics (each step):
    1. Send messages + tool definitions to the LLM.
    2. If LLM returns tool_calls, execute each tool, append observations,
       continue.
    3. If LLM returns plain text without tool_calls, treat as final answer
       and exit.
    4. If max_steps reached, exit with a timeout signal.

Architectural choices worth knowing:
    * The LLM never sees raw STIX JSON in full. It sees a structured summary
      and the lookup-tool results. Keeps the context window small and
      reasoning crisp.
    * Mutation tools validate references — the LLM cannot create dangling
      relationships or invent ids it doesn't know about.
    * Trace emission is at the loop level, not inside the LLM client. The
      trace IS the audit artifact.
"""
from __future__ import annotations

from typing import Any

from .llm import LLMClient
from .stix_io import EnrichmentSession
from .tools import Tools
from .trace import Tracer


SYSTEM_PROMPT = """You are a cybersecurity threat intelligence enrichment agent.

You receive thin STIX 2.1 bundles (typically a single Indicator and an
Observed-Data) and you must enrich them by adding:
  - applicable MITRE ATT&CK techniques (as attack-pattern SDOs)
  - threat-actor attribution WHEN strongly supported (as threat-actor SDOs)
  - relationships (SROs) linking new objects to existing observables

You have these tools:
  LOOKUP (read-only):
    mitre_attack_lookup(query)
    threat_actor_search(query)
    related_intel_search(query)
  MUTATE (write):
    add_attack_pattern(name, mitre_id, description)
    add_threat_actor(name, description, sophistication, primary_motivation, aliases)
    add_relationship(source_ref, target_ref, relationship_type, description)
  REFLECT:
    assess_completeness()

Workflow:
  1. Read the bundle summary in the user message.
  2. Look up MITRE ATT&CK techniques for the observed pattern.
  3. Add the most clearly supported attack-pattern(s).
  4. Add relationships linking the indicator(s) to the new attack-pattern(s)
     using the relationship_type "indicates".
  5. Optionally search for threat-actor attribution. Only add a threat-actor
     if multiple indicators clearly point to one — attribution is high-stakes.
  6. Call assess_completeness() to self-check; stop when sufficient.
  7. Reply with a brief final summary (no more tool calls) and stop.

Critical rules:
  * DO NOT invent MITRE IDs or technique names. Use only those returned by
    mitre_attack_lookup.
  * DO NOT fabricate threat actors. Use only those returned by
    threat_actor_search.
  * DO NOT over-enrich. 1–3 attack-patterns and 0–1 threat-actor is usually
    appropriate for a thin bundle.
  * When creating relationships, source_ref and target_ref MUST be ids you
    have seen in the bundle summary or that were returned by your own
    add_* tool calls.
  * When you are done, send a brief final message WITHOUT calling any tools.
"""


class EnrichmentAgent:
    def __init__(
        self,
        llm: LLMClient,
        tools: Tools,
        tracer: Tracer,
        max_steps: int = 12,
    ) -> None:
        self.llm = llm
        self.tools = tools
        self.tracer = tracer
        self.max_steps = max_steps

    def enrich(self, bundle_summary: str, bundle_id: str) -> EnrichmentSession:
        """Run the agentic loop until the agent stops or max_steps is hit.

        Returns the EnrichmentSession (which contains the working bundle).
        """
        self.tracer.log_session_start(bundle_id=bundle_id, model=self.llm.model)

        messages: list[dict[str, Any]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    "Please enrich the following STIX 2.1 bundle. "
                    "Begin by looking up applicable MITRE ATT&CK techniques.\n\n"
                    f"{bundle_summary}"
                ),
            },
        ]

        tool_defs = self.tools.get_definitions()

        for step in range(1, self.max_steps + 1):
            self.tracer.log_step_start(step, self.max_steps)

            response = self.llm.chat(messages=messages, tools=tool_defs)
            message = response["message"]

            assistant_content = message.get("content", "") or ""
            tool_calls = message.get("tool_calls") or []

            # Always show the model's thought, if any
            if assistant_content.strip():
                self.tracer.log_thought(assistant_content)

            # Append the assistant message (preserving tool_calls) for next turn
            messages.append(self._assistant_message_for_history(message))

            if not tool_calls:
                # Final answer — agent decided to stop
                self.tracer.log_done(
                    final_message=assistant_content,
                    additions_count=len(self.tools.session.added_objects),
                )
                return self.tools.session

            # Execute tool calls and append observations
            for call in tool_calls:
                fn = call.get("function", {})
                name = fn.get("name", "")
                args = fn.get("arguments") or {}
                if isinstance(args, str):
                    # Some clients return arguments as a JSON string
                    import json as _json
                    try:
                        args = _json.loads(args)
                    except Exception:
                        args = {}

                self.tracer.log_action(name, args)
                result = self.tools.execute(name, args)
                self.tracer.log_observation(result)

                messages.append(
                    {
                        "role": "tool",
                        "name": name,
                        "content": result,
                    }
                )

        # Loop ended without the agent stopping itself
        self.tracer.log_timeout(self.max_steps)
        return self.tools.session

    @staticmethod
    def _assistant_message_for_history(raw_message: dict[str, Any]) -> dict[str, Any]:
        """Normalize an Ollama assistant message for inclusion in history.

        Ollama returns a dict-like object; we keep just role/content/tool_calls.
        """
        out: dict[str, Any] = {
            "role": "assistant",
            "content": raw_message.get("content", "") or "",
        }
        tcs = raw_message.get("tool_calls")
        if tcs:
            out["tool_calls"] = tcs
        return out
