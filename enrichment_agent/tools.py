"""Tools the enrichment agent can call.

Two categories:

    LOOKUP TOOLS (read-only):
        - mitre_attack_lookup
        - threat_actor_search
        - related_intel_search

    MUTATION TOOLS (modify the EnrichmentSession):
        - add_attack_pattern
        - add_threat_actor
        - add_relationship
        - assess_completeness  (read-only but signals intent to stop)

The split is deliberate. Lookup tools let the agent gather evidence; mutation
tools let the agent commit decisions to the working bundle. This is the
architectural lever for governance — every change to the bundle is mediated
by typed code, not by free-form LLM output.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from .stix_io import EnrichmentSession


# ──────────────────────────────────────────────────────────────────────────
# Tool implementations
# ──────────────────────────────────────────────────────────────────────────


class Tools:
    """Bundles all tool implementations and the JSON-schema definitions
    Ollama needs for native tool calling."""

    def __init__(self, mock_data_dir: Path, session: EnrichmentSession) -> None:
        self.session = session
        with (mock_data_dir / "attack_techniques.json").open() as f:
            self._techniques = json.load(f)["techniques"]
        with (mock_data_dir / "threat_actors.json").open() as f:
            self._actors = json.load(f)["actors"]
        with (mock_data_dir / "related_intel.json").open() as f:
            self._intel = json.load(f)["intel_records"]

    # ── Lookup tools ─────────────────────────────────────────────────

    def mitre_attack_lookup(self, query: str) -> dict[str, Any]:
        """Search the mock MITRE ATT&CK catalog for techniques matching a
        keyword, behavior, or indicator type."""
        q = query.lower()
        matches = []
        for t in self._techniques:
            haystack = " ".join(
                [
                    t["name"].lower(),
                    t["description"].lower(),
                    " ".join(t.get("indicators", [])),
                    " ".join(t.get("tactics", [])),
                ]
            )
            if q in haystack:
                matches.append(
                    {
                        "mitre_id": t["mitre_id"],
                        "name": t["name"],
                        "description": t["description"],
                        "tactics": t.get("tactics", []),
                    }
                )
        return {"query": query, "match_count": len(matches), "matches": matches[:5]}

    def threat_actor_search(self, query: str) -> dict[str, Any]:
        """Search the mock threat-actor catalog. Query may be an indicator
        keyword, technique id, or actor name/alias."""
        q = query.lower()
        matches = []
        for a in self._actors:
            haystack = " ".join(
                [
                    a["name"].lower(),
                    " ".join(s.lower() for s in a.get("aliases", [])),
                    a["description"].lower(),
                    " ".join(a.get("associated_techniques", [])).lower(),
                    " ".join(a.get("associated_indicators", [])),
                ]
            )
            if q in haystack:
                matches.append(
                    {
                        "name": a["name"],
                        "aliases": a.get("aliases", []),
                        "description": a["description"],
                        "sophistication": a.get("sophistication"),
                        "primary_motivation": a.get("primary_motivation"),
                        "associated_techniques": a.get("associated_techniques", []),
                    }
                )
        return {"query": query, "match_count": len(matches), "matches": matches[:5]}

    def related_intel_search(self, query: str) -> dict[str, Any]:
        """Search related intelligence records for context on a pattern or
        observable type."""
        q = query.lower()
        matches = [
            {
                "indicator_pattern": r["indicator_pattern"],
                "context": r["context"],
                "common_actors": r.get("common_actors", []),
                "confidence": r.get("confidence", "medium"),
            }
            for r in self._intel
            if q in r["indicator_pattern"].lower() or q in r["context"].lower()
        ]
        return {"query": query, "match_count": len(matches), "matches": matches[:3]}

    # ── Mutation tools ───────────────────────────────────────────────

    def add_attack_pattern(
        self, name: str, mitre_id: str, description: str
    ) -> dict[str, Any]:
        """Add a STIX attack-pattern SDO to the bundle."""
        new_id = self.session.add_attack_pattern(name, mitre_id, description)
        return {"status": "added", "id": new_id, "type": "attack-pattern"}

    def add_threat_actor(
        self,
        name: str,
        description: str,
        sophistication: str = "intermediate",
        primary_motivation: str = "unknown",
        aliases: list[str] | None = None,
    ) -> dict[str, Any]:
        """Add a STIX threat-actor SDO to the bundle. USE WITH CAUTION:
        attribution is a high-stakes claim."""
        new_id = self.session.add_threat_actor(
            name=name,
            description=description,
            sophistication=sophistication,
            primary_motivation=primary_motivation,
            aliases=aliases,
        )
        return {"status": "added", "id": new_id, "type": "threat-actor"}

    def add_relationship(
        self,
        source_ref: str,
        target_ref: str,
        relationship_type: str,
        description: str | None = None,
    ) -> dict[str, Any]:
        """Add a STIX relationship (SRO) linking two existing objects."""
        try:
            new_id = self.session.add_relationship(
                source_ref=source_ref,
                target_ref=target_ref,
                relationship_type=relationship_type,
                description=description,
            )
            return {"status": "added", "id": new_id, "type": "relationship"}
        except ValueError as e:
            return {"status": "error", "error": str(e)}

    def assess_completeness(self) -> dict[str, Any]:
        """Self-assessment tool. Returns a summary of what's been added so far
        and a structural signal for the agent to decide whether to stop."""
        added = self.session.added_objects
        added_types = [obj.get("type") for obj in added]
        return {
            "additions_count": len(added),
            "additions_by_type": {
                t: added_types.count(t) for t in set(added_types)
            },
            "summary": self.session.summary(),
            "guidance": (
                "Stop if you have added at least one attack-pattern with "
                "linking relationship, OR if you've made 8+ additions, OR if "
                "no further high-confidence enrichment is supported by your "
                "lookup results. Do not over-enrich."
            ),
        }

    # ── Dispatch and definitions ─────────────────────────────────────

    def get_function_map(self) -> dict[str, Callable[..., dict[str, Any]]]:
        return {
            "mitre_attack_lookup": self.mitre_attack_lookup,
            "threat_actor_search": self.threat_actor_search,
            "related_intel_search": self.related_intel_search,
            "add_attack_pattern": self.add_attack_pattern,
            "add_threat_actor": self.add_threat_actor,
            "add_relationship": self.add_relationship,
            "assess_completeness": self.assess_completeness,
        }

    def execute(self, name: str, args: dict[str, Any]) -> str:
        """Dispatch a tool call by name. Always returns a JSON string."""
        fn = self.get_function_map().get(name)
        if fn is None:
            return json.dumps({"error": f"Unknown tool: {name}"})
        try:
            result = fn(**args)
            return json.dumps(result, default=str)
        except TypeError as e:
            return json.dumps({"error": f"Bad arguments for {name}: {e}"})
        except Exception as e:
            return json.dumps({"error": f"Tool {name} raised: {type(e).__name__}: {e}"})

    @staticmethod
    def get_definitions() -> list[dict[str, Any]]:
        """Return JSON-schema tool definitions in the OpenAI/Ollama format."""
        return [
            {
                "type": "function",
                "function": {
                    "name": "mitre_attack_lookup",
                    "description": (
                        "Search MITRE ATT&CK for techniques matching a keyword, "
                        "behavior, or indicator type (e.g., 'powershell', "
                        "'phishing', 'ransomware')."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "Keyword or behavior to search.",
                            }
                        },
                        "required": ["query"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "threat_actor_search",
                    "description": (
                        "Search threat-actor catalog. Query may be an indicator, "
                        "technique id (e.g., 'T1566'), or actor name/alias."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "query": {"type": "string"},
                        },
                        "required": ["query"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "related_intel_search",
                    "description": (
                        "Search related intelligence records for context on an "
                        "indicator pattern or observable."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "query": {"type": "string"},
                        },
                        "required": ["query"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "add_attack_pattern",
                    "description": (
                        "Add a STIX attack-pattern SDO to the bundle. Use only "
                        "after confirming the pattern via mitre_attack_lookup."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "mitre_id": {
                                "type": "string",
                                "description": "MITRE ATT&CK ID (e.g., 'T1566').",
                            },
                            "description": {"type": "string"},
                        },
                        "required": ["name", "mitre_id", "description"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "add_threat_actor",
                    "description": (
                        "Add a STIX threat-actor SDO. ATTRIBUTION IS HIGH-STAKES; "
                        "use only when threat_actor_search returns a strong match "
                        "supported by multiple indicators."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "description": {"type": "string"},
                            "sophistication": {
                                "type": "string",
                                "enum": ["minimal", "intermediate", "advanced", "expert"],
                            },
                            "primary_motivation": {"type": "string"},
                            "aliases": {
                                "type": "array",
                                "items": {"type": "string"},
                            },
                        },
                        "required": ["name", "description"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "add_relationship",
                    "description": (
                        "Add a STIX relationship (SRO) linking two existing "
                        "objects. Both source_ref and target_ref must be ids of "
                        "objects already in the bundle (originals or previously "
                        "added)."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "source_ref": {"type": "string"},
                            "target_ref": {"type": "string"},
                            "relationship_type": {
                                "type": "string",
                                "description": (
                                    "STIX relationship type, e.g., 'indicates', "
                                    "'uses', 'attributed-to'."
                                ),
                            },
                            "description": {"type": "string"},
                        },
                        "required": [
                            "source_ref",
                            "target_ref",
                            "relationship_type",
                        ],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "assess_completeness",
                    "description": (
                        "Self-assessment of enrichment progress. Call this when "
                        "you think you may be done; the response will help you "
                        "decide whether to stop."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {},
                    },
                },
            },
        ]
