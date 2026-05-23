"""STIX 2.1 input/output and the mutable enrichment session.

The agent doesn't manipulate STIX objects directly through the LLM. Instead,
it calls *tools* (see tools.py) that read from and write to an EnrichmentSession.
This separation keeps the LLM focused on decisions and ensures every STIX
object that ends up in the output bundle was created by validated code paths
rather than free-form LLM text.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from stix2 import (
    AttackPattern,
    Bundle,
    ExternalReference,
    Relationship,
    ThreatActor,
    parse,
)


# ──────────────────────────────────────────────────────────────────────────
# Bundle I/O
# ──────────────────────────────────────────────────────────────────────────


def load_bundle(path: Path) -> Bundle:
    """Load a STIX 2.1 bundle from a JSON file."""
    with path.open("r", encoding="utf-8") as f:
        text = f.read()
    return parse(text, allow_custom=True)


def save_bundle(bundle: Bundle, path: Path) -> None:
    """Write a STIX 2.1 bundle to a JSON file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        f.write(bundle.serialize(pretty=True))


def summarize_bundle(bundle: Bundle) -> str:
    """Produce a compact textual summary of a bundle for the LLM prompt.

    The summary deliberately avoids full STIX JSON — LLMs perform much better
    with structured prose than with raw JSON dumps in the prompt.
    """
    lines: list[str] = []
    lines.append(f"Bundle id: {bundle.id}")
    lines.append(f"Object count: {len(bundle.objects)}")
    lines.append("")
    lines.append("Objects:")

    for obj in bundle.objects:
        otype = obj.get("type")
        oid = obj.get("id")
        if otype == "indicator":
            lines.append(f"  - {oid}")
            lines.append(f"      type: indicator")
            lines.append(f"      name: {obj.get('name', '(unnamed)')}")
            lines.append(f"      description: {obj.get('description', '(none)')}")
            lines.append(f"      pattern: {obj.get('pattern', '(none)')}")
            types = obj.get("indicator_types", [])
            if types:
                lines.append(f"      indicator_types: {', '.join(types)}")
        elif otype == "observed-data":
            lines.append(f"  - {oid}")
            lines.append(f"      type: observed-data")
            refs = obj.get("object_refs", [])
            lines.append(f"      object_refs: {', '.join(refs) if refs else '(none)'}")
        elif otype == "url":
            lines.append(f"  - {oid}")
            lines.append(f"      type: url")
            lines.append(f"      value: {obj.get('value')}")
        elif otype == "identity":
            lines.append(f"  - {oid}")
            lines.append(f"      type: identity")
            lines.append(f"      name: {obj.get('name')}")
            sectors = obj.get("sectors", [])
            if sectors:
                lines.append(f"      sectors: {', '.join(sectors)}")
        else:
            # Generic catch-all so the agent sees that the object exists
            lines.append(f"  - {oid}")
            lines.append(f"      type: {otype}")

    return "\n".join(lines)


# ──────────────────────────────────────────────────────────────────────────
# Enrichment Session
# ──────────────────────────────────────────────────────────────────────────


@dataclass
class EnrichmentSession:
    """Mutable working state during agent enrichment.

    The agent acts on this through tool calls. Original bundle objects are
    preserved; new SDOs and SROs are appended.
    """

    original_bundle: Bundle
    added_objects: list[Any] = field(default_factory=list)

    @property
    def all_objects(self) -> list[Any]:
        return list(self.original_bundle.objects) + list(self.added_objects)

    @property
    def all_object_ids(self) -> list[str]:
        return [o.get("id") for o in self.all_objects if o.get("id")]

    def add_attack_pattern(
        self, name: str, mitre_id: str, description: str
    ) -> str:
        """Append a STIX attack-pattern SDO; return its id."""
        ap = AttackPattern(
            name=name,
            description=description,
            external_references=[
                ExternalReference(
                    source_name="mitre-attack",
                    external_id=mitre_id,
                )
            ],
            allow_custom=True,
        )
        self.added_objects.append(ap)
        return ap.id

    def add_threat_actor(
        self,
        name: str,
        description: str,
        sophistication: str = "intermediate",
        primary_motivation: str = "unknown",
        aliases: list[str] | None = None,
    ) -> str:
        """Append a STIX threat-actor SDO; return its id."""
        kwargs: dict[str, Any] = {
            "name": name,
            "description": description,
            "sophistication": sophistication,
            "primary_motivation": primary_motivation,
            "threat_actor_types": ["nation-state"]
            if "state" in primary_motivation
            else ["criminal"],
        }
        if aliases:
            kwargs["aliases"] = aliases
        ta = ThreatActor(allow_custom=True, **kwargs)
        self.added_objects.append(ta)
        return ta.id

    def add_relationship(
        self,
        source_ref: str,
        target_ref: str,
        relationship_type: str,
        description: str | None = None,
    ) -> str:
        """Append a STIX relationship SRO; return its id.

        Validates that source_ref and target_ref both refer to objects we know.
        """
        known_ids = set(self.all_object_ids)
        if source_ref not in known_ids:
            raise ValueError(
                f"source_ref {source_ref} not found in bundle. "
                f"Known ids: {sorted(known_ids)}"
            )
        if target_ref not in known_ids:
            raise ValueError(
                f"target_ref {target_ref} not found in bundle. "
                f"Known ids: {sorted(known_ids)}"
            )

        kwargs: dict[str, Any] = {
            "source_ref": source_ref,
            "target_ref": target_ref,
            "relationship_type": relationship_type,
        }
        if description:
            kwargs["description"] = description
        rel = Relationship(allow_custom=True, **kwargs)
        self.added_objects.append(rel)
        return rel.id

    def to_bundle(self) -> Bundle:
        """Build the final enriched bundle (originals + additions)."""
        return Bundle(objects=self.all_objects, allow_custom=True)

    def summary(self) -> str:
        """Brief human-readable summary of additions so far."""
        if not self.added_objects:
            return "No enrichments added yet."
        lines = [f"Enrichments added so far ({len(self.added_objects)}):"]
        for obj in self.added_objects:
            otype = obj.get("type")
            if otype == "attack-pattern":
                refs = obj.get("external_references", [])
                mitre = next(
                    (r.get("external_id") for r in refs if r.get("source_name") == "mitre-attack"),
                    "?",
                )
                lines.append(f"  - attack-pattern: {obj.get('name')} ({mitre})")
            elif otype == "threat-actor":
                lines.append(f"  - threat-actor: {obj.get('name')}")
            elif otype == "relationship":
                lines.append(
                    f"  - relationship: {obj.get('source_ref')} "
                    f"--[{obj.get('relationship_type')}]--> {obj.get('target_ref')}"
                )
        return "\n".join(lines)
