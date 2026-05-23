"""STIX 2.1 Submission Enrichment Agent.

A reference implementation of an agentic AI system that enriches thin STIX 2.1
threat intelligence bundles with MITRE ATT&CK techniques, threat actor
attribution, and supporting context — using a ReAct-style reasoning loop with
local LLM inference (Ollama).

Designed to integrate with any upstream STIX 2.1 producer via a
file-based inbox/outbox pattern.
"""

__version__ = "0.1.0"
