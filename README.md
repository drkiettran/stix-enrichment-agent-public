# STIX 2.1 Threat Intel Enrichment Agent

A working prototype of an **agentic AI service** that enriches thin STIX 2.1
threat intelligence bundles. The agent watches an inbox directory for thin
STIX bundles, reasons about what enrichment is appropriate, calls tools to
look up MITRE ATT&CK techniques and threat actor context, mutates a working
bundle, and writes the enriched result to an outbox. All inference is local
via Ollama — no external AI API calls.

> **Platform.** This edition targets **Windows 10 / 11** with native
> Python 3 and **Ollama for Windows**. The Python code itself is
> OS-agnostic (all paths use `pathlib`) — only the install steps and
> shell examples differ from a Linux setup.

---

## What this demonstrates

- **Genuine agency.** The LLM decides which lookup tools to call, when to
  commit enrichments, when to stop, and how to link new objects to
  originals. This is not a workflow with predetermined steps.
- **ReAct-style loop with native tool calling.** Built on Ollama's
  OpenAI-compatible tools API. Compatible with the broader MCP / tool-use
  ecosystem.
- **Two-tier tool design.** Read-only lookup tools (research) plus
  mutation tools (action) — the architectural lever that lets you govern
  what the LLM can actually do versus what it can merely propose.
- **Validated mutations.** Every change to the bundle goes through typed
  Python that validates references, generates valid STIX 2.1, and
  prevents dangling SROs. The LLM cannot hallucinate STIX object ids.
- **Visible trace.** Every (thought, action, observation) tuple is
  emitted to a Rich console panel — usable as an audit artifact.
- **File-based integration.** An upstream STIX producer drops bundles
  into `inbox\`; the agent picks them up, enriches, and writes to
  `outbox\`. Polyglot, decoupled, no API contract to negotiate.
- **Local LLM only.** Ollama with a small tool-capable model
  (configurable). Same pattern useful for self-hosted enterprise
  deployments where external AI APIs aren't reachable.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│  Upstream STIX Producer   →   inbox\   →   Enrichment Agent (Python) │
│                                                │                     │
│                                                ▼                     │
│                                            outbox\  →  downstream    │
└──────────────────────────────────────────────────────────────────────┘
```

See `architecture.puml` for the full C4 Container-level diagram.

### Tools the agent can call

**Lookup (read-only):**
- `mitre_attack_lookup(query)` — search the mock ATT&CK catalog
- `threat_actor_search(query)` — search the mock threat-actor catalog
- `related_intel_search(query)` — search related intel context

**Mutate (write to the working bundle):**
- `add_attack_pattern(name, mitre_id, description)`
- `add_threat_actor(name, description, sophistication, primary_motivation, aliases)`
- `add_relationship(source_ref, target_ref, relationship_type, description)`

**Reflect:**
- `assess_completeness()` — self-check signal for the agent to decide whether to stop

---

## Setup (Windows 10 / 11 + PowerShell)

### 1. Install Python 3.11+

Download from https://python.org or use winget:

```powershell
winget install Python.Python.3.11
```

### 2. Install Ollama for Windows

Download from https://ollama.com/download and install. Then pull a
tool-capable model:

```powershell
ollama pull llama3.2:3b      # smaller, faster — recommended for first run
ollama pull llama3.1:8b      # better reasoning — needs ~8 GB free VRAM/RAM
```

Verify Ollama is running:

```powershell
ollama list
```

### 3. Set up the Python environment

```powershell
cd path\to\stix-enrichment-agent
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

If PowerShell blocks the activate script, run once per session:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
```

### 4. Configure

Copy `.env.example` to `.env` and adjust if needed:

```powershell
Copy-Item .env.example .env
notepad .env
```

Defaults work for most setups. Tune `OLLAMA_MODEL` and `MAX_AGENT_STEPS`
to taste.

---

## Running

### One-shot enrichment

```powershell
python -m enrichment_agent.cli enrich .\samples\thin_bundle.json
```

Writes the enriched bundle to `outbox\<input-name>.enriched.json` and
prints the full agent trace to the console.

### Watch mode

```powershell
python -m enrichment_agent.cli watch
```

Watches `inbox\` for new `.json` files. On creation, kicks off the
enrichment loop. On success, moves the original to `inbox\processed\`
and writes enriched output to `outbox\`.

### Generate synthetic samples

```powershell
python generate_samples.py --count 20 --out .\inbox
```

Produces parameterized thin STIX 2.1 bundles covering ten scenarios
(phishing, ransomware, brute force, C2 traffic, suspicious domain,
exploit attempt, etc.).

### Smoke test (no LLM required)

```powershell
python smoke_test.py
```

Runs an end-to-end enrichment with a scripted fake LLM client.
Validates plumbing without needing Ollama.

---

## Project structure

```
stix-enrichment-agent\
├── README.md              # this file
├── architecture.puml      # C4 Container diagram of this prototype
├── requirements.txt
├── .env.example           # config template
├── smoke_test.py          # end-to-end test with scripted fake LLM
├── samples\
│   └── thin_bundle.json   # sample input
├── inbox\                 # drop bundles here (watch mode)
│   └── processed\         # successfully processed bundles move here
├── outbox\                # enriched bundles land here
├── data\mock\
│   ├── attack_techniques.json
│   ├── threat_actors.json
│   └── related_intel.json
└── enrichment_agent\
    ├── __init__.py
    ├── config.py          # env-driven config
    ├── llm.py             # Ollama wrapper
    ├── stix_io.py         # STIX I/O + EnrichmentSession (mutable working state)
    ├── tools.py           # lookup + mutation tools, + JSON schema definitions
    ├── trace.py           # rich-console trace logger
    ├── agent.py           # the ReAct loop
    └── cli.py             # one-shot + watch mode entry points
```

---

## Known limitations and design tradeoffs

- **Attribution risk.** The agent will sometimes attempt to attribute
  to a threat actor on weak evidence. The system prompt warns against
  this; production use would want a confidence threshold and
  human-review escalation rather than autonomous attribution.

- **Context window drift on long loops.** Repeated tool calls accumulate
  context. The current implementation keeps everything; a production
  version would summarize older observations.

- **Smaller model unreliability.** `llama3.2:3b` is faster but more
  prone to tool-format mistakes and hallucinated IDs than `llama3.1:8b`.
  Real production would land on a model size that balances reliability
  with serving cost.

### Where you'd take this next

- **Better tool validation.** Reject `add_attack_pattern` calls with
  MITRE IDs that didn't appear in a recent `mitre_attack_lookup` result.
- **Confidence propagation.** Threat actor attribution should carry a
  confidence score; relationships should reflect uncertainty.
- **Prompt-as-code discipline.** Put the system prompt in a versioned
  file with eval-suite gating before promotion.
- **Eval harness.** Build a set of golden thin bundles with expected
  enrichments; LLM-as-judge scoring against the golden set; regression
  on every prompt or model change.
- **Guardrails layer.** Input filtering (strip PII), output validation
  (validate STIX 2.1 schema), action authorization (human-in-the-loop
  for threat-actor SDOs above a confidence threshold).
- **Real ATT&CK data.** Replace the mock with the actual MITRE ATT&CK
  STIX 2.1 distribution.
- **MCP wrapping.** Expose the tools via MCP so other agents can also
  use the enrichment capabilities.

---

## License

MIT — see LICENSE file (add one if you intend to redistribute).

---

*Proof-of-concept. Not production-grade. Bring your own threat intel.*
