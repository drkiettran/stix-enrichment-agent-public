# Running on macOS

The Python code in this project is OS-agnostic — paths use `pathlib`, no Windows-only libraries, no platform checks. The original README targets Windows; this document captures the macOS equivalents plus practical findings from actually running the agent on Apple Silicon.

Tested on: Apple Silicon Mac mini, macOS, zsh. Intel Macs should work identically except for the Homebrew prefix (`/usr/local` instead of `/opt/homebrew`).

---

## Prerequisites

Homebrew installed and on PATH. If `brew --version` doesn't work, install it from https://brew.sh first.

## 1. Install Python 3.11+

```bash
brew install python@3.11
```

Homebrew installs `python3.11` to `/opt/homebrew/bin/python3.11` (Apple Silicon) or `/usr/local/bin/python3.11` (Intel). It deliberately does NOT create an unversioned `python` symlink on PATH — use `python3.11` for the venv setup step below. Inside the activated venv, `python` and `pip` work normally.

If `python3.11 --version` returns "command not found", Homebrew's shell init isn't loaded. Fix once with:

```bash
echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zshrc
source ~/.zshrc
```

## 2. Install Ollama

```bash
brew install --cask ollama
```

Or download the `.dmg` from https://ollama.com/download/mac and drag to Applications.

Launch the Ollama app once from Applications so the background service starts — you'll see a llama icon in the menu bar. Confirm it's reachable:

```bash
ollama list
```

If `ollama list` errors with a connection refused, the background service isn't running. Open the app from Applications.

## 3. Pick a model — this matters

The Windows README defaults to `llama3.2:3b` and suggests `llama3.1:8b` for better reasoning. In practice both Llama variants fail at the ReAct tool-calling loop this project requires — they intermittently emit tool calls as JSON inside `content` instead of using Ollama's native `tool_calls` protocol, which causes the agent loop to terminate early with zero enrichments.

**Use Qwen 2.5 instead.** It's specifically tuned for native tool calling and runs the full agent loop reliably on Apple Silicon:

```bash
ollama pull qwen2.5:7b    # ~4.7 GB on disk, needs ~8 GB free unified memory
# or, if you're on an 8 GB Mac:
ollama pull qwen2.5:3b
```

Observed results on `samples/thin_bundle.json`:

| Model         | Result                                                              |
|---------------|---------------------------------------------------------------------|
| `llama3.1:8b` | Emitted tool call as text in step 2 → terminated, 0 enrichments     |
| `llama3.2:3b` | Called lookup with empty query, then collapsed to text emission → 0 |
| `qwen2.5:7b`  | Full multi-step loop, valid enrichments, clean completion           |

## 4. Set up the Python environment

```bash
cd path/to/stix-enrichment-agent-public
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Edit `.env` and change the model line:

```
OLLAMA_MODEL=qwen2.5:7b
```

Note: a bare `OLLAMA_MODEL=qwen2.5:7b` line in zsh does NOT export the variable for subsequent commands — it just evaporates. Either edit `.env` (preferred, since `python-dotenv` reads it on startup), or prefix your invocation: `OLLAMA_MODEL=qwen2.5:7b python -m ...`. If you do edit `.env`, make sure there isn't a stale duplicate `OLLAMA_MODEL` line above the one you want — `python-dotenv` uses the first one it sees.

## 5. Smoke test (no LLM needed)

Validates plumbing with a scripted fake LLM. Good first sanity check before involving Ollama:

```bash
python smoke_test.py
```

Expect output ending in `✔ Smoke test passed.`

## 6. Run the agent for real

The Windows README's one-shot example uses a positional argument that no longer matches `cli.py`. The correct invocation uses `--input` and `--output` flags:

```bash
python -m enrichment_agent.cli enrich \
  --input ./samples/thin_bundle.json \
  --output ./outbox/thin_bundle.enriched.json
```

Watch mode is unchanged:

```bash
python -m enrichment_agent.cli watch
```

Inspect the enriched bundle:

```bash
python -m json.tool outbox/thin_bundle.enriched.json | less
```

## What to expect from the real loop

With Qwen 2.5:7b, expect 3–8 trace steps producing 2–4 enrichments per bundle:

- A lookup against the mock MITRE catalog (`mitre_attack_lookup`)
- One or more `add_attack_pattern` calls
- An `add_relationship` linking the original indicator to the new attack-pattern
- An `assess_completeness` self-check
- A final summary

Two of the README's documented "Known limitations" show up reliably in practice:

- **Hallucinated STIX ids.** The model sometimes calls `add_relationship` with a `target_ref` it invented rather than the id returned by the prior `add_attack_pattern`. The validated-mutation layer rejects it with an error listing valid ids, and the model usually recovers on the next step. This is the architecture working as designed.
- **Duplicate attack-patterns.** The model may add the same MITRE technique twice. The duplicate is wired to nothing, so it's harmless in the output but visible in the bundle.

## Other repo notes (not macOS-specific)

- `generate_samples.py` is referenced in the main README but is not in the repo. Skip that step or use the included `samples/thin_bundle.json`.
- The main README's one-shot `enrich` example uses positional args; current `cli.py` requires `--input` and `--output` flags.

## Differences from the Windows README at a glance

| Step               | Windows                                | macOS                                       |
|--------------------|----------------------------------------|---------------------------------------------|
| Install Python     | `winget install Python.Python.3.11`    | `brew install python@3.11`                  |
| Install Ollama     | `.exe` from ollama.com                 | `brew install --cask ollama`                |
| Create venv        | `python -m venv .venv`                 | `python3.11 -m venv .venv`                  |
| Activate venv      | `.\.venv\Scripts\Activate.ps1`         | `source .venv/bin/activate`                 |
| Copy env file      | `Copy-Item .env.example .env`          | `cp .env.example .env`                      |
| Path separators    | `.\samples\thin_bundle.json`           | `./samples/thin_bundle.json`                |
| Recommended model  | `llama3.2:3b` (per README)             | `qwen2.5:7b` (Llama variants fail loop)     |

The Python code itself requires zero changes.
