# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

kube2docs — a Python CLI that crawls a Kubernetes cluster and produces structured operational knowledge (JSON profiles, dependency graphs), with optional AI-powered documentation generation.

## Commands

```bash
# Install (editable, with dev deps)
uv pip install -e ".[dev]"

# Run tests
python -m pytest
python -m pytest tests/test_schemas.py -v                              # one file
python -m pytest tests/test_schemas.py::TestContainerInfo::test_create_minimal -v  # one test

# Lint, format & type check
ruff check src/
ruff format src/
mypy src/kube2docs/

# CLI entry point (after install)
kube2docs scan --kubeconfig ~/.kube/config --output ./kb/
kube2docs generate --input ./kb/ --output ./docs/ --model openrouter/anthropic/claude-haiku-4-5

# Scan modes (single --mode flag — one combination on the (exec, image, LLM) axis)
kube2docs scan --output ./kb/ --mode survey    # K8s API only
kube2docs scan --output ./kb/ --mode image     # image-layer inspection, no pod exec
kube2docs scan --output ./kb/ --mode exec      # pod exec only, no registry calls (air-gapped)
kube2docs scan --output ./kb/ --mode deep      # exec + image inspection [default]
kube2docs scan --output ./kb/ --mode agentic \
  --model openrouter/moonshotai/kimi-k2.5 --api-key $OPENROUTER_API_KEY
```

## Output Directories

`kb/`, `docs/`, and `output/` are gitignored scan/generation output directories. They may be absent or empty in a fresh clone.

## AI Provider Configuration

The `generate` command uses litellm, supporting multiple backends. Set the appropriate env var (see `.env.example`):
- `ANTHROPIC_API_KEY` — Anthropic native
- `OPENAI_API_KEY` — OpenAI
- `OLLAMA_API_BASE` — local Ollama

Or pass `--api-key` on the CLI.

## Architecture

Pipeline with a default boundary: **scanning is deterministic (no AI), generation uses AI**. The `--mode=agentic` option replaces the deterministic exec path with an LLM-driven one.

### Scanning decision tree

Phase 1 (survey) always runs. The second stage is selected by a **single `--mode` flag** with four values on one axis from shallow to deepest:

| Mode | Flag | Access required | Fact category | Confidence |
|---|---|---|---|---|
| Survey | `--mode=survey` | K8s API read | declared state | 0.3 |
| Image inspect | `--mode=image` | K8s API read + registry HTTPS egress | packaged state | 0.5 |
| Exec only | `--mode=exec` | K8s API read + `pods/exec` | runtime state | 0.7 |
| Deep (default) | `--mode=deep` | K8s API read + `pods/exec` + registry egress | runtime + packaged | 0.7 |
| Agentic | `--mode=agentic` + `--model` | deep + external LLM API | runtime + LLM reasoning | 0.9 |

Confidence numbers are calibrated for questions about **live runtime state**. For questions about *what is installed in the image*, image inspection is categorically stronger than exec (it reads the full package database; `ps` only shows what is currently running). The five modes are not "more" or "less" of the same thing — they observe different fact categories.

Pick the mode from the environment's operational constraint:
- **No `pods/exec` RBAC** → `--mode=image`
- **Air-gapped cluster (no registry egress)** → `--mode=exec`
- **Distroless containers in a mixed cluster** → `--mode=deep` (image inspection captures them) or `--mode=image` for the whole scan
- **Deep discovery, LLM budget available** → `--mode=agentic`
- **Quick cluster overview** → `--mode=survey`

### Phase modules
1. **Survey** (`phases/survey.py`) — read-only K8s API inventory; Deployments, StatefulSets, DaemonSets, CronJobs, Jobs, Pods, Services, Ingresses, NetworkPolicies, ConfigMaps, Secrets, ServiceAccounts, Roles, RoleBindings. Always runs. Emits per-workload JSON profiles at confidence 0.3.
2. **Deep inspect** (`phases/deep_inspect.py`) — `run_deep_inspect` for `--mode=deep`: execs discovery commands (`ps`, `ss`, `/proc/1/environ`, `df`, config dirs) into every container, and runs `ImageInspectionTracker.inspect()` for every container alongside. Regex parsing via `ai/extractor.py`. Bumps confidence to 0.7 (or 0.5 if every container fell back to image analysis only).
3. **Image inspect** (`phases/image_inspect.py` + `run_image_only_inspect` in `deep_inspect.py`) — OCI Distribution Spec API client. Pulls image manifest + config blob, scans small filesystem layers for Alpine/Debian package databases. Never execs. Invoked directly via `--mode=image`, and also triangulated within `--mode=deep` and `--mode=agentic`.
4. **Agentic** (`phases/agentic.py`) — LLM iteratively decides what commands to exec, interprets results, emits structured profile updates. Replaces the deep-inspect exec path; still runs image-layer inspection per container. Confidence 0.9. Requires `--model` and `--api-key`.
5. **Incremental rescanning** — `knowledge/fingerprint.py` tracks image digests and config versions; all modes skip unchanged workloads unless `--force-rescan`.

### Triangulation: deep/agentic always run image inspection

In `--depth=deep` (default) and `--agentic` modes, OCI image-layer inspection runs for every container alongside exec. Because exec and image inspection observe different fact categories (runtime state vs packaged state), running both **triangulates** rather than duplicates. Facts neither mode can find alone:
- Package installed in image but not currently running → unused attack surface
- Process running but not in the image's package DB → injected at runtime (supply-chain red flag)
- Env var defined at runtime but not baked in → added by the orchestrator

There is no flag to disable this — it just works. If the image registry is unreachable (air-gapped cluster, DNS failure, network policy block, private registry without credentials), the scan emits a **one-off warning per unreachable registry** via `ImageInspectionTracker` in `phases/image_inspect.py` and continues with exec-only data. The scan never fails because of image inspection.

### What NOT to hybridize

Do not mix the deterministic deep-inspect phase with the agentic phase — they both exec into pods using different discovery strategies, and mixing them would double cost without adding information. Pick one or the other. The triangulation rule applies only to the image-inspection tier, which is categorically different.

### Documentation generation (`kube2docs generate`)
`ai/writer.py` reads scan output, sends structured data to an LLM via `ai/provider.py` (litellm wrapper), produces Markdown docs. `--recommendations` generates separate recommendation files.

### Key modules
- `cli.py` — Click commands (entry point: `kube2docs.cli:main`)
- `scanner.py` — orchestrates phases, wires dependencies
- `knowledge/schemas.py` — Pydantic models for all data structures
- `knowledge/store.py` — JSON file I/O
- `kube/client.py` — wraps official K8s Python client
- `kube/exec.py` — pod command execution with shell detection and timeouts
- `security/hasher.py` — SHA-256 hashing for sensitive values (passwords, tokens, keys)
- `progress/tracker.py` — status JSON + rich terminal output
- `phases/agentic.py` — Phase 3 agentic scan; multi-turn LLM conversation loop with command safety validation (`_is_safe_command`) and artifact storage in `{workload}.raw/agentic/`

## Code Conventions

- Python 3.12+ syntax: `list[str]`, `dict[str, int]`, `X | None` unions
- Line length: 120
- Ruff rules: E, F, I, N, W, UP, B, SIM
- MyPy strict mode
- Every module uses `logger = logging.getLogger(__name__)`
- Pydantic BaseModel for all data schemas; `Literal` for constrained strings; `Field(default_factory=...)` for mutable defaults
- Tests use pytest classes with `tmp_path` fixture for temp directories
