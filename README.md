# kube2docs

[![CI](https://github.com/matt-szymczyk/kube2docs/actions/workflows/ci.yml/badge.svg)](https://github.com/matt-szymczyk/kube2docs/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/kube2docs)](https://pypi.org/project/kube2docs/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Reverse-engineer a Kubernetes cluster: crawl every workload, discover what it does at runtime, build a dependency graph, and generate operational documentation.

Two-step pipeline:

1. **`scan`** — crawls the cluster, execs into pods, builds a structured JSON knowledge base
2. **`generate`** — turns that knowledge base into Markdown docs (uses an LLM)

Optimized for **non-production clusters** where you need to document what's running but can't rely on live traffic to map dependencies.

## Install

```bash
pip install kube2docs

# From source
uv venv && uv pip install -e ".[dev]"
```

## Quickstart

```bash
# Scan the cluster
kube2docs scan --output ./kb/

# Generate docs
export OPENROUTER_API_KEY=...
kube2docs generate --input ./kb/ --output ./docs/ \
  --model openrouter/anthropic/claude-haiku-4-5 --recommendations
```

## How scanning works

Scanning always starts with a read-only inventory via the Kubernetes API: every Deployment, StatefulSet, Service, ConfigMap, etc. is catalogued. Then for each workload, `kube2docs` picks one running pod and **execs into it** to discover runtime state — what processes are running, which ports are open, what config files exist, where outbound connections go.

You pick **how** that runtime discovery happens:

| Mode | Flag | Cost | Best for |
|---|---|---|---|
| **Inventory only** | `--depth survey` | Free | Quick listing — no pod exec |
| **Deterministic** (default) | — | Free | Regulated envs, CI drift detection, nightly rescans |
| **Agentic** | `--agentic` | ~$0.003/workload | Distroless containers, dependency discovery, initial exploration |

**Deterministic** runs a fixed set of commands (`ps`, `ss`, `cat` known config paths) in every container and parses output with regex. Reproducible, data stays local.

**Agentic** hands the inventory data to an LLM, which iteratively chooses commands to exec based on what it learns from each step. Works on distroless containers (by reading image metadata when there's no shell), and discovers ~5x more dependencies in testing because it actually reads and understands config files. Non-deterministic; sends exec output (with secrets redacted) to the LLM provider.

```bash
# Preview what would be scanned and estimated cost
kube2docs scan --output ./kb/ --agentic \
  --model openrouter/moonshotai/kimi-k2.5 --dry-run

# Run the agentic scan
kube2docs scan --output ./kb/ --agentic \
  --model openrouter/moonshotai/kimi-k2.5 --api-key $OPENROUTER_API_KEY
```

## Output

The `scan` command writes to `--output`:

```
kb/
├── cluster-overview.json      # Cluster summary + dependency list
├── dependency-graph.json      # Edges between workloads (internal + external)
├── topology.mmd               # Mermaid diagram, auto-embedded in generated docs
├── services.json              # All K8s Services
├── nodes.json                 # Node info
├── events.json                # Recent cluster events (last 24h)
├── kube2docs-status.json       # Scan progress
└── <namespace>/
    ├── <workload>.profile.json     # Structured workload record
    └── <workload>.raw/             # Raw exec outputs, config files
        └── agentic/                # LLM conversation artifacts (if --agentic)
```

The JSON is the source of truth. Designed to be consumed by AI agents, RAG pipelines, or read directly.

## What agentic scan won't do

Agentic mode runs LLM-chosen commands inside your pods. The safety filter blocks:

- **Writes** (`rm`, `chmod`, `chown`, `mv`, `sed -i`, `> /path`)
- **Process control** (`kill`, `systemctl stop`, `shutdown`)
- **Outbound network** to non-localhost (prevents data exfiltration)
- **Cluster API access** (`kubectl`, `helm`, service account token reads)
- **Package installation** (`apt/yum/apk/pip/npm install`)

Reads are broad: `cat`, `find`, `grep`, `ps`, `ss`, `strings`, etc. — the LLM has whatever filesystem access the pod's user already has. Secret patterns (JWTs, AWS keys, PEM private keys, URI credentials) are detected and hashed before leaving the local process.

Important: agentic scan sends exec output to the LLM provider you configured. Use `--agentic` only on clusters where that's acceptable.

## RBAC / Permissions

kube2docs needs read-only access to cluster resources plus `pods/exec` for runtime inspection. Here's a minimal ClusterRole:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: kube2docs-reader
rules:
  - apiGroups: [""]
    resources: [namespaces, pods, services, configmaps, secrets, persistentvolumeclaims, events, nodes]
    verbs: [get, list]
  - apiGroups: [""]
    resources: [pods/exec]
    verbs: [create]
  - apiGroups: [apps]
    resources: [deployments, statefulsets, daemonsets]
    verbs: [get, list]
  - apiGroups: [batch]
    resources: [cronjobs, jobs]
    verbs: [get, list]
  - apiGroups: [networking.k8s.io]
    resources: [ingresses, networkpolicies]
    verbs: [get, list]
  - apiGroups: [autoscaling]
    resources: [horizontalpodautoscalers]
    verbs: [get, list]
  - apiGroups: [policy]
    resources: [poddisruptionbudgets]
    verbs: [get, list]
```

Bind it to a ServiceAccount or your user. Agentic mode (`--agentic`) uses the same `pods/exec` permission — no additional K8s access is needed.

Secret values are never stored: only key names are inventoried, and any secret patterns in exec output are hashed before being written to disk.

## Incremental scanning

Re-running `scan` on the same `--output` directory skips unchanged workloads by comparing image digests and config versions. Use `--force-rescan` to override.

## Documentation

See [CLAUDE.md](CLAUDE.md) for architecture details.
