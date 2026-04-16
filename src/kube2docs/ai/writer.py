"""AI-powered documentation writer.

Reads structured JSON profiles from the knowledge base and generates
Markdown documentation using an AI model for interpretation.
"""

import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from kube2docs.ai.provider import AIProvider
from kube2docs.knowledge.schemas import ClusterOverview, WorkloadProfile
from kube2docs.progress.tracker import ProgressTracker

logger = logging.getLogger(__name__)

# Max parallel AI calls. Conservative to avoid rate limits.
DEFAULT_WORKERS = 4

SYSTEM_PROMPT_DOC = """\
You are a senior platform engineer writing internal documentation for a \
Kubernetes cluster. You are given structured JSON data collected by an \
automated scanner (kube2docs). Your job is to interpret this data and \
produce clear, factual Markdown documentation.

Rules:
- Document what EXISTS, not what should change.
- Be concise and specific. No filler.
- If data is missing or confidence is low, say so rather than guessing.
- Use Markdown headers, bullet lists, and tables for readability.
- Do NOT repeat raw JSON — summarize and interpret it.
- Do NOT include recommendations, suggestions, or "you should" language.

VERIFIED vs UNVERIFIED FACTS (critical):
- Entries in network_listeners, outbound_connections, and dependency edges \
have a `verified` boolean and an `evidence` string.
- verified=true entries were observed at runtime (ss/netstat/proc). Present \
them as confirmed facts.
- verified=false entries are declared/referenced (image EXPOSE, config file \
reference, env var name pattern) — they may not reflect runtime behavior.
- In tables, add a "Verified" column or mark unverified entries with \
"(declared — may be overridden)" or "(referenced in config — not observed)" \
or "(inferred from env var name)".
- NEVER present a verified=false listener, connection, or dependency as a \
plain fact. A reader must be able to tell at a glance which is which.
- Do not invent facts beyond what the JSON contains. If a port is listed as \
unverified, say so; do not assert the workload "listens on X" as if certain.
- If ALL entries for a given section are unverified, say so explicitly: \
"The following dependencies are inferred, not observed at runtime".
"""

SYSTEM_PROMPT_REC = """\
You are a senior platform engineer reviewing a Kubernetes cluster for \
operational risks and improvements. You are given structured JSON data \
and documentation collected by an automated scanner (kube2docs). Your job \
is to identify issues and produce actionable recommendations.

Rules:
- Focus on risks, missing best practices, and concrete fixes.
- Prioritize by impact: critical issues first.
- Be specific — name the workload, the setting, the fix.
- Use Markdown headers, bullet lists, and checklists for readability.
- Do NOT repeat the documentation — reference it and add what's missing.
"""


def generate_docs(
    input_dir: Path,
    output_dir: Path,
    ai: AIProvider,
    tracker: ProgressTracker,
    instructions: str = "",
    recommendations: bool = False,
    workers: int = DEFAULT_WORKERS,
) -> None:
    """Generate documentation from a kube2docs knowledge base."""
    tracker.phase_header("Generating Documentation")

    # Load cluster data
    overview = _load_overview(input_dir)
    services = _load_json_list(input_dir / "services.json")
    deps = _load_json_list(input_dir / "dependency-graph.json")

    # Load all profiles
    profiles = _load_profiles(input_dir)
    if not profiles:
        tracker.warning("No profiles found in knowledge base")
        return

    tracker.log(f"Found {len(profiles)} workload profiles (workers={workers})")

    total = len(profiles) + 1  # workloads + overview
    if recommendations:
        total *= 2  # double for recommendation passes
    tracker.start("generate", total)

    doc_system = SYSTEM_PROMPT_DOC
    rec_system = SYSTEM_PROMPT_REC
    if instructions:
        doc_system += f"\n\nAdditional instructions from the user:\n{instructions}"
        rec_system += f"\n\nAdditional instructions from the user:\n{instructions}"

    output_dir.mkdir(parents=True, exist_ok=True)
    completed = 0

    # --- Per-workload documentation (parallel) ---
    completed += _generate_workload_docs_parallel(
        profiles,
        ai,
        doc_system,
        deps,
        input_dir,
        output_dir,
        tracker,
        workers,
    )

    # --- Cluster overview (sequential — depends on all profiles) ---
    tracker.update("cluster-overview", completed)
    overview_doc = _generate_overview_doc(overview, profiles, services, deps, ai, doc_system)
    if overview_doc:
        # Embed topology diagram (generated during scan) if available
        topology_path = input_dir / "topology.mmd"
        if topology_path.exists():
            mermaid = topology_path.read_text().strip()
            overview_doc = f"{overview_doc}\n\n## Topology Diagram\n\n```mermaid\n{mermaid}\n```\n"
        (output_dir / "cluster-overview.md").write_text(overview_doc)
        tracker.item("cluster-overview.md")
    completed += 1

    # --- Recommendations (optional, parallel) ---
    if recommendations:
        tracker.phase_header("Generating Recommendations")

        completed += _generate_workload_recs_parallel(
            profiles,
            ai,
            rec_system,
            deps,
            input_dir,
            output_dir,
            tracker,
            workers,
        )

        tracker.update("cluster-recommendations", completed)
        cluster_rec = _generate_cluster_recommendations(overview, profiles, services, deps, ai, rec_system)
        if cluster_rec:
            (output_dir / "cluster-recommendations.md").write_text(cluster_rec)
            tracker.item("cluster-recommendations.md")
        completed += 1

    tracker.log(f"AI calls used: {ai.calls_used}/{ai.max_calls}")
    tracker.update("done", completed)


# ======================================================================
# Parallel execution
# ======================================================================


def _generate_workload_docs_parallel(
    profiles: list[WorkloadProfile],
    ai: AIProvider,
    system: str,
    deps: list[Any],
    input_dir: Path,
    output_dir: Path,
    tracker: ProgressTracker,
    workers: int,
) -> int:
    """Generate per-workload docs in parallel. Returns number completed."""
    completed = 0

    with ThreadPoolExecutor(max_workers=workers) as pool:
        future_to_profile = {
            pool.submit(_generate_workload_doc, profile, ai, system, deps, input_dir): profile for profile in profiles
        }

        for future in as_completed(future_to_profile):
            profile = future_to_profile[future]
            label = f"{profile.namespace}/{profile.name}"
            try:
                doc = future.result()
                if doc:
                    ns_dir = output_dir / profile.namespace
                    ns_dir.mkdir(parents=True, exist_ok=True)
                    (ns_dir / f"{profile.name}.md").write_text(doc)
                    tracker.item(label)
                else:
                    tracker.warning(f"{label}: doc generation failed")
            except Exception as exc:
                tracker.warning(f"{label}: {exc}")
            completed += 1
            tracker.update(label, completed)

    return completed


def _generate_workload_recs_parallel(
    profiles: list[WorkloadProfile],
    ai: AIProvider,
    system: str,
    deps: list[Any],
    input_dir: Path,
    output_dir: Path,
    tracker: ProgressTracker,
    workers: int,
) -> int:
    """Generate per-workload recommendations in parallel. Returns number completed."""
    completed = 0

    with ThreadPoolExecutor(max_workers=workers) as pool:
        future_to_profile = {
            pool.submit(_generate_workload_recommendations, profile, ai, system, deps, input_dir): profile
            for profile in profiles
        }

        for future in as_completed(future_to_profile):
            profile = future_to_profile[future]
            label = f"{profile.namespace}/{profile.name}"
            try:
                rec = future.result()
                if rec:
                    ns_dir = output_dir / profile.namespace
                    ns_dir.mkdir(parents=True, exist_ok=True)
                    (ns_dir / f"{profile.name}.recommendations.md").write_text(rec)
                    tracker.item(f"{label} recommendations")
                else:
                    tracker.warning(f"{label}: recommendations generation failed")
            except Exception as exc:
                tracker.warning(f"{label} recommendations: {exc}")
            completed += 1
            tracker.update(f"{label} (recommendations)", completed)

    return completed


# ======================================================================
# Documentation generators (factual)
# ======================================================================


def _generate_workload_doc(
    profile: WorkloadProfile,
    ai: AIProvider,
    system: str,
    deps: list[Any],
    input_dir: Path,
) -> str | None:
    profile_json = profile.model_dump_json(indent=2)
    key = f"{profile.namespace}/{profile.name}"
    related_deps = [d for d in deps if d.get("source") == key or d.get("destination") == key]
    configs_section = _load_raw_configs(input_dir, profile)
    raw_section = _load_raw_outputs(input_dir, profile)

    user_prompt = f"""\
Write factual documentation for this Kubernetes workload.

## Workload Profile (JSON)
```json
{profile_json}
```

## Related Dependencies
```json
{json.dumps(related_deps, indent=2)}
```
{configs_section}{raw_section}
Generate a Markdown document with these sections:
1. **Overview** — What this workload is (1-2 sentences based on image, process info, behavior)
2. **Architecture** — Container setup, replicas, resource requests/limits
3. **Networking** — Listening ports, outbound connections, service dependencies
4. **Configuration** — Env vars (values hashed), config files, secrets. Interpret raw config contents.
5. **Health & Observability** — Health endpoints, metrics, probes configured
6. **Resilience** — PDB, anti-affinity, HPA, replica placement (state facts, not advice)

Use the workload name as the H1 header. Document what IS, not what should be."""

    return ai.complete_text(system=system, user=user_prompt, temperature=0.1)


def _generate_overview_doc(
    overview: ClusterOverview | None,
    profiles: list[WorkloadProfile],
    services: list[Any],
    deps: list[Any],
    ai: AIProvider,
    system: str,
) -> str | None:
    workload_summary = _build_workload_summary(profiles)

    user_prompt = f"""\
Write a factual cluster overview document.

## Cluster Overview
```json
{json.dumps(overview.model_dump() if overview else {}, indent=2, default=str)}
```

## Workload Summary
```json
{json.dumps(workload_summary, indent=2)}
```

## Dependency Graph
```json
{json.dumps(deps, indent=2)}
```

## Services
```json
{json.dumps(services, indent=2)}
```

Generate a Markdown document with these sections:
1. **Cluster Summary** — Namespaces, node count, workload count
2. **Workload Inventory** — Table of all workloads with type, language, replicas, ports
3. **Service Map** — How workloads connect to each other (dependency graph)

Use "Cluster Overview" as the H1 header. Document what IS, not what should be."""

    return ai.complete_text(system=system, user=user_prompt, temperature=0.1)


# ======================================================================
# Recommendation generators (advisory)
# ======================================================================


def _generate_workload_recommendations(
    profile: WorkloadProfile,
    ai: AIProvider,
    system: str,
    deps: list[Any],
    input_dir: Path,
) -> str | None:
    profile_json = profile.model_dump_json(indent=2)
    configs_section = _load_raw_configs(input_dir, profile)

    user_prompt = f"""\
Review this workload and provide operational recommendations.

## Workload Profile (JSON)
```json
{profile_json}
```
{configs_section}
Generate a Markdown document with:
1. **Critical Issues** — Things that could cause outages or data loss
2. **Best Practice Gaps** — Missing health checks, PDBs, resource limits, etc.
3. **Configuration Concerns** — Issues found in config files
4. **Action Items** — Prioritized checklist of concrete fixes

Use "{profile.name} — Recommendations" as the H1 header."""

    return ai.complete_text(system=system, user=user_prompt, temperature=0.1)


def _generate_cluster_recommendations(
    overview: ClusterOverview | None,
    profiles: list[WorkloadProfile],
    services: list[Any],
    deps: list[Any],
    ai: AIProvider,
    system: str,
) -> str | None:
    workload_summary = _build_workload_summary(profiles)

    user_prompt = f"""\
Review this cluster and provide operational recommendations.

## Cluster Overview
```json
{json.dumps(overview.model_dump() if overview else {}, indent=2, default=str)}
```

## Workload Summary
```json
{json.dumps(workload_summary, indent=2)}
```

## Dependency Graph
```json
{json.dumps(deps, indent=2)}
```

Generate a Markdown document with:
1. **Critical Issues** — Cluster-wide risks (single points of failure, missing resilience)
2. **Cross-Cutting Concerns** — Patterns affecting multiple workloads
3. **Priority Improvements** — Ordered checklist of what to fix first

Use "Cluster Recommendations" as the H1 header."""

    return ai.complete_text(system=system, user=user_prompt, temperature=0.1)


# ======================================================================
# Helpers
# ======================================================================


def _build_workload_summary(profiles: list[WorkloadProfile]) -> list[dict[str, Any]]:
    summary: list[dict[str, Any]] = []
    for p in profiles:
        proc = next((c for c in p.config_files if c.get("_type") == "process_info"), {})
        summary.append(
            {
                "name": f"{p.namespace}/{p.name}",
                "type": p.workload_type,
                "replicas": p.replicas,
                "language": proc.get("language", "unknown"),
                "ports": [
                    {"port": nl.port, "verified": nl.verified, "evidence": nl.evidence}
                    for nl in p.network_listeners
                ],
                "connections": [
                    {"destination": oc.destination, "verified": oc.verified, "evidence": oc.evidence}
                    for oc in p.outbound_connections
                ],
                "has_health_check": bool(p.health),
                "has_pdb": p.resilience.pod_disruption_budget,
                "confidence": p.confidence,
            }
        )
    return summary


def _load_overview(input_dir: Path) -> ClusterOverview | None:
    path = input_dir / "cluster-overview.json"
    if path.exists():
        try:
            return ClusterOverview(**json.loads(path.read_text()))
        except (json.JSONDecodeError, ValueError, OSError) as exc:
            logger.warning("Failed to load cluster overview from %s: %s", path, exc)
    return None


def _load_profiles(input_dir: Path) -> list[WorkloadProfile]:
    profiles: list[WorkloadProfile] = []
    for path in input_dir.rglob("*.profile.json"):
        try:
            profiles.append(WorkloadProfile(**json.loads(path.read_text())))
        except (json.JSONDecodeError, ValueError, OSError) as exc:
            logger.warning("Skipping %s: %s", path, exc)
    return profiles


def _load_raw_configs(input_dir: Path, profile: WorkloadProfile) -> str:
    """Load raw config files saved during deep inspection."""
    configs_dir = input_dir / profile.namespace / f"{profile.name}.raw" / "configs"
    if not configs_dir.exists():
        return ""

    parts: list[str] = []
    for config_file in sorted(configs_dir.iterdir()):
        if not config_file.is_file():
            continue
        content = config_file.read_text()
        original_path = "/" + config_file.name.replace("__", "/")
        if len(content) > 4000:
            logger.debug("Truncating %s from %d to 4000 chars for AI prompt", config_file.name, len(content))
            content = content[:4000] + "\n... [truncated]"
        parts.append(f"### {original_path}\n```\n{content}\n```")

    if not parts:
        return ""
    return "\n\n## Configuration Files (raw, sensitive values redacted)\n\n" + "\n\n".join(parts) + "\n"


def _load_raw_outputs(input_dir: Path, profile: WorkloadProfile) -> str:
    """Load raw exec outputs (processes, listeners, connections)."""
    raw_dir = input_dir / profile.namespace / f"{profile.name}.raw"
    if not raw_dir.exists():
        return ""

    parts: list[str] = []
    for label in ("processes", "listeners", "connections"):
        f = raw_dir / f"{label}.txt"
        if f.exists():
            content = f.read_text().strip()
            if content:
                parts.append(f"### {label}\n```\n{content}\n```")

    if not parts:
        return ""
    return "\n\n## Raw Discovery Outputs\n\n" + "\n\n".join(parts) + "\n"


def _load_json_list(path: Path) -> list[Any]:
    """Load a JSON file, returning an empty list if it doesn't exist or isn't a list."""
    if path.exists():
        try:
            data = json.loads(path.read_text())
            if isinstance(data, list):
                return data
            logger.warning("Expected a JSON list in %s, got %s", path, type(data).__name__)
        except Exception as exc:
            logger.warning("Failed to load JSON list from %s: %s", path, exc)
    return []
