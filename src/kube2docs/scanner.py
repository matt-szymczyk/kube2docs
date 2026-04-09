"""Main orchestrator — runs phases in order."""

import contextlib
import json
import logging
from pathlib import Path
from typing import Any

from kube2docs.config import ScanConfig
from kube2docs.knowledge.fingerprint import FingerprintTracker
from kube2docs.knowledge.schemas import ClusterOverview, DependencyEdge, WorkloadProfile
from kube2docs.knowledge.store import KnowledgeStore
from kube2docs.kube.client import KubeClient
from kube2docs.phases.deep_inspect import run_deep_inspect
from kube2docs.phases.survey import run_survey
from kube2docs.progress.tracker import ProgressTracker

logger = logging.getLogger(__name__)

# Destinations that represent default Kubernetes platform capabilities
# (every pod has access by default — not meaningful dependencies).
_PLATFORM_DESTINATIONS = frozenset(
    {
        "default/kubernetes",
        "kube-system/kube-dns",
        "kube-system/metrics-server",
        "kube-system/coredns",
    }
)


def run_scan(config: ScanConfig) -> None:
    """Execute the full scan pipeline."""
    output = Path(config.output)
    output.mkdir(parents=True, exist_ok=True)

    tracker = ProgressTracker(output)
    store = KnowledgeStore(output)
    fingerprints = FingerprintTracker(output)

    try:
        kube = KubeClient(kubeconfig=config.kubeconfig, context=config.context)
    except Exception as e:
        tracker.fail(f"Cannot connect to cluster: {e}")
        raise SystemExit(1) from e

    # Phase 1: Survey
    run_survey(kube, config, store, tracker, fingerprints)

    # Dry run: print what would be scanned in Phase 2/3 and exit.
    if config.dry_run:
        _print_dry_run_summary(config, store, tracker)
        tracker.complete()
        return

    # Phase 2 or Phase 3
    if config.agentic:
        # Phase 3: AI-driven agentic scan (replaces Phase 2)
        from kube2docs.ai.provider import AIProvider
        from kube2docs.phases.agentic import run_agentic_scan

        services = _load_services(store)
        ai = AIProvider(
            model=config.agentic_model or "",
            api_key=config.agentic_api_key,
            max_calls=config.agentic_max_calls,
        )
        run_agentic_scan(kube, config, store, tracker, services, fingerprints, ai)
        _merge_outbound_connections(store, tracker)
    elif config.depth == "deep":
        # Phase 2: Deterministic deep inspection
        services = _load_services(store)
        run_deep_inspect(kube, config, store, tracker, services, fingerprints)
        _merge_outbound_connections(store, tracker)

    tracker.complete()


def _print_dry_run_summary(config: ScanConfig, store: KnowledgeStore, tracker: ProgressTracker) -> None:
    """Print what would be scanned without running Phase 2 or Phase 3."""
    profiles: list[WorkloadProfile] = []
    for path in store.output_dir.rglob("*.profile.json"):
        try:
            data = json.loads(path.read_text())
            profiles.append(WorkloadProfile(**data))
        except (json.JSONDecodeError, ValueError, OSError):
            continue

    # CronJobs are skipped by both Phase 2 and Phase 3.
    scannable = [p for p in profiles if p.workload_type != "CronJob"]

    tracker.log("")
    tracker.log(
        f"Dry run — would scan {len(scannable)} workloads (skipping {len(profiles) - len(scannable)} CronJobs):"
    )
    for p in scannable:
        tracker.log(f"  - {p.namespace}/{p.name} ({p.workload_type})")

    if config.agentic:
        from kube2docs.phases.agentic import _estimate_cost

        estimate = _estimate_cost(config.agentic_model or "", len(scannable))
        tracker.log("")
        tracker.log(f"Agentic scan: model={config.agentic_model}, max budget={config.agentic_max_calls} calls")
        if estimate is not None:
            tracker.log(f"Estimated cost: ~${estimate:.3f} (at ~2 LLM rounds per workload)")
        else:
            tracker.log("Cost estimate unavailable — pricing unknown for this model")
    else:
        from kube2docs.phases.deep_inspect import _DISCOVERY_COMMANDS

        tracker.log("")
        tracker.log("Deterministic deep inspect: free (no LLM calls)")
        tracker.log("Commands that would be exec'd into each container:")
        for label, cmd in _DISCOVERY_COMMANDS:
            tracker.log(f"  [{label}] {cmd}")

    tracker.log("")
    tracker.log("Remove --dry-run to execute the scan.")


def _load_services(store: KnowledgeStore) -> list[dict[str, Any]]:
    """Load services.json written by Phase 1."""
    svc_path = store.output_dir / "services.json"
    data = store.read_json(svc_path)
    if isinstance(data, list):
        return data
    return []


def _merge_outbound_connections(store: KnowledgeStore, tracker: ProgressTracker) -> None:
    """Merge Phase 2/3 outbound connections into dependency-graph.json and cluster-overview.json."""
    # Load all updated profiles
    profiles: list[WorkloadProfile] = []
    for path in store.output_dir.rglob("*.profile.json"):
        try:
            data = json.loads(path.read_text())
            profiles.append(WorkloadProfile(**data))
        except (json.JSONDecodeError, ValueError) as exc:
            logger.warning("Failed to load profile %s: %s", path, exc)
        except OSError as exc:
            logger.warning("Failed to read profile file %s: %s", path, exc)

    # Build IP-to-service map for resolving unmatched IP destinations
    ip_to_service: dict[str, dict[str, str]] = {}
    services_raw = store.read_json(store.output_dir / "services.json")
    if isinstance(services_raw, list):
        for svc in services_raw:
            cluster_ip = svc.get("clusterIP")
            if cluster_ip and cluster_ip != "None":
                ip_to_service[cluster_ip] = {"name": svc["name"], "namespace": svc["namespace"]}

    # Load existing dependency graph
    graph_path = store.output_dir / "dependency-graph.json"
    existing_raw = store.read_json(graph_path)
    existing_edges: list[DependencyEdge] = []
    if isinstance(existing_raw, list):
        for item in existing_raw:
            with contextlib.suppress(ValueError, KeyError):
                existing_edges.append(DependencyEdge(**item))

    seen: set[str] = set()
    for edge in existing_edges:
        seen.add(f"{edge.source}->{edge.destination}:{edge.port}")

    # Build a set of known cluster workloads ("namespace/name") so we can
    # tell internal dependencies from external hostnames.
    cluster_workloads = {f"{p.namespace}/{p.name}" for p in profiles}

    new_count = 0
    skipped_platform = 0
    for profile in profiles:
        source = f"{profile.namespace}/{profile.name}"
        for conn in profile.outbound_connections:
            dest, port = _parse_connection_destination(conn.destination, ip_to_service)
            if not dest or port == 0:
                continue
            # Skip self-references
            if dest == source:
                continue
            # Skip default platform capabilities (not meaningful dependencies)
            if dest in _PLATFORM_DESTINATIONS:
                skipped_platform += 1
                continue
            edge_key = f"{source}->{dest}:{port}"
            if edge_key not in seen:
                seen.add(edge_key)
                # External if not a known cluster workload and not a "ns/name" format
                is_external = dest not in cluster_workloads and "/" not in dest
                existing_edges.append(
                    DependencyEdge(
                        source=source,
                        destination=dest,
                        port=port,
                        protocol=conn.protocol,
                        critical=conn.critical,
                        external=is_external,
                    )
                )
                new_count += 1

    # Write updated dependency graph
    store.write_json(graph_path, [e.model_dump() for e in existing_edges])

    # Update cluster-overview.json
    overview_path = store.output_dir / "cluster-overview.json"
    overview_raw = store.read_json(overview_path)
    if isinstance(overview_raw, dict):
        try:
            overview = ClusterOverview(**overview_raw)
            overview.dependencies = existing_edges
            store.write_model(overview_path, overview)
        except (json.JSONDecodeError, ValueError) as exc:
            logger.warning("Failed to update cluster-overview.json: %s", exc)

    suffix = f" (skipped {skipped_platform} platform edges)" if skipped_platform else ""
    tracker.item(
        "Dependency merge",
        f"{new_count} new edges from outbound connections (total {len(existing_edges)}){suffix}",
    )

    # Render a Mermaid topology diagram from the final edge set.
    topology = _render_mermaid_topology(existing_edges, cluster_workloads)
    (store.output_dir / "topology.mmd").write_text(topology)


def _render_mermaid_topology(edges: list[DependencyEdge], cluster_workloads: set[str]) -> str:
    """Render a Mermaid flowchart from dependency edges.

    Internal workloads are grouped by namespace. External destinations
    appear as a separate node shape.
    """
    # Group internal workloads by namespace
    by_namespace: dict[str, set[str]] = {}
    for wl in cluster_workloads:
        if "/" in wl:
            ns, name = wl.split("/", 1)
            by_namespace.setdefault(ns, set()).add(name)

    # Any destinations that are also workloads but weren't in our profile set
    # (shouldn't happen normally, but be safe)
    for edge in edges:
        if not edge.external and "/" in edge.destination:
            ns, name = edge.destination.split("/", 1)
            by_namespace.setdefault(ns, set()).add(name)

    def _node_id(label: str) -> str:
        # Mermaid IDs can't contain special chars
        return label.replace("/", "_").replace("-", "_").replace(".", "_").replace(":", "_")

    lines = ["flowchart LR"]

    # Subgraphs per namespace for internal workloads
    for ns in sorted(by_namespace):
        lines.append(f"  subgraph {_node_id(ns)}[{ns}]")
        for name in sorted(by_namespace[ns]):
            node_id = _node_id(f"{ns}/{name}")
            lines.append(f"    {node_id}[{name}]")
        lines.append("  end")

    # External nodes (collect first, dedup)
    external_nodes: set[str] = set()
    for edge in edges:
        if edge.external:
            external_nodes.add(edge.destination)
    for ext in sorted(external_nodes):
        node_id = _node_id(ext)
        lines.append(f"  {node_id}([{ext}]):::external")

    # Edges
    for edge in edges:
        src_id = _node_id(edge.source)
        dst_id = _node_id(edge.destination)
        label = f"{edge.protocol}:{edge.port}"
        lines.append(f"  {src_id} -->|{label}| {dst_id}")

    # Styling
    lines.append("  classDef external stroke:#888,stroke-dasharray:5 5,fill:#f4f4f4")

    return "\n".join(lines) + "\n"


def _parse_connection_destination(
    destination: str,
    ip_to_service: dict[str, dict[str, str]] | None = None,
) -> tuple[str, int]:
    """Parse a connection destination into (label, port).

    Handles two formats from deep_inspect (both always include :port):
      - "service_name.namespace:port" (matched service)  -> ("namespace/service_name", port)
      - "ip:port" (unmatched)                             -> resolved via ip_to_service or ("ip:port", port)

    Returns (dest_label, port). Port is 0 if it cannot be determined.
    """
    if ":" not in destination:
        return ("", 0)

    # Split off the trailing port
    base, _, port_str = destination.rpartition(":")
    try:
        port = int(port_str)
    except ValueError:
        return ("", 0)

    if not base:
        return ("", 0)

    # Matched service format: "svc_name.namespace"
    # (contains a dot but is not a bare IP — IPs have 3 dots)
    dot_count = base.count(".")
    if dot_count == 1:
        svc_name, ns = base.split(".", 1)
        return (f"{ns}/{svc_name}", port)

    # Try resolving bare IPs against the service registry
    if ip_to_service and base in ip_to_service:
        svc = ip_to_service[base]
        return (f"{svc['namespace']}/{svc['name']}", port)

    # Unmatched: bare IP or hostname — return base only (port is stored separately)
    return (base, port)
