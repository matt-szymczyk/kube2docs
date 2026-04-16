"""Phase 1: Read-only cluster inventory — no AI, no exec."""

import json
import logging
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from kubernetes.client.rest import ApiException

from kube2docs.config import PORT_PROTOCOL_MAP, SKIP_ANNOTATION, ScanConfig
from kube2docs.knowledge.fingerprint import FingerprintTracker
from kube2docs.knowledge.schemas import (
    ClusterOverview,
    ContainerInfo,
    DependencyEdge,
    EnvVar,
    RbacRule,
    RbacSummary,
    ResilienceInfo,
    VolumeInfo,
    WorkloadProfile,
)
from kube2docs.knowledge.store import KnowledgeStore
from kube2docs.kube.client import KubeClient
from kube2docs.progress.tracker import ProgressTracker
from kube2docs.security.hasher import hash_value

logger = logging.getLogger(__name__)


def _resolve_namespaces(requested: list[str], available: list[str]) -> list[str]:
    """Match requested namespaces against those available in the cluster.

    Warns about each missing namespace and exits if none match.
    """
    target: list[str] = []
    for ns in requested:
        if ns in available:
            target.append(ns)
        else:
            logger.warning("Requested namespace %r not found in cluster — skipping", ns)
    if not target:
        raise SystemExit(f"None of the requested namespaces exist: {requested}")
    return target


def run_survey(
    kube: KubeClient,
    config: ScanConfig,
    store: KnowledgeStore,
    tracker: ProgressTracker,
    fingerprints: FingerprintTracker,
) -> ClusterOverview:
    """Execute Phase 1: full read-only cluster survey."""
    tracker.phase_header("Phase 1: Cluster Survey")

    # 1. Discover namespaces
    all_ns = kube.list_namespaces()
    if config.namespaces:
        target_ns = _resolve_namespaces(config.namespaces, all_ns)
    else:
        target_ns = [ns for ns in all_ns if not config.is_namespace_excluded(ns)]

    tracker.log(f"Scanning {len(target_ns)} namespaces: {', '.join(target_ns)}")

    # 2. Collect nodes
    nodes = kube.list_nodes()
    node_info = _collect_node_info(nodes)
    tracker.item("Nodes", f"{len(nodes)} nodes")

    # 3. Per-namespace inventory
    all_profiles: list[WorkloadProfile] = []
    all_services: list[dict[str, Any]] = []
    all_dependencies: list[DependencyEdge] = []
    all_events: list[dict[str, Any]] = []
    ns_network_policies: dict[str, list[dict[str, Any]]] = {}

    # Build a global service registry for dependency resolution
    service_registry: dict[str, dict[str, Any]] = {}  # "name.namespace" -> {clusterIP, ports, selector}

    total_workloads = 0
    for ns in target_ns:
        ns_workloads = _count_workloads(kube, ns)
        total_workloads += ns_workloads

    tracker.start("survey", total_workloads)
    completed = 0

    # Collect cluster-scoped RBAC data once (ClusterRoles + ClusterRoleBindings)
    cluster_roles, crb_index = _collect_cluster_rbac(kube)
    if cluster_roles:
        logger.debug("Loaded %d ClusterRoles for RBAC analysis", len(cluster_roles))

    for ns in target_ns:
        tracker.log(f"Scanning namespace: {ns}")

        # Services
        services = kube.list_services(ns)
        for svc in services:
            svc_data = _extract_service(svc, ns)
            all_services.append(svc_data)
            dns_name = f"{svc.metadata.name}.{ns}"
            service_registry[dns_name] = svc_data
            # Also register short name for same-namespace lookups
            service_registry[svc.metadata.name] = svc_data

        tracker.item(f"{ns}/services", f"{len(services)} services")

        # Ingresses
        try:
            ingresses = kube.list_ingresses(ns)
            tracker.item(f"{ns}/ingresses", f"{len(ingresses)} ingresses")
        except ApiException as exc:
            logger.debug("Failed to list ingresses in %s: %s", ns, exc.reason)
            ingresses = []

        # Network policies
        try:
            netpols = kube.list_network_policies(ns)
            ns_network_policies[ns] = [_extract_network_policy(np) for np in netpols]
            if not netpols:
                tracker.warning(f"{ns}: no NetworkPolicies")
        except ApiException as exc:
            logger.debug("Failed to list network policies in %s: %s", ns, exc.reason)
            ns_network_policies[ns] = []

        # ConfigMaps and Secrets (for reference lookup)
        configmaps = {cm.metadata.name: cm for cm in kube.list_configmaps(ns)}
        secrets = {s.metadata.name: s for s in kube.list_secrets(ns)}

        # RBAC: namespaced Roles and RoleBindings
        ns_roles, rb_index = _collect_namespace_rbac(kube, ns)

        # PVCs
        pvcs = {pvc.metadata.name: pvc for pvc in kube.list_pvcs(ns)}

        # HPAs
        hpas = kube.list_hpas(ns)
        hpa_targets: dict[str, Any] = {}
        for hpa in hpas:
            ref = hpa.spec.scale_target_ref
            hpa_targets[f"{ref.kind}/{ref.name}"] = hpa

        # PDBs
        pdbs = kube.list_pdbs(ns)
        pdb_selectors: list[dict[str, Any]] = []
        for pdb in pdbs:
            if pdb.spec.selector and pdb.spec.selector.match_labels:
                pdb_selectors.append(pdb.spec.selector.match_labels)

        # Pods (for node placement analysis)
        pods = kube.list_pods(ns)
        pod_node_map: dict[str, list[str]] = {}  # workload-name -> [node-names]
        for pod in pods:
            owner = _get_workload_owner(pod)
            if owner:
                pod_node_map.setdefault(owner, []).append(pod.spec.node_name or "unknown")

        # Events (last 24h)
        events = kube.list_events(ns)
        cutoff = datetime.now(UTC) - timedelta(hours=24)
        for ev in events:
            ts = ev.last_timestamp or ev.event_time
            if ts and ts.replace(tzinfo=UTC) > cutoff:
                all_events.append(
                    {
                        "namespace": ns,
                        "type": ev.type,
                        "reason": ev.reason,
                        "object": f"{ev.involved_object.kind}/{ev.involved_object.name}",
                        "message": ev.message,
                        "count": ev.count,
                        "last_seen": str(ts),
                    }
                )

        # --- Workloads ---
        workload_sources = [
            ("Deployment", kube.list_deployments(ns)),
            ("StatefulSet", kube.list_statefulsets(ns)),
            ("DaemonSet", kube.list_daemonsets(ns)),
            ("CronJob", kube.list_cronjobs(ns)),
        ]

        for wl_type, items in workload_sources:
            for item in items:
                meta = item.metadata
                if _should_skip(meta):
                    tracker.log(f"Skipping {ns}/{meta.name} (skip annotation)")
                    continue

                tracker.update(f"{ns}/{meta.name}", completed)

                # Check fingerprint for incremental scanning
                current_images = _compute_image_fingerprint(item, wl_type)
                current_config_versions = _compute_config_versions(
                    item,
                    wl_type,
                    configmaps,
                    secrets,
                )

                if not config.force_rescan and not fingerprints.has_changed(
                    ns,
                    meta.name,
                    current_images,
                    current_config_versions,
                ):
                    # Workload unchanged — try to load existing profile
                    existing_path = store.namespace_dir(ns) / f"{meta.name}.profile.json"
                    if existing_path.exists():
                        try:
                            data = json.loads(existing_path.read_text())
                            profile = WorkloadProfile(**data)
                            all_profiles.append(profile)
                            completed += 1
                            tracker.log(f"{ns}/{meta.name} unchanged, skipping")
                            continue
                        except (json.JSONDecodeError, ValueError) as exc:
                            logger.debug("Failed to reload cached profile %s: %s", existing_path, exc)

                fingerprints.mark_changed(ns, meta.name)

                profile = _build_profile(
                    item=item,
                    wl_type=wl_type,
                    namespace=ns,
                    config=config,
                    configmaps=configmaps,
                    secrets=secrets,
                    pvcs=pvcs,
                    hpa_targets=hpa_targets,
                    pdb_selectors=pdb_selectors,
                    pod_node_map=pod_node_map,
                    service_registry=service_registry,
                    ns_roles=ns_roles,
                    cluster_roles=cluster_roles,
                    rb_index=rb_index,
                    crb_index=crb_index,
                )
                all_profiles.append(profile)

                # Write profile to knowledge base
                ns_dir = store.namespace_dir(ns)
                store.write_model(ns_dir / f"{meta.name}.profile.json", profile)

                # Update fingerprints
                fingerprints.set_fingerprint(
                    ns,
                    meta.name,
                    profile.image_fingerprint,
                    _get_config_versions(profile, configmaps, secrets),
                )

                completed += 1
                tracker.item(f"{ns}/{meta.name}", f"{wl_type}, {len(profile.containers)} containers")

    # 4. Build dependency graph
    all_dependencies = _build_dependency_graph(all_profiles, all_services, service_registry)
    tracker.item("Dependencies", f"{len(all_dependencies)} edges discovered")

    # 5. Write cluster-level outputs
    total_pods = sum(p.replicas for p in all_profiles)
    overview = ClusterOverview(
        scanned_at=datetime.now(UTC),
        namespaces=target_ns,
        node_count=len(nodes),
        total_workloads=len(all_profiles),
        total_pods=total_pods,
        dependencies=all_dependencies,
    )
    store.write_model(store.output_dir / "cluster-overview.json", overview)
    store.write_json(store.output_dir / "dependency-graph.json", [d.model_dump() for d in all_dependencies])
    store.write_json(store.output_dir / "nodes.json", node_info)
    store.write_json(store.output_dir / "services.json", all_services)
    store.write_json(store.output_dir / "events.json", all_events)
    if ns_network_policies:
        store.write_json(store.output_dir / "network-policies.json", ns_network_policies)
    fingerprints.save()

    tracker.set_findings(
        workloads=len(all_profiles),
        services=len(all_services),
        dependencies=len(all_dependencies),
    )
    tracker.update("survey complete", completed)

    return overview


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _compute_image_fingerprint(item: Any, wl_type: str) -> dict[str, str]:
    """Compute image fingerprint from a workload without building a full profile."""
    pod_spec = _get_pod_spec(item, wl_type)
    fp: dict[str, str] = {}
    all_containers = list(pod_spec.containers or []) + list(pod_spec.init_containers or [])
    for c in all_containers:
        image = c.image or ""
        if "@sha256:" in image:
            fp[image] = image.split("@sha256:")[-1]
        else:
            fp[image] = hash_value(image)
    return fp


def _compute_config_versions(
    item: Any,
    wl_type: str,
    configmaps: dict[str, Any],
    secrets: dict[str, Any],
) -> dict[str, str]:
    """Compute config versions from a workload without building a full profile."""
    pod_spec = _get_pod_spec(item, wl_type)
    versions: dict[str, str] = {}
    for c in pod_spec.containers or []:
        for env in c.env or []:
            if env.value_from:
                if env.value_from.config_map_key_ref:
                    cm_name = env.value_from.config_map_key_ref.name
                    if cm_name in configmaps:
                        versions[f"configmap/{cm_name}"] = configmaps[cm_name].metadata.resource_version
                elif env.value_from.secret_key_ref:
                    sec_name = env.value_from.secret_key_ref.name
                    if sec_name in secrets:
                        versions[f"secret/{sec_name}"] = secrets[sec_name].metadata.resource_version
        for env_from in c.env_from or []:
            if env_from.config_map_ref:
                cm_name = env_from.config_map_ref.name
                if cm_name in configmaps:
                    versions[f"configmap/{cm_name}"] = configmaps[cm_name].metadata.resource_version
            if env_from.secret_ref:
                sec_name = env_from.secret_ref.name
                if sec_name in secrets:
                    versions[f"secret/{sec_name}"] = secrets[sec_name].metadata.resource_version
    return versions


def _count_workloads(kube: KubeClient, namespace: str) -> int:
    count = 0
    count += len(kube.list_deployments(namespace))
    count += len(kube.list_statefulsets(namespace))
    count += len(kube.list_daemonsets(namespace))
    count += len(kube.list_cronjobs(namespace))
    return count


def _should_skip(meta: Any) -> bool:
    annotations = meta.annotations or {}
    return str(annotations.get(SKIP_ANNOTATION, "")).lower() == "true"


def _get_workload_owner(pod: Any) -> str | None:
    """Walk owner references to find the top-level workload name."""
    if not pod.metadata.owner_references:
        return None
    for ref in pod.metadata.owner_references:
        if ref.kind == "ReplicaSet":
            # Strip ReplicaSet hash suffix to get Deployment name
            parts = ref.name.rsplit("-", 1)
            return str(parts[0]) if len(parts) > 1 else str(ref.name)
        if ref.kind in ("StatefulSet", "DaemonSet", "Job"):
            return str(ref.name)
    return str(pod.metadata.owner_references[0].name)


def _get_pod_spec(item: Any, wl_type: str) -> Any:
    """Extract the pod spec from any workload type."""
    if wl_type == "CronJob":
        return item.spec.job_template.spec.template.spec
    return item.spec.template.spec


def _get_replicas(item: Any, wl_type: str) -> int:
    if wl_type == "DaemonSet":
        return item.status.desired_number_scheduled or 0
    if wl_type == "CronJob":
        return 0
    return item.spec.replicas or 1


def _build_profile(
    item: Any,
    wl_type: str,
    namespace: str,
    config: ScanConfig,
    configmaps: dict[str, Any],
    secrets: dict[str, Any],
    pvcs: dict[str, Any],
    hpa_targets: dict[str, Any],
    pdb_selectors: list[dict[str, Any]],
    pod_node_map: dict[str, list[str]],
    service_registry: dict[str, dict[str, Any]],
    ns_roles: dict[str, list[RbacRule]],
    cluster_roles: dict[str, list[RbacRule]],
    rb_index: dict[str, list[tuple[str, str, str]]],
    crb_index: dict[tuple[str, str], list[tuple[str, str]]],
) -> WorkloadProfile:
    meta = item.metadata
    pod_spec = _get_pod_spec(item, wl_type)

    # Containers
    containers = _extract_containers(pod_spec.containers, role="main")
    init_containers = _extract_containers(pod_spec.init_containers or [], role="init")

    # Image fingerprints
    image_fp: dict[str, str] = {}
    for c in containers + init_containers:
        if c.image_digest:
            image_fp[c.image] = c.image_digest
        else:
            image_fp[c.image] = hash_value(c.image)

    # Env vars
    env_vars = _extract_env_vars(pod_spec.containers, config.reveal_configmap_values)

    # Volumes
    volumes = _extract_volumes(pod_spec, pvcs)

    # Secrets referenced
    secrets_ref = _extract_secret_refs(pod_spec, secrets)

    # Resource requests
    resource_requested = _extract_resource_requests(pod_spec.containers)

    # Health probes
    health = _extract_health_probes(pod_spec.containers)

    # Resilience
    if wl_type == "CronJob":
        labels: dict[str, str] = item.spec.job_template.spec.template.metadata.labels or {}
    else:
        labels = item.spec.template.metadata.labels or {}

    resilience = _build_resilience(
        item=item,
        wl_type=wl_type,
        labels=labels,
        pod_spec=pod_spec,
        hpa_targets=hpa_targets,
        pdb_selectors=pdb_selectors,
        pod_node_map=pod_node_map,
    )

    # CronJob-specific metadata
    cron_schedule = item.spec.schedule if wl_type == "CronJob" else None
    cron_suspend = item.spec.suspend if wl_type == "CronJob" else None
    cron_concurrency_policy = item.spec.concurrency_policy if wl_type == "CronJob" else None

    # RBAC
    sa_name: str = pod_spec.service_account_name or ""
    rbac = _resolve_rbac(sa_name, namespace, ns_roles, cluster_roles, rb_index, crb_index) if sa_name else None

    return WorkloadProfile(
        name=meta.name,
        namespace=namespace,
        workload_type=wl_type,
        explored_at=datetime.now(UTC),
        confidence=0.3,  # Survey-only confidence
        containers=containers,
        init_containers=init_containers,
        image_fingerprint=image_fp,
        replicas=_get_replicas(item, wl_type),
        cron_schedule=cron_schedule,
        cron_suspend=cron_suspend,
        cron_concurrency_policy=cron_concurrency_policy,
        env_vars=env_vars,
        volumes=volumes,
        secrets_referenced=secrets_ref,
        resource_requested=resource_requested,
        health=health,
        resilience=resilience,
        rbac=rbac,
    )


def _extract_containers(containers: list[Any], role: Literal["main", "sidecar", "init"]) -> list[ContainerInfo]:
    result = []
    for c in containers:
        image = c.image or ""
        digest = None
        if "@sha256:" in image:
            digest = image.split("@sha256:")[-1]
        result.append(
            ContainerInfo(
                name=c.name,
                role=role,
                image=image,
                image_digest=digest,
            )
        )
    return result


def _extract_env_vars(containers: list[Any], reveal_configmap: bool) -> list[EnvVar]:
    env_vars: list[EnvVar] = []
    for c in containers:
        for env in c.env or []:
            source = "pod-spec"
            value = env.value or ""

            if env.value_from:
                if env.value_from.secret_key_ref:
                    ref = env.value_from.secret_key_ref
                    source = f"secret/{ref.name}"
                    value = f"<secret:{ref.name}/{ref.key}>"
                elif env.value_from.config_map_key_ref:
                    ref = env.value_from.config_map_key_ref
                    source = f"configmap/{ref.name}"
                    value = f"<configmap:{ref.name}/{ref.key}>"
                elif env.value_from.field_ref:
                    source = f"fieldRef/{env.value_from.field_ref.field_path}"
                    value = f"<fieldRef:{env.value_from.field_ref.field_path}>"

            # Always hash values
            value_hash = hash_value(value)

            env_vars.append(
                EnvVar(
                    name=env.name,
                    source=source,
                    value_hash=value_hash,
                )
            )

        # envFrom (bulk configmap/secret injection)
        for env_from in c.env_from or []:
            if env_from.secret_ref:
                env_vars.append(
                    EnvVar(
                        name=f"<all-from-secret/{env_from.secret_ref.name}>",
                        source=f"secret/{env_from.secret_ref.name}",
                        value_hash=hash_value(f"bulk-secret:{env_from.secret_ref.name}"),
                    )
                )
            if env_from.config_map_ref:
                env_vars.append(
                    EnvVar(
                        name=f"<all-from-configmap/{env_from.config_map_ref.name}>",
                        source=f"configmap/{env_from.config_map_ref.name}",
                        value_hash=hash_value(f"bulk-configmap:{env_from.config_map_ref.name}"),
                    )
                )
    return env_vars


def _extract_volumes(pod_spec: Any, pvcs: dict[str, Any]) -> list[VolumeInfo]:
    volumes: list[VolumeInfo] = []
    volume_map: dict[str, Any] = {}
    for v in pod_spec.volumes or []:
        volume_map[v.name] = v

    # Walk volume mounts across all containers to find mount paths
    mount_paths: dict[str, str] = {}
    for c in pod_spec.containers or []:
        for vm in c.volume_mounts or []:
            mount_paths[vm.name] = vm.mount_path

    for name, vol in volume_map.items():
        vol_type = "unknown"
        size = None
        if vol.persistent_volume_claim:
            vol_type = "PVC"
            pvc_name = vol.persistent_volume_claim.claim_name
            if pvc_name in pvcs:
                req = pvcs[pvc_name].spec.resources.requests or {}
                size = req.get("storage")
        elif vol.empty_dir is not None:
            vol_type = "emptyDir"
        elif vol.config_map:
            vol_type = "configMap"
        elif vol.secret:
            vol_type = "secret"
        elif vol.host_path:
            vol_type = "hostPath"
        elif vol.projected:
            vol_type = "projected"

        volumes.append(
            VolumeInfo(
                name=name,
                mount_path=mount_paths.get(name, "<not-mounted>"),
                volume_type=vol_type,
                size=size,
            )
        )
    return volumes


def _extract_secret_refs(pod_spec: Any, secrets: dict[str, Any]) -> list[dict[str, Any]]:
    """Collect all secret references (keys only, never values)."""
    refs: list[dict[str, Any]] = []
    seen: set[str] = set()
    for c in pod_spec.containers or []:
        for env in c.env or []:
            if env.value_from and env.value_from.secret_key_ref:
                ref = env.value_from.secret_key_ref
                key = f"{ref.name}/{ref.key}"
                if key not in seen:
                    seen.add(key)
                    refs.append({"secret": ref.name, "key": ref.key})
        for env_from in c.env_from or []:
            if env_from.secret_ref:
                name = env_from.secret_ref.name
                if name not in seen:
                    seen.add(name)
                    secret_obj = secrets.get(name)
                    keys = list(secret_obj.data.keys()) if secret_obj and secret_obj.data else []
                    refs.append({"secret": name, "keys": keys})
    return refs


def _extract_resource_requests(containers: list[Any]) -> dict[str, Any] | None:
    result: dict[str, dict[str, Any]] = {}
    for c in containers:
        res = c.resources
        if not res:
            continue
        entry: dict[str, Any] = {}
        if res.requests:
            entry["requests"] = {k: str(v) for k, v in res.requests.items()}
        if res.limits:
            entry["limits"] = {k: str(v) for k, v in res.limits.items()}
        if entry:
            result[c.name] = entry
    return result or None


def _extract_health_probes(containers: list[Any]) -> dict[str, Any]:
    probes: dict[str, dict[str, Any]] = {}
    for c in containers:
        c_probes: dict[str, Any] = {}
        for probe_name in ("liveness_probe", "readiness_probe", "startup_probe"):
            probe = getattr(c, probe_name, None)
            if probe:
                c_probes[probe_name.replace("_probe", "")] = _probe_to_dict(probe)
        if c_probes:
            probes[c.name] = c_probes
    return probes


def _probe_to_dict(probe: Any) -> dict[str, Any]:
    result: dict[str, Any] = {}
    if probe.http_get:
        result["type"] = "httpGet"
        result["path"] = probe.http_get.path
        result["port"] = probe.http_get.port
    elif probe.tcp_socket:
        result["type"] = "tcpSocket"
        result["port"] = probe.tcp_socket.port
    elif probe.exec:
        result["type"] = "exec"
        result["command"] = probe.exec.command
    elif getattr(probe, "grpc", None):
        result["type"] = "grpc"
        result["port"] = probe.grpc.port
    result["initialDelaySeconds"] = probe.initial_delay_seconds
    result["periodSeconds"] = probe.period_seconds
    return result


def _build_resilience(
    item: Any,
    wl_type: str,
    labels: dict[str, str],
    pod_spec: Any,
    hpa_targets: dict[str, Any],
    pdb_selectors: list[dict[str, Any]],
    pod_node_map: dict[str, list[str]],
) -> ResilienceInfo:
    name = item.metadata.name

    # PDB check
    has_pdb = False
    for sel in pdb_selectors:
        if all(labels.get(k) == v for k, v in sel.items()):
            has_pdb = True
            break

    # HPA check
    has_hpa = f"{wl_type}/{name}" in hpa_targets

    # Anti-affinity
    affinity = pod_spec.affinity
    has_anti_affinity = False
    has_topology_spread = False
    if affinity and affinity.pod_anti_affinity:
        has_anti_affinity = True

    # Topology spread constraints
    if pod_spec.topology_spread_constraints:
        has_topology_spread = True

    # All replicas same node?
    nodes = pod_node_map.get(name, [])
    unique_nodes = set(nodes)
    all_same_node = None
    if len(nodes) > 1:
        all_same_node = len(unique_nodes) == 1

    return ResilienceInfo(
        pod_disruption_budget=has_pdb,
        anti_affinity=has_anti_affinity,
        topology_spread=has_topology_spread,
        all_replicas_same_node=all_same_node,
        horizontal_pod_autoscaler=has_hpa,
    )


def _rules_from_k8s(rules: list[Any] | None) -> list[RbacRule]:
    """Convert Kubernetes policy rules to RbacRule models."""
    result: list[RbacRule] = []
    for r in rules or []:
        result.append(
            RbacRule(
                verbs=list(r.verbs or []),
                api_groups=list(r.api_groups or []),
                resources=list(r.resources or []),
                resource_names=list(r.resource_names or []),
                non_resource_urls=list(getattr(r, "non_resource_ur_ls", None) or []),
            )
        )
    return result


def _detect_high_risk(rules: list[RbacRule]) -> list[str]:
    """Return human-readable flags for elevated or dangerous RBAC permissions."""
    flags: list[str] = []
    for rule in rules:
        verbs = set(rule.verbs)
        resources = set(rule.resources)
        if "*" in verbs and "*" in resources:
            flags.append("*:*")
            continue
        if "secrets" in resources and verbs & {"get", "list", "watch", "*"}:
            matched = sorted(verbs & {"get", "list", "watch", "*"})
            flags.append(f"secrets:{','.join(matched)}")
        for subres in ("pods/exec", "pods/attach"):
            if subres in resources and "create" in verbs:
                flags.append(f"{subres}:create")
        if "clusterroles" in resources and verbs & {"bind", "escalate", "*"}:
            matched = sorted(verbs & {"bind", "escalate", "*"})
            flags.append(f"clusterroles:{','.join(matched)}")
    # Deduplicate while preserving order
    return list(dict.fromkeys(flags))


def _collect_cluster_rbac(
    kube: KubeClient,
) -> tuple[dict[str, list[RbacRule]], dict[tuple[str, str], list[tuple[str, str]]]]:
    """Load ClusterRoles and ClusterRoleBindings.

    Returns:
        cluster_roles: {cluster_role_name -> [rules]}
        crb_index:     {(sa_name, sa_namespace) -> [(cluster_role_name, binding_name)]}
    """
    cluster_roles: dict[str, list[RbacRule]] = {}
    crb_index: dict[tuple[str, str], list[tuple[str, str]]] = {}
    try:
        for cr in kube.list_cluster_roles():
            cluster_roles[cr.metadata.name] = _rules_from_k8s(cr.rules)
    except ApiException as exc:
        logger.debug("Cannot list ClusterRoles (RBAC denied?): %s", exc.reason)
        return cluster_roles, crb_index
    try:
        for crb in kube.list_cluster_role_bindings():
            cr_name = crb.role_ref.name
            binding_name = crb.metadata.name
            for subject in crb.subjects or []:
                if subject.kind == "ServiceAccount" and subject.name and subject.namespace:
                    key = (subject.name, subject.namespace)
                    crb_index.setdefault(key, []).append((cr_name, binding_name))
    except ApiException as exc:
        logger.debug("Cannot list ClusterRoleBindings (RBAC denied?): %s", exc.reason)
    return cluster_roles, crb_index


def _collect_namespace_rbac(
    kube: KubeClient,
    namespace: str,
) -> tuple[dict[str, list[RbacRule]], dict[str, list[tuple[str, str, str]]]]:
    """Load Roles and RoleBindings for one namespace.

    Returns:
        ns_roles:  {role_name -> [rules]}
        rb_index:  {sa_name -> [(role_kind, role_name, binding_name)]}
    """
    ns_roles: dict[str, list[RbacRule]] = {}
    rb_index: dict[str, list[tuple[str, str, str]]] = {}
    try:
        for role in kube.list_roles(namespace):
            ns_roles[role.metadata.name] = _rules_from_k8s(role.rules)
    except ApiException as exc:
        logger.debug("Cannot list Roles in %s (RBAC denied?): %s", namespace, exc.reason)
        return ns_roles, rb_index
    try:
        for rb in kube.list_role_bindings(namespace):
            role_kind = rb.role_ref.kind
            role_name = rb.role_ref.name
            binding_name = rb.metadata.name
            for subject in rb.subjects or []:
                if subject.kind == "ServiceAccount" and subject.name:
                    rb_index.setdefault(subject.name, []).append((role_kind, role_name, binding_name))
    except ApiException as exc:
        logger.debug("Cannot list RoleBindings in %s (RBAC denied?): %s", namespace, exc.reason)
    return ns_roles, rb_index


def _resolve_rbac(
    sa_name: str,
    namespace: str,
    ns_roles: dict[str, list[RbacRule]],
    cluster_roles: dict[str, list[RbacRule]],
    rb_index: dict[str, list[tuple[str, str, str]]],
    crb_index: dict[tuple[str, str], list[tuple[str, str]]],
) -> RbacSummary:
    """Resolve effective RBAC rules for a ServiceAccount."""
    all_rules: list[RbacRule] = []
    role_refs: list[str] = []

    for role_kind, role_name, _binding in rb_index.get(sa_name, []):
        if role_kind == "Role":
            rules = ns_roles.get(role_name, [])
            role_refs.append(f"role/{role_name}")
        else:  # ClusterRole referenced via namespaced RoleBinding
            rules = cluster_roles.get(role_name, [])
            role_refs.append(f"clusterrole/{role_name}")
        all_rules.extend(rules)

    for cr_name, _binding in crb_index.get((sa_name, namespace), []):
        all_rules.extend(cluster_roles.get(cr_name, []))
        role_refs.append(f"clusterrole/{cr_name}")

    return RbacSummary(
        service_account=sa_name,
        roles=list(dict.fromkeys(role_refs)),
        rules=all_rules,
        high_risk=_detect_high_risk(all_rules),
    )


def _extract_service(svc: Any, namespace: str) -> dict[str, Any]:
    ports = []
    for p in svc.spec.ports or []:
        ports.append(
            {
                "name": p.name,
                "port": p.port,
                "targetPort": p.target_port,
                "protocol": p.protocol,
            }
        )
    return {
        "name": svc.metadata.name,
        "namespace": namespace,
        "type": svc.spec.type,
        "clusterIP": svc.spec.cluster_ip,
        "selector": dict(svc.spec.selector) if svc.spec.selector else {},
        "ports": ports,
    }


def _extract_network_policy(np: Any) -> dict[str, Any]:
    return {
        "name": np.metadata.name,
        "podSelector": (
            np.spec.pod_selector.match_labels if np.spec.pod_selector and np.spec.pod_selector.match_labels else {}
        ),
        "policyTypes": np.spec.policy_types or [],
    }


def _collect_node_info(nodes: list[Any]) -> list[dict[str, Any]]:
    result = []
    for node in nodes:
        capacity = node.status.capacity or {}
        allocatable = node.status.allocatable or {}
        taints = []
        for t in node.spec.taints or []:
            taints.append({"key": t.key, "value": t.value, "effect": t.effect})
        labels = dict(node.metadata.labels or {})
        result.append(
            {
                "name": node.metadata.name,
                "labels": labels,
                "taints": taints,
                "capacity": {k: str(v) for k, v in capacity.items()},
                "allocatable": {k: str(v) for k, v in allocatable.items()},
            }
        )
    return result


def _get_config_versions(
    profile: WorkloadProfile, configmaps: dict[str, Any], secrets: dict[str, Any]
) -> dict[str, str]:
    """Get resource versions for all referenced configmaps/secrets."""
    versions: dict[str, str] = {}
    for env in profile.env_vars:
        if env.source.startswith("configmap/"):
            cm_name = env.source.split("/", 1)[1]
            if cm_name in configmaps:
                versions[f"configmap/{cm_name}"] = configmaps[cm_name].metadata.resource_version
        elif env.source.startswith("secret/"):
            sec_name = env.source.split("/", 1)[1]
            if sec_name in secrets:
                versions[f"secret/{sec_name}"] = secrets[sec_name].metadata.resource_version
    return versions


def _build_dependency_graph(
    profiles: list[WorkloadProfile],
    services: list[dict[str, Any]],
    service_registry: dict[str, dict[str, Any]],
) -> list[DependencyEdge]:
    """Build dependency graph from env var analysis (service hostname patterns)."""
    edges: list[DependencyEdge] = []
    seen: set[str] = set()

    # Known service hostnames and IPs
    svc_by_ip: dict[str, dict[str, Any]] = {}
    for svc in services:
        if svc.get("clusterIP") and svc["clusterIP"] != "None":
            svc_by_ip[svc["clusterIP"]] = svc

    # Patterns that reference other services
    # e.g., POSTGRES_HOST=postgres, REDIS_URL=redis://redis:6379, DATABASE_URL=postgresql://postgres:5432
    service_names = {s["name"] for s in services}

    for profile in profiles:
        source = f"{profile.namespace}/{profile.name}"

        for env in profile.env_vars:
            # Check if hash corresponds to a known service reference
            # We can't unhash, but we can check the env var name for hints
            env_name_lower = env.name.lower()
            for svc_name in service_names:
                # Match env var names like POSTGRES_HOST, REDIS_URL, etc.
                svc_upper = svc_name.upper().replace("-", "_")
                if svc_upper in env_name_lower or svc_name in env_name_lower:
                    # Find the matching service
                    svc_data = service_registry.get(svc_name)
                    if svc_data and svc_data["namespace"] != profile.namespace and svc_data["name"] == svc_name:
                        # Cross-namespace reference — use full DNS
                        dest = f"{svc_data['namespace']}/{svc_data['name']}"
                    elif svc_data:
                        dest = f"{svc_data['namespace']}/{svc_data['name']}"
                    else:
                        continue

                    if dest == source:
                        continue

                    for port_info in (svc_data or {}).get("ports", []):
                        edge_key = f"{source}->{dest}:{port_info['port']}"
                        if edge_key not in seen:
                            seen.add(edge_key)
                            edges.append(
                                DependencyEdge(
                                    source=source,
                                    destination=dest,
                                    port=port_info["port"],
                                    protocol=_guess_protocol(port_info["port"], port_info.get("name", "")),
                                    evidence=(
                                        f"env var '{env.name}' name matches service '{svc_name}' "
                                        "(not observed in live sockets)"
                                    ),
                                    verified=False,
                                )
                            )

    return edges


def _guess_protocol(port: int, name: str | None) -> str:
    """Guess protocol from port number or service port name."""
    name_lower = (name or "").lower()
    if "grpc" in name_lower:
        return "gRPC"
    if "http" in name_lower:
        return "HTTP"
    return PORT_PROTOCOL_MAP.get(port, "TCP")
