"""Phase 2: Deep inspection — exec into pods, probe endpoints, extract data.

All extraction is done via deterministic regex parsing.  AI is NOT used
here — it is reserved for the writer/interpretation layer.
"""

import json
import logging
import re
import shlex
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from kube2docs.ai.extractor import Extractor
from kube2docs.config import ScanConfig
from kube2docs.knowledge.fingerprint import FingerprintTracker
from kube2docs.knowledge.schemas import (
    EnvVar,
    NetworkListener,
    OutboundConnection,
    WorkloadProfile,
)
from kube2docs.knowledge.store import KnowledgeStore
from kube2docs.kube.client import KubeClient
from kube2docs.kube.exec import PodExec, pick_running_pod
from kube2docs.phases.image_inspect import inspect_image
from kube2docs.progress.tracker import ProgressTracker
from kube2docs.security.hasher import hash_value, redact_secrets

logger = logging.getLogger(__name__)


def _merge_unique[T](
    existing: list[T],
    new_items: list[dict[str, Any]],
    key_fn: Callable[[T], str],
    new_key_fn: Callable[[dict[str, Any]], str],
    constructor: Callable[[dict[str, Any]], T],
) -> None:
    """Merge new items into an existing list, skipping duplicates by key."""
    seen = {key_fn(item) for item in existing}
    for entry in new_items:
        key = new_key_fn(entry)
        if key and key not in seen:
            existing.append(constructor(entry))
            seen.add(key)


# Commands to run inside pods, in order. Each is (label, command).
_DISCOVERY_COMMANDS: list[tuple[str, str]] = [
    ("processes", "ps aux 2>/dev/null || cat /proc/1/cmdline 2>/dev/null | tr '\\0' '\\n'"),
    (
        "listeners",
        "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null",
    ),
    (
        "connections",
        "ss -tnp 2>/dev/null || netstat -tnp 2>/dev/null",
    ),
    ("environ", "cat /proc/1/environ 2>/dev/null | tr '\\0' '\\n'"),
    ("disk", "df -h 2>/dev/null"),
    (
        "config_dirs",
        "ls -la /etc/ /app/ /opt/ /config/ /etc/nginx/ 2>/dev/null | head -100",
    ),
]

# Health/ready paths to probe on discovered ports.
# Extensions that indicate a config file when found in cmdline args.
_CONFIG_EXTENSIONS = frozenset(
    {
        ".conf",
        ".yaml",
        ".yml",
        ".json",
        ".toml",
        ".ini",
        ".cfg",
        ".properties",
        ".xml",
        ".env",
        ".cnf",
        ".config",
    }
)

_HEALTH_PATHS = ("/health", "/healthz", "/readyz", "/ready", "/status", "/")
_METRICS_PATHS = ("/metrics", "/actuator/prometheus")

# Config file paths to attempt reading.
_CONFIG_GLOBS = (
    "/etc/nginx/nginx.conf",
    "/etc/nginx/conf.d/default.conf",
    "/etc/redis/redis.conf",
    "/etc/postgresql/postgresql.conf",
    "/var/lib/postgresql/data/postgresql.conf",
    "/var/lib/postgresql/data/pg_hba.conf",
    "/app/config.*",
    "/app/application.*",
    "/opt/*/conf/*",
    "/etc/*.conf",
)


def run_deep_inspect(
    kube: KubeClient,
    config: ScanConfig,
    store: KnowledgeStore,
    tracker: ProgressTracker,
    services: list[dict[str, Any]],
    fingerprints: FingerprintTracker | None = None,
) -> None:
    """Execute Phase 2: deep inspection of each workload via exec."""
    tracker.phase_header("Phase 2: Deep Inspection")

    extractor = Extractor()
    pod_exec = PodExec(core_api=kube.core, timeout=config.timeout)

    # Load profiles written by Phase 1
    profiles = _load_profiles(store)
    tracker.start("deep_inspect", len(profiles))

    completed = 0
    for profile in profiles:
        ns = profile.namespace
        name = profile.name
        tracker.update(f"{ns}/{name}", completed)

        # Skip CronJobs — they may not have running pods
        if profile.workload_type == "CronJob":
            tracker.log(f"Skipping {ns}/{name} (CronJob, no persistent pod)")
            completed += 1
            continue

        # Skip unchanged workloads (incremental scanning)
        if fingerprints and not config.force_rescan and not fingerprints.was_changed_this_scan(ns, name):
            tracker.log(f"{ns}/{name} unchanged, skipping deep inspection")
            completed += 1
            continue

        # Find a running pod for this workload
        pods = kube.list_pods(ns)
        pod = pick_running_pod(pods, name)
        if pod is None:
            tracker.warning(f"{ns}/{name}: no running pod found")
            completed += 1
            continue

        pod_name = pod.metadata.name

        # Iterate all containers (main + sidecars), not just the first one
        containers_to_inspect = profile.containers if profile.containers else [None]
        any_succeeded = False

        for cont_info in containers_to_inspect:
            container = cont_info.name if cont_info else None

            # Run discovery commands for this container
            raw_outputs: dict[str, str] = {}
            for label, command in _DISCOVERY_COMMANDS:
                output = pod_exec.run_safe(ns, pod_name, command, container)
                if output:
                    raw_outputs[label] = output

            if not raw_outputs:
                # Exec failed — try image-layer analysis as a fallback.
                # This handles distroless containers, scratch images, and
                # environments where exec permissions are restricted.
                if cont_info is not None:
                    analysis = inspect_image(cont_info.image, timeout=config.timeout)
                    if analysis:
                        _apply_image_analysis(profile, cont_info.name, analysis)
                        tracker.log(
                            f"{ns}/{name}/{container}: exec failed, image-layer analysis succeeded"
                            f" ({analysis.get('packages', {}).get('os', 'unknown OS')},"
                            f" {len(analysis.get('packages', {}).get('packages', []))} packages)"
                        )
                    else:
                        tracker.log(f"{ns}/{name}/{container}: no exec and image registry unreachable")
                continue

            any_succeeded = True

            # Extract structured data from outputs
            _enrich_profile(
                profile=profile,
                raw_outputs=raw_outputs,
                extractor=extractor,
                pod_exec=pod_exec,
                pod_name=pod_name,
                namespace=ns,
                container=container,
                services=services,
                tracker=tracker,
                store=store,
                container_name=container,
                max_configs_per_glob=config.config_files_per_glob,
            )

            # Write raw outputs per container for debugging
            raw_dir = store.namespace_dir(ns) / f"{name}.raw"
            if container:
                raw_dir = raw_dir / container
            raw_dir.mkdir(parents=True, exist_ok=True)
            for label, output in raw_outputs.items():
                (raw_dir / f"{label}.txt").write_text(output)

        if not any_succeeded:
            # If image-layer analysis ran for any container, record that as the source.
            if profile.image_analysis:
                profile.confidence = 0.5
                profile.inspection_source = "image_inspect"
                profile.explored_at = datetime.now(UTC)
                tracker.item(f"{ns}/{name}", _summarize_image_analysis(profile))
            else:
                tracker.warning(f"{ns}/{name}: no exec or image analysis succeeded")
            completed += 1
            continue

        # Bump confidence and record inspection source
        profile.confidence = min(0.7, profile.confidence + 0.3)
        profile.inspection_source = "deep_inspect"
        profile.explored_at = datetime.now(UTC)

        # Write updated profile
        ns_dir = store.namespace_dir(ns)
        store.write_model(ns_dir / f"{name}.profile.json", profile)

        completed += 1
        findings = _summarize_findings(profile)
        tracker.item(f"{ns}/{name}", findings)


def _load_profiles(store: KnowledgeStore) -> list[WorkloadProfile]:
    """Load all Phase 1 profiles from the knowledge base."""
    profiles: list[WorkloadProfile] = []
    for path in store.output_dir.rglob("*.profile.json"):
        try:
            data = json.loads(path.read_text())
            profiles.append(WorkloadProfile(**data))
        except (json.JSONDecodeError, ValueError) as exc:
            logger.warning("Failed to load profile %s: %s", path, exc)
        except OSError as exc:
            logger.warning("Failed to read profile file %s: %s", path, exc)
    return profiles


def _enrich_profile(
    profile: WorkloadProfile,
    raw_outputs: dict[str, str],
    extractor: Extractor,
    pod_exec: PodExec,
    pod_name: str,
    namespace: str,
    container: str | None,
    services: list[dict[str, Any]],
    tracker: ProgressTracker,
    store: KnowledgeStore | None = None,
    container_name: str | None = None,
    max_configs_per_glob: int = 5,
) -> None:
    """Update a profile with deep inspection findings."""

    # --- Processes ---
    if "processes" in raw_outputs:
        proc_info = extractor.extract_process_info(
            raw_outputs["processes"],
            pod_name,
        )
        # Use container-specific type key to preserve per-container process info
        proc_type = f"process_info:{container_name}" if container_name else "process_info"
        profile.config_files = [cf for cf in profile.config_files if cf.get("_type") != proc_type]
        profile.config_files.append(
            {
                "_type": proc_type,
                "container": container_name,
                **proc_info,
            }
        )

    # --- Network listeners ---
    if "listeners" in raw_outputs:
        parsed_listeners = extractor.extract_listeners(
            raw_outputs["listeners"],
            pod_name,
        )
        _merge_unique(
            profile.network_listeners,
            parsed_listeners,
            key_fn=lambda nl: str(nl.port),
            new_key_fn=lambda e: str(e.get("port", 0)) if e.get("port") else "",
            constructor=lambda e: NetworkListener(
                port=e["port"],
                protocol=e.get("protocol", "TCP"),
                purpose=e.get("process"),
            ),
        )

    # --- Outbound connections ---
    if "connections" in raw_outputs:
        parsed_conns = extractor.extract_connections(
            raw_outputs["connections"],
            pod_name,
            services,
        )

        def _conn_dest(entry: dict[str, Any]) -> str:
            dest_ip = entry.get("destination_ip", "")
            dest_port = entry.get("destination_port", 0)
            matched = entry.get("matched_service", "")
            return f"{matched}:{dest_port}" if matched else f"{dest_ip}:{dest_port}"

        _merge_unique(
            profile.outbound_connections,
            parsed_conns,
            key_fn=lambda oc: oc.destination,
            new_key_fn=_conn_dest,
            constructor=lambda e: OutboundConnection(
                destination=_conn_dest(e),
                protocol=e.get("protocol_guess", "TCP"),
            ),
        )

    # --- Runtime environment variables ---
    if "environ" in raw_outputs:
        parsed_env = extractor.extract_env(raw_outputs["environ"])
        _merge_unique(
            profile.env_vars,
            parsed_env,
            key_fn=lambda ev: ev.name,
            new_key_fn=lambda e: e.get("name", ""),
            constructor=lambda e: EnvVar(
                name=e["name"],
                source="runtime",
                value_hash=e.get("value_hash", ""),
            ),
        )

    # --- Disk usage ---
    if "disk" in raw_outputs:
        parsed_df = extractor.extract_disk_usage(raw_outputs["disk"])
        vol_by_mount = {v.mount_path: v for v in profile.volumes}
        for entry in parsed_df:
            mount = entry.get("mounted_on", "")
            if mount in vol_by_mount:
                vol_by_mount[mount].current_usage = entry.get("use_percent")

    # --- Config files ---
    assert store is not None
    raw_base = store.namespace_dir(namespace) / f"{profile.name}.raw"
    configs_dir = raw_base / container_name / "configs" if container_name else raw_base / "configs"
    configs_dir.mkdir(parents=True, exist_ok=True)

    # Dynamically discover config paths from PID 1 cmdline
    extra_config_paths: list[str] = []
    if "processes" in raw_outputs:
        extra_config_paths = _extract_config_paths_from_cmdline(raw_outputs["processes"])

    _try_read_config_files(
        profile=profile,
        extractor=extractor,
        pod_exec=pod_exec,
        pod_name=pod_name,
        namespace=namespace,
        container=container,
        configs_dir=configs_dir,
        extra_paths=extra_config_paths,
        max_per_glob=max_configs_per_glob,
    )

    # --- Health endpoint probing ---
    _probe_health_endpoints(
        profile=profile,
        extractor=extractor,
        pod_exec=pod_exec,
        pod_name=pod_name,
        namespace=namespace,
        container=container,
        tracker=tracker,
    )


def _try_read_config_files(
    profile: WorkloadProfile,
    extractor: Extractor,
    pod_exec: PodExec,
    pod_name: str,
    namespace: str,
    container: str | None,
    configs_dir: Path | None = None,
    extra_paths: list[str] | None = None,
    max_per_glob: int = 5,
) -> None:
    """Attempt to read known config file paths and save raw contents."""
    all_globs: list[str] = list(_CONFIG_GLOBS)
    if extra_paths:
        all_globs.extend(extra_paths)
    for glob_path in all_globs:
        if "*" in glob_path:
            output = pod_exec.run_safe(
                namespace,
                pod_name,
                f"ls {shlex.quote(glob_path)} 2>/dev/null",
                container,
                timeout=5,
            )
            if not output:
                continue
            paths = [p.strip() for p in output.splitlines() if p.strip()]
        else:
            paths = [glob_path]

        for fpath in paths[:max_per_glob]:
            content = pod_exec.run_safe(
                namespace,
                pod_name,
                f"cat {shlex.quote(fpath)} 2>/dev/null",
                container,
                timeout=5,
            )
            if not content or len(content.strip()) < 5:
                continue

            parsed = extractor.extract_config_file(content, fpath)

            # Redact only sensitive values, keep everything else
            redacted = redact_secrets(content)

            # Save raw (redacted) config to disk
            if configs_dir:
                safe_name = fpath.lstrip("/").replace("/", "__")
                (configs_dir / safe_name).write_text(redacted)

            profile.config_files = [cf for cf in profile.config_files if cf.get("path") != fpath]
            profile.config_files.append(
                {
                    "path": fpath,
                    "size": len(content),
                    "content_hash": hash_value(content),
                    **parsed,
                }
            )


def _find_fetch_command(
    pod_exec: PodExec,
    namespace: str,
    pod_name: str,
    container: str | None,
) -> str | None:
    """Detect an available HTTP fetch tool (curl or wget) in the pod."""
    for tool, cmd in [("curl", "curl -sf --max-time 2"), ("wget", "wget -q -O- --timeout=2")]:
        result = pod_exec.run_safe(namespace, pod_name, f"which {tool} 2>/dev/null", container, timeout=5)
        if result and tool in result:
            return cmd
    return None


def _probe_endpoints(
    pod_exec: PodExec,
    namespace: str,
    pod_name: str,
    container: str | None,
    fetch_cmd: str,
    port: int,
    paths: tuple[str, ...],
    check_fn: Callable[[str, str], dict[str, Any] | None],
) -> tuple[dict[str, Any], str] | None:
    """Probe a list of endpoint paths on a port, returning (result, matched_path) or None."""
    for path in paths:
        url = f"http://localhost:{port}{path}"
        body = pod_exec.run_safe(namespace, pod_name, f"{fetch_cmd} {url} 2>/dev/null", container, timeout=5)
        if body and body.strip():
            result = check_fn(body, url)
            if result is not None:
                return result, path
    return None


def _probe_health_endpoints(
    profile: WorkloadProfile,
    extractor: Extractor,
    pod_exec: PodExec,
    pod_name: str,
    namespace: str,
    container: str | None,
    tracker: ProgressTracker,
) -> None:
    """Probe discovered ports for health and metrics endpoints."""
    ports = [nl.port for nl in profile.network_listeners]
    if not ports:
        return

    fetch_cmd = _find_fetch_command(pod_exec, namespace, pod_name, container)
    if fetch_cmd is None:
        return

    health_results: dict[str, Any] = profile.health.copy()

    def _check_health(body: str, url: str) -> dict[str, Any] | None:
        result = extractor.extract_health_response(body, url)
        return result if result["status"] == "healthy" else None

    def _check_metrics(body: str, url: str) -> dict[str, Any] | None:
        info = extractor.detect_metrics(body)
        return info if info["prometheus"] else None

    for port in ports[:3]:
        health_match = _probe_endpoints(
            pod_exec,
            namespace,
            pod_name,
            container,
            fetch_cmd,
            port,
            _HEALTH_PATHS,
            _check_health,
        )
        if health_match:
            health_results[f"port_{port}_health"] = health_match[0]

        metrics_match = _probe_endpoints(
            pod_exec,
            namespace,
            pod_name,
            container,
            fetch_cmd,
            port,
            _METRICS_PATHS,
            _check_metrics,
        )
        if metrics_match:
            metrics_result, matched_path = metrics_match
            health_results[f"port_{port}_metrics"] = metrics_result
            for nl in profile.network_listeners:
                if nl.port == port and matched_path not in nl.detected_endpoints:
                    nl.detected_endpoints.append(matched_path)
                    break

    profile.health = health_results


def _summarize_findings(profile: WorkloadProfile) -> str:
    """Build a short summary string for the progress tracker."""
    parts: list[str] = []
    proc = next((c for c in profile.config_files if str(c.get("_type", "")).startswith("process_info")), None)
    if proc:
        lang = proc.get("language", "unknown")
        if lang != "unknown":
            parts.append(lang)

    if profile.network_listeners:
        ports = ", ".join(str(nl.port) for nl in profile.network_listeners)
        parts.append(f"ports={ports}")

    if profile.outbound_connections:
        parts.append(f"{len(profile.outbound_connections)} connections")

    health_count = sum(1 for k in profile.health if "health" in k)
    if health_count:
        parts.append(f"{health_count} health endpoints")

    if not parts:
        parts.append("basic info only")

    return ", ".join(parts)


def _apply_image_analysis(profile: WorkloadProfile, container_name: str, analysis: dict[str, Any]) -> None:
    """Merge image-layer analysis results into a WorkloadProfile.

    Populates:
    - profile.image_analysis[container_name] — full raw analysis
    - profile.network_listeners — from declared ports in image config
    - profile.env_vars — baked-in env var names from image config
    """
    profile.image_analysis[container_name] = analysis

    # Declared ports → network_listeners (if not already present from exec)
    existing_ports = {nl.port for nl in profile.network_listeners}
    for port in analysis.get("declared_ports", []):
        if port not in existing_ports:
            profile.network_listeners.append(
                NetworkListener(port=port, protocol="TCP", purpose="declared in image config")
            )
            existing_ports.add(port)

    # Baked env var names → env_vars (source = image_config)
    existing_env = {ev.name for ev in profile.env_vars}
    for env_name in analysis.get("baked_env_vars", []):
        if env_name not in existing_env and not env_name.startswith("PATH"):
            profile.env_vars.append(
                EnvVar(name=env_name, source="image_config", value_hash="")
            )
            existing_env.add(env_name)


def _summarize_image_analysis(profile: WorkloadProfile) -> str:
    """Build a progress-tracker summary string for image-layer-only profiles."""
    parts: list[str] = []
    for container_name, analysis in profile.image_analysis.items():
        pkg_info = analysis.get("packages")
        if pkg_info:
            os_name = pkg_info.get("os", "unknown")
            count = len(pkg_info.get("packages", []))
            parts.append(f"{container_name}: {os_name}, {count} packages")
        if analysis.get("declared_ports"):
            ports = ",".join(str(p) for p in analysis["declared_ports"])
            parts.append(f"ports={ports}")
        if analysis.get("entrypoint"):
            ep = analysis["entrypoint"]
            parts.append(f"entrypoint={ep[0] if ep else '?'}")
    return " | ".join(parts) if parts else "image-layer analysis only"


def _extract_config_paths_from_cmdline(ps_output: str) -> list[str]:
    """Extract file paths from PID 1 command line that look like config files.

    Parses process output looking for arguments like --config /path/to/file,
    -f /path, -c /path, or bare absolute paths with config-like extensions.
    """
    paths: list[str] = []
    seen: set[str] = set()

    # Try to find the PID 1 command line
    cmdline = ""
    for line in ps_output.splitlines():
        parts = line.split()
        if not parts:
            continue
        # ps aux format: USER PID ... COMMAND
        if len(parts) >= 11:
            try:
                pid = int(parts[1])
                if pid == 1:
                    cmdline = " ".join(parts[10:])
                    break
            except ValueError:
                continue
        # /proc/1/cmdline fallback: raw args, one per line
        elif len(parts) == 1 and parts[0].startswith("/"):
            cmdline += " " + parts[0]

    if not cmdline:
        cmdline = ps_output  # fallback: scan all output

    # Look for absolute paths with config-like extensions.
    # Only allow safe path characters (alphanumeric, /, ., -, _) to prevent
    # shell injection via crafted cmdline args like --config '/app/foo$(rm -rf /)'.
    path_pattern = re.compile(r"(/[a-zA-Z0-9_./-]+)")
    for match in path_pattern.finditer(cmdline):
        candidate = match.group(1)
        # Check if it has a config-like extension
        for ext in _CONFIG_EXTENSIONS:
            if candidate.endswith(ext) and candidate not in seen:
                seen.add(candidate)
                paths.append(candidate)
                break

    return paths
