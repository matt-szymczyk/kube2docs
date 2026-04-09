"""Phase 3: AI-driven agentic scan — LLM decides what commands to run.

Replaces Phase 2 (deep inspect) when --agentic is used. Receives Phase 1
profiles and iteratively execs commands chosen by an LLM to discover runtime
configuration, dependencies, and health endpoints.
"""

import json
import logging
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from kube2docs.ai.provider import AIProvider
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
from kube2docs.progress.tracker import ProgressTracker
from kube2docs.security.hasher import hash_value, redact_secrets

logger = logging.getLogger(__name__)

# Maximum bytes of output to keep per exec command.
_MAX_OUTPUT_BYTES = 65_536

# Narrow threat model: block only mutations, process control, outbound network,
# and cluster API access. Read-only commands are allowed freely so the agent
# can inspect every corner of the pod (that's the whole point).

# 1. Writes and file mutations.
_WRITE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\brm\b"),
    re.compile(r"\bchmod\b"),
    re.compile(r"\bchown\b"),
    re.compile(r"\bdd\b"),
    re.compile(r"\bmkfs\b"),
    re.compile(r"\btruncate\b"),
    re.compile(r"\bmv\b"),
    re.compile(r"\bcp\s+.*\s+/(?!tmp|dev/null)"),
    re.compile(r"[>;|&]\s*tee\b"),
    re.compile(r"(?<!2)>\s*/(?!dev/null|tmp/)"),
    re.compile(r">>\s*/(?!dev/null|tmp/)"),
    re.compile(r"\bsed\s+.*-i\b"),
    re.compile(r"\bawk\s+.*>\s*/"),
]

# 2. Process control and system state.
_PROCESS_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bkill\b"),
    re.compile(r"\bkillall\b"),
    re.compile(r"\bpkill\b"),
    re.compile(r"\bshutdown\b"),
    re.compile(r"\breboot\b"),
    re.compile(r"\bhalt\b"),
    re.compile(r"\bsystemctl\s+(stop|start|restart|reload|enable|disable|mask)"),
    re.compile(r"\bservice\s+\S+\s+(stop|start|restart|reload)"),
]

# 3. Outbound network to non-localhost (prevent exfiltration and external calls).
#    Allow localhost probes for health/metrics endpoints.
_NETWORK_PATTERNS: list[re.Pattern[str]] = [
    # curl/wget to anything that isn't localhost/127.x/::1
    re.compile(r"\bcurl\b(?!.*(localhost|127\.0\.0\.1|\[::1\]|\bip6-localhost\b))\s+.*https?://"),
    re.compile(r"\bwget\b(?!.*(localhost|127\.0\.0\.1|\[::1\]|\bip6-localhost\b))\s+.*https?://"),
    re.compile(r"\bnc\b\s+(?!.*(localhost|127\.0\.0\.1|::1)).*\d"),
    re.compile(r"\bncat\b\s+(?!.*(localhost|127\.0\.0\.1|::1)).*\d"),
    re.compile(r"/dev/tcp/(?!localhost|127\.0\.0\.1|::1)"),
    re.compile(r"/dev/udp/(?!localhost|127\.0\.0\.1|::1)"),
]

# 4. Cluster API access from inside the pod (prevent lateral movement).
_CLUSTER_API_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bkubectl\b"),
    re.compile(r"\bhelm\b"),
    re.compile(r"\bkubeadm\b"),
    # Direct K8s API calls via service account token.
    re.compile(r"kubernetes\.default(\.svc)?"),
    re.compile(r"/var/run/secrets/kubernetes\.io/serviceaccount/token"),
]

# 5. Package installation (prevents image mutation).
_PACKAGE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bapt(-get)?\s+(install|remove|upgrade|purge)\b"),
    re.compile(r"\byum\s+(install|remove|update|upgrade)\b"),
    re.compile(r"\bdnf\s+(install|remove|update|upgrade)\b"),
    re.compile(r"\bapk\s+(add|del|upgrade)\b"),
    re.compile(r"\bpip\s+install\b"),
    re.compile(r"\bnpm\s+(install|i)\b"),
]

_DANGEROUS_PATTERNS: list[re.Pattern[str]] = (
    _WRITE_PATTERNS + _PROCESS_PATTERNS + _NETWORK_PATTERNS + _CLUSTER_API_PATTERNS + _PACKAGE_PATTERNS
)

AGENTIC_SYSTEM_PROMPT = """\
You are a Kubernetes workload analyst. You receive a workload profile \
collected from Kubernetes API metadata and your job is to determine what \
shell commands to run inside the pod's containers to understand the \
workload's runtime behavior, configuration, dependencies, and health.

Respond ONLY with a JSON object. Two response types:

1. Request commands:
{
  "done": false,
  "commands": [
    {"command": "cat /etc/nginx/nginx.conf 2>/dev/null", "container": "nginx", "purpose": "Read nginx config"}
  ],
  "reasoning": "Brief explanation of strategy"
}

2. Final profile update (when you have enough information):
{
  "done": true,
  "profile_updates": {
    "network_listeners": [{"port": 8080, "protocol": "HTTP", "purpose": "API server"}],
    "outbound_connections": [{"destination": "postgres.default:5432", "protocol": "PostgreSQL"}],
    "config_files": [{"path": "/etc/nginx/nginx.conf", "format": "nginx", "key_fields": ["upstream", "server"]}]
  },
  "summary": "One-paragraph description of what this workload does"
}

Rules:
- Read freely: cat, ls, find, grep, head, stat, readlink, strings, ps, ss, \
netstat, env, nginx -T, redis-cli INFO, etc. are all fine
- You may read any file the container can access — including configs, /proc, \
application data, anything you need to understand the workload
- HTTP probes to localhost (curl/wget to localhost/127.0.0.1) are encouraged \
for health and metrics endpoint discovery
- Do NOT request commands that: mutate state (rm, chmod, chown, mv, sed -i), \
kill processes (kill, systemctl stop/restart), reach external networks \
(curl/wget to non-localhost), touch the K8s API (kubectl, helm, service \
account token), or install packages (apt/yum/apk/pip/npm install)
- Target specific containers by name when the pod has multiple containers
- If a container has no shell, skip it and try others
- Keep commands efficient — prefer targeted reads over broad exploration

DEPENDENCY EXTRACTION (critical — this is the main value of this scan):
- When you read a config file, scan it for references to OTHER services: \
hostnames, connection strings, upstream blocks, proxy_pass, DATABASE_URL, \
service DNS names like "postgres.app-team", "redis:6379", etc.
- Every such reference MUST become an entry in outbound_connections. Do not \
just mention them in the summary — they belong in the structured field.
- Prefer the format "service_name.namespace:port" for destinations (matches \
Kubernetes DNS). If you only know an IP, use "ip:port". If external, use \
the hostname.
- Also extract dependencies from: env var values you see in /proc/1/environ \
or ps output, nginx upstream/proxy_pass blocks, database connection strings, \
Redis/Kafka broker lists, SMTP hosts.
- If a command-line flag reveals another service (e.g. --db-host=postgres), \
that's a dependency — add it.

RESPONSE FORMAT:
- In profile_updates, use ONLY these field names: network_listeners, \
outbound_connections, config_files, env_vars
- network_listeners: [{"port": int, "protocol": str, "purpose": str}]
- outbound_connections: [{"destination": "name.ns:port", "protocol": str}]
- config_files: [{"path": str, "format": str, "key_fields": [str]}]
- env_vars: [{"name": str, "value": str, "source": str}]
"""


def run_agentic_scan(
    kube: KubeClient,
    config: ScanConfig,
    store: KnowledgeStore,
    tracker: ProgressTracker,
    services: list[dict[str, Any]],
    fingerprints: FingerprintTracker | None,
    ai: AIProvider,
) -> None:
    """Execute Phase 3: AI-driven agentic scan of each workload."""
    tracker.phase_header("Phase 3: Agentic Scan")

    pod_exec = PodExec(core_api=kube.core, timeout=config.timeout)
    profiles = _load_profiles(store)
    tracker.start("agentic_scan", len(profiles))

    completed = 0
    for profile in profiles:
        ns = profile.namespace
        name = profile.name
        tracker.update(f"{ns}/{name}", completed)

        if profile.workload_type == "CronJob":
            tracker.log(f"Skipping {ns}/{name} (CronJob, no persistent pod)")
            completed += 1
            continue

        if fingerprints and not config.force_rescan and not fingerprints.was_changed_this_scan(ns, name):
            tracker.log(f"{ns}/{name} unchanged, skipping agentic scan")
            completed += 1
            continue

        if ai.budget_exhausted:
            tracker.warning(f"AI budget exhausted, skipping remaining workloads (at {ns}/{name})")
            break

        pods = kube.list_pods(ns)
        pod = pick_running_pod(pods, name)
        if pod is None:
            tracker.warning(f"{ns}/{name}: no running pod found")
            completed += 1
            continue

        pod_name = pod.metadata.name

        # Run the agentic conversation loop
        _run_agentic_loop(
            profile=profile,
            pod_exec=pod_exec,
            pod_name=pod_name,
            namespace=ns,
            services=services,
            ai=ai,
            config=config,
            store=store,
            tracker=tracker,
        )

        # Bump confidence
        profile.confidence = min(0.9, profile.confidence + 0.6)
        profile.explored_at = datetime.now(UTC)

        # Write updated profile
        ns_dir = store.namespace_dir(ns)
        store.write_model(ns_dir / f"{name}.profile.json", profile)

        completed += 1
        tracker.item(f"{ns}/{name}", f"agentic scan complete, confidence={profile.confidence:.1f}")


def _run_agentic_loop(
    profile: WorkloadProfile,
    pod_exec: PodExec,
    pod_name: str,
    namespace: str,
    services: list[dict[str, Any]],
    ai: AIProvider,
    config: ScanConfig,
    store: KnowledgeStore,
    tracker: ProgressTracker,
) -> None:
    """Run the iterative LLM conversation loop for one workload."""
    max_rounds = config.agentic_max_rounds
    max_execs = config.agentic_max_execs
    total_execs = 0

    # Prepare artifact storage
    artifact_dir = store.namespace_dir(namespace) / f"{profile.name}.raw" / "agentic"
    artifact_dir.mkdir(parents=True, exist_ok=True)

    # Build initial context
    container_names = [c.name for c in profile.containers]
    service_summary = [
        {"name": s["name"], "namespace": s["namespace"], "ports": s.get("ports", []), "clusterIP": s.get("clusterIP")}
        for s in services
    ]

    profile_json = profile.model_dump_json(indent=2)
    # Truncate large profiles to stay within context limits
    if len(profile_json) > 8000:
        profile_data = profile.model_dump()
        # Keep essential fields only
        for key in ("health", "resilience", "image_fingerprint"):
            profile_data.pop(key, None)
        profile_json = json.dumps(profile_data, indent=2, default=str)
    # Defense in depth: redact secrets even in Phase 1 profile data.
    profile_json = redact_secrets(profile_json)

    initial_user_msg = (
        f"Workload profile:\n```json\n{profile_json}\n```\n\n"
        f"Available containers: {container_names}\n\n"
        f"Cluster services (for dependency context):\n```json\n{json.dumps(service_summary, indent=2)}\n```\n\n"
        "What commands should I run to understand this workload better?"
    )

    messages: list[dict[str, str]] = [
        {"role": "system", "content": AGENTIC_SYSTEM_PROMPT},
        {"role": "user", "content": initial_user_msg},
    ]

    for round_num in range(1, max_rounds + 1):
        if ai.budget_exhausted:
            tracker.log(f"{namespace}/{profile.name}: AI budget exhausted at round {round_num}")
            break

        # Get LLM response
        response = ai.complete_json_multi(messages, temperature=0.0)

        # Save request/response artifacts
        _save_artifact(artifact_dir, f"round_{round_num:03d}_request.json", messages[-1])
        _save_artifact(artifact_dir, f"round_{round_num:03d}_response.json", response)

        if response is None:
            tracker.log(f"{namespace}/{profile.name}: AI returned invalid response at round {round_num}")
            break

        if not isinstance(response, dict):
            tracker.log(f"{namespace}/{profile.name}: unexpected response type at round {round_num}")
            break

        # Check if LLM is done
        if response.get("done"):
            validation_error = _validate_profile_updates(response)
            if validation_error and not ai.budget_exhausted:
                # Give the LLM one chance to fix the schema.
                logger.info("profile_updates validation failed, retrying: %s", validation_error)
                messages.append({"role": "assistant", "content": json.dumps(response)})
                messages.append(
                    {
                        "role": "user",
                        "content": (
                            f"Your profile_updates had a schema issue: {validation_error}\n\n"
                            "Please resend your final response with valid profile_updates."
                        ),
                    }
                )
                retry_response = ai.complete_json_multi(messages, temperature=0.0)
                _save_artifact(artifact_dir, f"round_{round_num:03d}_retry_response.json", retry_response)
                if isinstance(retry_response, dict) and retry_response.get("done"):
                    response = retry_response
            _apply_profile_updates(profile, response, namespace, services)
            _save_artifact(artifact_dir, "final_update.json", response)
            tracker.log(f"{namespace}/{profile.name}: agentic scan completed in {round_num} rounds")
            break

        # Execute requested commands
        commands = response.get("commands", [])
        if not commands:
            tracker.log(f"{namespace}/{profile.name}: no commands requested at round {round_num}")
            break

        valid_containers = {c.name for c in profile.containers}
        exec_results: list[dict[str, Any]] = []
        for cmd_req in commands:
            if total_execs >= max_execs:
                exec_results.append({"command": cmd_req.get("command", ""), "error": "exec limit reached"})
                continue

            command = cmd_req.get("command", "")
            container = cmd_req.get("container")
            purpose = cmd_req.get("purpose", "")

            if not command:
                continue

            if not _is_safe_command(command):
                exec_results.append({"command": command, "error": "command rejected (unsafe)", "purpose": purpose})
                logger.warning("Rejected unsafe command from LLM: %s", command)
                continue

            # Validate container name against the profile's containers.
            if container and container not in valid_containers:
                err = f"container '{container}' not found in pod. Valid containers: {sorted(valid_containers)}"
                exec_results.append({"command": command, "error": err, "purpose": purpose})
                continue

            output = pod_exec.run_safe(namespace, pod_name, command, container)
            total_execs += 1

            if output and len(output) > _MAX_OUTPUT_BYTES:
                output = output[:_MAX_OUTPUT_BYTES] + "\n... [truncated]"

            # Redact secrets BEFORE the output leaves this process (sent to LLM provider).
            safe_output = redact_secrets(output) if output else None

            exec_results.append(
                {
                    "command": command,
                    "container": container,
                    "purpose": purpose,
                    "output": safe_output or "(no output)",
                    "success": output is not None,
                }
            )

        _save_artifact(artifact_dir, f"round_{round_num:03d}_exec_results.json", exec_results)

        # Build follow-up message with results
        results_text = json.dumps(exec_results, indent=2)
        follow_up = f"Command results:\n```json\n{results_text}\n```\n\n"

        if total_execs >= max_execs:
            follow_up += "Exec limit reached. Please provide your final profile update with what you've learned so far."
        elif round_num >= max_rounds:
            follow_up += (
                "This is the last round. Please provide your final profile update with what you've learned so far."
            )
        else:
            follow_up += "Do you need more commands, or can you provide a final profile update?"

        # Add assistant response and user follow-up to conversation
        messages.append({"role": "assistant", "content": json.dumps(response)})
        messages.append({"role": "user", "content": follow_up})
    else:
        # Max rounds reached without LLM saying "done" — force a final call
        if not ai.budget_exhausted:
            messages.append({"role": "assistant", "content": json.dumps(response) if response else "{}"})
            messages.append(
                {
                    "role": "user",
                    "content": "Maximum rounds reached. Please provide your final profile update now.",
                }
            )
            final_response = ai.complete_json_multi(messages, temperature=0.0)
            if isinstance(final_response, dict) and final_response.get("done"):
                _apply_profile_updates(profile, final_response, namespace, services)
                _save_artifact(artifact_dir, "final_update.json", final_response)


def _is_safe_command(command: str) -> bool:
    """Check if a command is safe to execute (read-only)."""
    return all(not pattern.search(command) for pattern in _DANGEROUS_PATTERNS)


# Allowed keys in profile_updates. Used for validation + retry when the LLM
# uses wrong field names (e.g. "ports" instead of "network_listeners").
_ALLOWED_UPDATE_KEYS = frozenset({"network_listeners", "outbound_connections", "config_files", "env_vars"})


def _validate_profile_updates(response: dict[str, Any]) -> str | None:
    """Return a human-readable error if profile_updates has unknown fields.

    Returns None if valid (or if there are no updates to validate).
    The error message is fed back to the LLM for a retry.
    """
    updates = response.get("profile_updates")
    if not updates:
        return None
    if not isinstance(updates, dict):
        return "profile_updates must be a JSON object, not a list or scalar"

    unknown = set(updates.keys()) - _ALLOWED_UPDATE_KEYS
    if unknown:
        return (
            f"profile_updates contains unknown fields: {sorted(unknown)}. "
            f"Valid fields are: {sorted(_ALLOWED_UPDATE_KEYS)}. "
            "Please resend profile_updates using only these field names."
        )

    # Validate types of each known field
    for key in _ALLOWED_UPDATE_KEYS:
        if key in updates and not isinstance(updates[key], list):
            return f"profile_updates.{key} must be a list, got {type(updates[key]).__name__}"

    # Validate shape of each entry
    for nl in updates.get("network_listeners", []):
        if not isinstance(nl, dict) or "port" not in nl:
            return "Each network_listeners entry must be an object with at least a 'port' field"
    for oc in updates.get("outbound_connections", []):
        if not isinstance(oc, dict) or "destination" not in oc:
            return "Each outbound_connections entry must be an object with at least a 'destination' field"

    return None


def _apply_profile_updates(
    profile: WorkloadProfile,
    response: dict[str, Any],
    namespace: str,
    services: list[dict[str, Any]],
) -> None:
    """Merge LLM-provided profile updates into the existing profile."""
    updates = response.get("profile_updates", {})
    if not updates:
        return

    # Network listeners
    for nl_data in updates.get("network_listeners", []):
        try:
            port = nl_data.get("port")
            if port and not any(nl.port == port for nl in profile.network_listeners):
                profile.network_listeners.append(
                    NetworkListener(
                        port=port,
                        protocol=nl_data.get("protocol", "TCP"),
                        purpose=nl_data.get("purpose"),
                    )
                )
        except (ValueError, TypeError):
            logger.debug("Skipping invalid network listener from LLM: %s", nl_data)

    # Outbound connections
    for conn_data in updates.get("outbound_connections", []):
        try:
            dest = conn_data.get("destination", "")
            if dest and not any(oc.destination == dest for oc in profile.outbound_connections):
                profile.outbound_connections.append(
                    OutboundConnection(
                        destination=dest,
                        protocol=conn_data.get("protocol", "TCP"),
                    )
                )
        except (ValueError, TypeError):
            logger.debug("Skipping invalid outbound connection from LLM: %s", conn_data)

    # Config files
    for cf_data in updates.get("config_files", []):
        path = cf_data.get("path", "")
        if path and not any(cf.get("path") == path for cf in profile.config_files):
            profile.config_files.append(cf_data)

    # Environment variables
    for env_data in updates.get("env_vars", []):
        try:
            name = env_data.get("name", "")
            if name and not any(ev.name == name for ev in profile.env_vars):
                profile.env_vars.append(
                    EnvVar(
                        name=name,
                        source=env_data.get("source", "agentic"),
                        value_hash=hash_value(env_data.get("value", name)),
                    )
                )
        except (ValueError, TypeError):
            logger.debug("Skipping invalid env var from LLM: %s", env_data)

    # LLM-generated summary of the workload
    summary = response.get("summary", "")
    if summary:
        profile.summary = summary


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


def _save_artifact(artifact_dir: Path, filename: str, data: Any) -> None:
    """Save a conversation artifact to disk."""
    try:
        (artifact_dir / filename).write_text(json.dumps(data, indent=2, default=str))
    except (OSError, TypeError) as exc:
        logger.debug("Failed to save artifact %s: %s", filename, exc)


# Observed from real scans: typical agentic scan uses ~2.3 rounds/workload
# with ~2900 input tokens and ~1000 output tokens per workload total.
_AVG_INPUT_TOKENS_PER_WORKLOAD = 2900
_AVG_OUTPUT_TOKENS_PER_WORKLOAD = 1000


def _estimate_cost(model: str, workload_count: int) -> float | None:
    """Estimate scan cost based on model pricing and typical token usage.

    Returns None if pricing is unknown for the model.
    """
    if workload_count == 0:
        return 0.0
    try:
        import litellm

        model_info = litellm.get_model_info(model)
        input_cost = model_info.get("input_cost_per_token", 0) or 0
        output_cost = model_info.get("output_cost_per_token", 0) or 0
        if input_cost == 0 and output_cost == 0:
            return None
        per_workload = _AVG_INPUT_TOKENS_PER_WORKLOAD * input_cost + _AVG_OUTPUT_TOKENS_PER_WORKLOAD * output_cost
        return per_workload * workload_count
    except Exception:
        logger.debug("Could not estimate cost for model=%s", model, exc_info=True)
        return None
