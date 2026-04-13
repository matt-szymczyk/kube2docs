"""Configuration loading and validation."""

from dataclasses import dataclass, field
from pathlib import Path

# Namespaces that are always excluded from scanning.
SYSTEM_NAMESPACES = frozenset(
    {
        "kube-system",
        "kube-public",
        "kube-node-lease",
        "default",
    }
)

# Namespace prefixes that are always excluded.
EXCLUDED_PREFIXES = (
    "istio-",
    "cert-manager",
    "ingress-",
    "monitoring",
    "flux-",
    "argocd",
    "local-path-storage",
)

SKIP_ANNOTATION = "kube2docs.io/skip"

# Shared port → protocol mapping used by extractor and survey.
PORT_PROTOCOL_MAP: dict[int, str] = {
    80: "HTTP",
    443: "HTTPS",
    5432: "PostgreSQL",
    3306: "MySQL",
    6379: "Redis",
    27017: "MongoDB",
    9090: "HTTP",
    9092: "Kafka",
    8080: "HTTP",
    8443: "HTTPS",
    53: "DNS",
    6443: "Kubernetes API",
}


@dataclass
class ScanConfig:
    """Configuration for a scan run."""

    kubeconfig: str | None = None
    context: str | None = None
    namespaces: list[str] | None = None
    output: Path = Path("./kb")
    depth: str = "deep"
    force_rescan: bool = False
    reveal_configmap_values: bool = False
    timeout: int = 300
    dry_run: bool = False
    agentic: bool = False
    agentic_model: str | None = None
    agentic_api_key: str | None = None
    agentic_api_base: str | None = None
    agentic_max_rounds: int = 5
    agentic_max_execs: int = 20
    agentic_max_calls: int = 200
    _excluded_namespaces: frozenset[str] = field(default_factory=lambda: SYSTEM_NAMESPACES)

    def is_namespace_excluded(self, namespace: str) -> bool:
        """Check if a namespace should be skipped."""
        if namespace in self._excluded_namespaces:
            return True
        return any(namespace.startswith(prefix) for prefix in EXCLUDED_PREFIXES)
