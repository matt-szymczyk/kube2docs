"""Kubernetes API wrapper."""

import logging
from typing import Any

from kubernetes import config
from kubernetes.client import (
    AppsV1Api,
    AutoscalingV1Api,
    BatchV1Api,
    CoreV1Api,
    NetworkingV1Api,
    PolicyV1Api,
    RbacAuthorizationV1Api,
)

logger = logging.getLogger(__name__)


class KubeClient:
    """Wrapper around the official Kubernetes Python client."""

    def __init__(self, kubeconfig: str | None = None, context: str | None = None) -> None:
        config.load_kube_config(config_file=kubeconfig, context=context)
        self.core = CoreV1Api()
        self.apps = AppsV1Api()
        self.batch = BatchV1Api()
        self.networking = NetworkingV1Api()
        self.autoscaling = AutoscalingV1Api()
        self.policy = PolicyV1Api()
        self.rbac = RbacAuthorizationV1Api()

    # --- Namespace ---

    def list_namespaces(self) -> list[str]:
        ns_list = self.core.list_namespace()
        return [ns.metadata.name for ns in ns_list.items]

    # --- Workloads ---

    def list_deployments(self, namespace: str) -> list[Any]:
        return self.apps.list_namespaced_deployment(namespace).items  # type: ignore[no-any-return]

    def list_statefulsets(self, namespace: str) -> list[Any]:
        return self.apps.list_namespaced_stateful_set(namespace).items  # type: ignore[no-any-return]

    def list_daemonsets(self, namespace: str) -> list[Any]:
        return self.apps.list_namespaced_daemon_set(namespace).items  # type: ignore[no-any-return]

    def list_cronjobs(self, namespace: str) -> list[Any]:
        return self.batch.list_namespaced_cron_job(namespace).items  # type: ignore[no-any-return]

    def list_jobs(self, namespace: str) -> list[Any]:
        return self.batch.list_namespaced_job(namespace).items  # type: ignore[no-any-return]

    # --- Pods ---

    def list_pods(self, namespace: str) -> list[Any]:
        return self.core.list_namespaced_pod(namespace).items  # type: ignore[no-any-return]

    # --- Services / Networking ---

    def list_services(self, namespace: str) -> list[Any]:
        return self.core.list_namespaced_service(namespace).items  # type: ignore[no-any-return]

    def list_ingresses(self, namespace: str) -> list[Any]:
        return self.networking.list_namespaced_ingress(namespace).items  # type: ignore[no-any-return]

    def list_network_policies(self, namespace: str) -> list[Any]:
        return self.networking.list_namespaced_network_policy(namespace).items  # type: ignore[no-any-return]

    # --- Config ---

    def list_configmaps(self, namespace: str) -> list[Any]:
        return self.core.list_namespaced_config_map(namespace).items  # type: ignore[no-any-return]

    def list_secrets(self, namespace: str) -> list[Any]:
        return self.core.list_namespaced_secret(namespace).items  # type: ignore[no-any-return]

    def get_configmap(self, namespace: str, name: str) -> Any:
        return self.core.read_namespaced_config_map(name, namespace)

    def get_secret(self, namespace: str, name: str) -> Any:
        return self.core.read_namespaced_secret(name, namespace)

    # --- Storage ---

    def list_pvcs(self, namespace: str) -> list[Any]:
        return self.core.list_namespaced_persistent_volume_claim(namespace).items  # type: ignore[no-any-return]

    # --- Autoscaling / Disruption ---

    def list_hpas(self, namespace: str) -> list[Any]:
        return self.autoscaling.list_namespaced_horizontal_pod_autoscaler(namespace).items  # type: ignore[no-any-return]

    def list_pdbs(self, namespace: str) -> list[Any]:
        return self.policy.list_namespaced_pod_disruption_budget(namespace).items  # type: ignore[no-any-return]

    # --- RBAC ---

    def list_roles(self, namespace: str) -> list[Any]:
        return self.rbac.list_namespaced_role(namespace).items  # type: ignore[no-any-return]

    def list_role_bindings(self, namespace: str) -> list[Any]:
        return self.rbac.list_namespaced_role_binding(namespace).items  # type: ignore[no-any-return]

    def list_cluster_roles(self) -> list[Any]:
        return self.rbac.list_cluster_role().items  # type: ignore[no-any-return]

    def list_cluster_role_bindings(self) -> list[Any]:
        return self.rbac.list_cluster_role_binding().items  # type: ignore[no-any-return]

    # --- Nodes ---

    def list_nodes(self) -> list[Any]:
        return self.core.list_node().items  # type: ignore[no-any-return]

    # --- Events ---

    def list_events(self, namespace: str) -> list[Any]:
        return self.core.list_namespaced_event(namespace).items  # type: ignore[no-any-return]
