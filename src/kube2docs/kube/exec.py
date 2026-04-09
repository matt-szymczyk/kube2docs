"""kubectl exec helpers for running commands inside pods."""

import logging
from typing import Any

from kubernetes.client import CoreV1Api
from kubernetes.client.rest import ApiException
from kubernetes.stream import stream

logger = logging.getLogger(__name__)

# Shells to try, in order of preference.
_SHELLS = ("/bin/bash", "/bin/sh", "/bin/ash")


class ExecError(Exception):
    """Raised when exec into a pod fails."""


class PodExec:
    """Execute commands inside Kubernetes pods."""

    def __init__(self, core_api: CoreV1Api, timeout: int = 30) -> None:
        self.core = core_api
        self.timeout = timeout

    def run(
        self,
        namespace: str,
        pod_name: str,
        command: str,
        container: str | None = None,
        timeout: int | None = None,
    ) -> str:
        """Execute a command in a pod and return stdout+stderr combined.

        Raises ExecError if the pod has no usable shell or exec is denied.
        """
        shell = self._find_shell(namespace, pod_name, container)
        if shell is None:
            raise ExecError(f"No usable shell in {namespace}/{pod_name}")

        exec_command = [shell, "-c", command]
        tout = timeout or self.timeout
        try:
            resp = stream(
                self.core.connect_get_namespaced_pod_exec,
                pod_name,
                namespace,
                command=exec_command,
                container=container or "",
                stderr=True,
                stdin=False,
                stdout=True,
                tty=False,
                _request_timeout=tout,
                _preload_content=True,
            )
            return resp if isinstance(resp, str) else str(resp)
        except ApiException as exc:
            raise ExecError(f"Exec failed in {namespace}/{pod_name}: {exc.reason}") from exc
        except Exception as exc:
            raise ExecError(f"Exec failed in {namespace}/{pod_name}: {exc}") from exc

    def _find_shell(
        self,
        namespace: str,
        pod_name: str,
        container: str | None,
    ) -> str | None:
        """Probe for available shell binaries."""
        for shell in _SHELLS:
            try:
                resp = stream(
                    self.core.connect_get_namespaced_pod_exec,
                    pod_name,
                    namespace,
                    command=[shell, "-c", "echo ok"],
                    container=container or "",
                    stderr=True,
                    stdin=False,
                    stdout=True,
                    tty=False,
                    _request_timeout=5,
                    _preload_content=True,
                )
                text = resp if isinstance(resp, str) else str(resp)
                if "ok" in text:
                    return shell
            except Exception:
                continue
        return None

    def run_safe(
        self,
        namespace: str,
        pod_name: str,
        command: str,
        container: str | None = None,
        timeout: int | None = None,
    ) -> str | None:
        """Like run(), but returns None instead of raising on failure."""
        try:
            return self.run(namespace, pod_name, command, container, timeout)
        except ExecError as exc:
            logger.debug("exec failed (%s): %s", command, exc)
            return None


def pick_running_pod(pods: list[Any], workload_name: str) -> Any | None:
    """Pick a running pod belonging to a workload.

    Returns the first pod in Running phase, or None.
    """
    for pod in pods:
        owner = _pod_owned_by(pod, workload_name)
        if owner and pod.status.phase == "Running":
            return pod
    return None


def _pod_owned_by(pod: Any, workload_name: str) -> bool:
    """Check if a pod belongs to a workload (by owner reference chain)."""
    for ref in pod.metadata.owner_references or []:
        # Direct match (StatefulSet, DaemonSet, Job)
        if ref.name == workload_name:
            return True
        # ReplicaSet — strip hash suffix to get Deployment name
        if ref.kind == "ReplicaSet":
            parts = ref.name.rsplit("-", 1)
            if parts[0] == workload_name:
                return True
    return False
