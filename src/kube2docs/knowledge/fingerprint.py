"""Image digest and config version tracking for incremental scanning."""

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class FingerprintTracker:
    """Tracks image digests and configmap/secret resource versions.

    On re-scan, fingerprints are compared to decide which workloads need
    re-scanning.  Only workloads whose images or referenced configs have
    changed are re-processed (unless --force-rescan is set).
    """

    def __init__(self, output_dir: Path) -> None:
        self.fingerprint_file = output_dir / ".fingerprints.json"
        self.fingerprints: dict[str, dict[str, dict[str, str]]] = {}
        self._changed_this_scan: set[str] = set()
        self._load()

    def _load(self) -> None:
        if self.fingerprint_file.exists():
            try:
                self.fingerprints = json.loads(self.fingerprint_file.read_text())
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Could not load fingerprints file, starting fresh: %s", exc)
                self.fingerprints = {}

    def save(self) -> None:
        self.fingerprint_file.parent.mkdir(parents=True, exist_ok=True)
        self.fingerprint_file.write_text(json.dumps(self.fingerprints, indent=2))

    @staticmethod
    def workload_key(namespace: str, name: str) -> str:
        return f"{namespace}/{name}"

    def set_fingerprint(
        self,
        namespace: str,
        name: str,
        images: dict[str, str],
        config_versions: dict[str, str],
    ) -> None:
        """Store the current fingerprint for a workload."""
        key = self.workload_key(namespace, name)
        self.fingerprints[key] = {
            "images": images,
            "config_versions": config_versions,
        }

    def mark_changed(self, namespace: str, name: str) -> None:
        """Mark a workload as changed during this scan."""
        self._changed_this_scan.add(self.workload_key(namespace, name))

    def was_changed_this_scan(self, namespace: str, name: str) -> bool:
        """Check if a workload was marked as changed during this scan."""
        return self.workload_key(namespace, name) in self._changed_this_scan

    def get_fingerprint(self, namespace: str, name: str) -> dict[str, dict[str, str]] | None:
        """Return the stored fingerprint for a workload, or None if not tracked."""
        return self.fingerprints.get(self.workload_key(namespace, name))

    def has_changed(
        self,
        namespace: str,
        name: str,
        images: dict[str, str],
        config_versions: dict[str, str],
    ) -> bool:
        """Return True if the workload's images or config versions differ from the stored fingerprint."""
        key = self.workload_key(namespace, name)
        old = self.fingerprints.get(key)
        if old is None:
            return True
        return old.get("images") != images or old.get("config_versions") != config_versions

    def remove(self, namespace: str, name: str) -> bool:
        """Remove a workload's fingerprint. Returns True if it existed."""
        key = self.workload_key(namespace, name)
        return self.fingerprints.pop(key, None) is not None

    def tracked_workloads(self) -> list[str]:
        """Return all tracked workload keys (namespace/name)."""
        return list(self.fingerprints.keys())


def parse_image_digest(image_ref: str) -> str | None:
    """Extract the sha256 digest from an image reference like 'nginx@sha256:abc123...'."""
    if "@sha256:" in image_ref:
        return image_ref.split("@sha256:", 1)[1]
    return None
