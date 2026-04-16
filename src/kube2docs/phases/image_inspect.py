"""OCI image-layer inspection — operational knowledge extraction without exec.

Implements the image-layer analysis tier of the multi-modal extraction pipeline.
Activated when pod exec fails: distroless containers, scratch-based images,
or environments where exec permissions are restricted.

Confidence tier: 0.5 — between survey (0.3, Kubernetes API declarations only)
and deep_inspect (0.7, live runtime exec). We see what is actually installed in
the image, but not live runtime state (open connections, active processes, etc.).

Authentication: supports anonymous pulls (public Docker Hub, GHCR, GCR public
repos). Private registries silently return None — the caller degrades gracefully.
"""

import contextlib
import gzip
import io
import json
import logging
import tarfile
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

from kube2docs.knowledge.schemas import EnvVar, NetworkListener, WorkloadProfile

logger = logging.getLogger(__name__)

# Maximum bytes to read per layer when scanning for package databases.
_MAX_LAYER_BYTES = 60 * 1024 * 1024  # 60 MB
# Maximum total bytes across all layer scans per image.
_MAX_TOTAL_BYTES = 200 * 1024 * 1024  # 200 MB
# Max layers to scan before giving up.
_MAX_LAYERS_SCANNED = 6

_MANIFEST_ACCEPT = ", ".join(
    [
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    ]
)

# Image labels worth surfacing in profiles.
_SURFACED_LABELS = frozenset(
    {
        "org.opencontainers.image.title",
        "org.opencontainers.image.description",
        "org.opencontainers.image.version",
        "org.opencontainers.image.url",
        "org.opencontainers.image.source",
        "org.opencontainers.image.licenses",
        "maintainer",
        "description",
    }
)

# Package database paths inside layer tarballs (without leading slash).
_PKG_DB_PATHS: dict[str, str] = {
    "var/lib/dpkg/status": "debian",
    "lib/apk/db/installed": "alpine",
}


@dataclass
class _ImageRef:
    registry: str  # e.g. "registry-1.docker.io"
    repository: str  # e.g. "library/nginx" or "myorg/myimage"
    reference: str  # tag or digest, e.g. "1.25" or "sha256:abc…"


def _parse_image_ref(image: str) -> _ImageRef:
    """Parse a Docker/OCI image reference into (registry, repository, reference).

    Handles:
      nginx                  → registry-1.docker.io, library/nginx, latest
      nginx:1.25             → registry-1.docker.io, library/nginx, 1.25
      myorg/app:tag          → registry-1.docker.io, myorg/app, tag
      ghcr.io/org/app:tag    → ghcr.io, org/app, tag
      app@sha256:abc…        → registry-1.docker.io, library/app, sha256:abc…
    """
    # Separate digest (@sha256:…) from the rest
    reference = "latest"
    if "@" in image:
        image, reference = image.split("@", 1)
    elif ":" in image:
        # Distinguish "registry:port/repo" from "repo:tag" by presence of /
        last_colon = image.rfind(":")
        last_slash = image.rfind("/")
        if last_colon > last_slash:
            image, reference = image[:last_colon], image[last_colon + 1 :]

    # Determine if the first path component is a registry hostname.
    # A hostname contains a dot or colon (port number), or equals "localhost".
    parts = image.split("/", 1)
    if len(parts) == 1:
        registry = "registry-1.docker.io"
        repository = f"library/{parts[0]}"
    elif "." in parts[0] or ":" in parts[0] or parts[0] == "localhost":
        registry = parts[0]
        repository = parts[1]
    else:
        registry = "registry-1.docker.io"
        repository = image

    # Normalise Docker Hub aliases
    if registry in ("docker.io", "index.docker.io"):
        registry = "registry-1.docker.io"

    return _ImageRef(registry=registry, repository=repository, reference=reference)


def _parse_www_authenticate(header: str, repository: str) -> dict[str, str]:
    """Parse a Bearer WWW-Authenticate challenge header into key/value pairs."""
    params: dict[str, str] = {}
    if not header.startswith("Bearer "):
        return params
    for part in header[len("Bearer "):].split(","):
        part = part.strip()
        if "=" in part:
            key, _, value = part.partition("=")
            params[key.strip()] = value.strip().strip('"')
    if "scope" not in params:
        params["scope"] = f"repository:{repository}:pull"
    return params


def _get_auth_token(ref: _ImageRef, timeout: int) -> str | None:
    """Obtain a registry pull token via the WWW-Authenticate challenge dance.

    Returns None for registries that allow anonymous access or are unreachable.
    """
    try:
        req = Request(f"https://{ref.registry}/v2/", headers={})
        urlopen(req, timeout=timeout).close()
        return None  # No auth challenge → anonymous access works
    except URLError as exc:
        if not hasattr(exc, "code") or getattr(exc, "code", 0) != 401:
            return None
        www_auth = getattr(exc, "headers", {}).get("WWW-Authenticate", "")
    except Exception:
        return None

    auth = _parse_www_authenticate(www_auth, ref.repository)
    realm = auth.get("realm", "")
    if not realm:
        return None

    params = []
    if "service" in auth:
        params.append(f"service={auth['service']}")
    params.append(f"scope={auth.get('scope', f'repository:{ref.repository}:pull')}")
    token_url = realm + "?" + "&".join(params)

    try:
        req = Request(token_url, headers={"Accept": "application/json"})
        with urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
            return str(data.get("token") or data.get("access_token", "")) or None
    except Exception:
        return None


def _fetch_json(url: str, token: str | None, accept: str, timeout: int) -> dict[str, Any] | None:
    """GET a JSON body from a registry endpoint."""
    headers: dict[str, str] = {"Accept": accept}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        with urlopen(Request(url, headers=headers), timeout=timeout) as resp:
            return json.loads(resp.read())  # type: ignore[no-any-return]
    except Exception as exc:
        logger.debug("Registry fetch failed %s: %s", url, exc)
        return None


def _resolve_manifest(ref: _ImageRef, token: str | None, timeout: int) -> dict[str, Any] | None:
    """Fetch the image manifest, resolving multi-arch indexes to linux/amd64."""
    url = f"https://{ref.registry}/v2/{ref.repository}/manifests/{ref.reference}"
    manifest = _fetch_json(url, token, _MANIFEST_ACCEPT, timeout)
    if manifest is None:
        return None

    media_type = manifest.get("mediaType", "")
    is_index = "manifest.list" in media_type or "image.index" in media_type or "manifests" in manifest

    if is_index:
        entries = manifest.get("manifests", [])
        chosen = next(
            (
                m
                for m in entries
                if m.get("platform", {}).get("os") == "linux"
                and m.get("platform", {}).get("architecture") == "amd64"
            ),
            entries[0] if entries else None,
        )
        if chosen is None:
            return None
        url = f"https://{ref.registry}/v2/{ref.repository}/manifests/{chosen['digest']}"
        manifest = _fetch_json(url, token, _MANIFEST_ACCEPT, timeout)

    return manifest


def _fetch_config(ref: _ImageRef, manifest: dict[str, Any], token: str | None, timeout: int) -> dict[str, Any] | None:
    """Fetch the OCI image config blob referenced in the manifest."""
    digest = (manifest.get("config") or {}).get("digest")
    if not digest:
        return None
    url = f"https://{ref.registry}/v2/{ref.repository}/blobs/{digest}"
    return _fetch_json(url, token, "application/json", timeout)


def _extract_from_config(config: dict[str, Any]) -> dict[str, Any]:
    """Extract operational knowledge from an OCI image config blob.

    Extracts declared ports, entrypoint/cmd, user, working dir, baked-in
    environment variable *names* (never values — they may contain secrets),
    and a curated subset of image labels.
    """
    cfg = config.get("config") or config
    result: dict[str, Any] = {}

    entrypoint = cfg.get("Entrypoint") or []
    cmd = cfg.get("Cmd") or []
    if entrypoint:
        result["entrypoint"] = entrypoint
    if cmd:
        result["cmd"] = cmd

    user = cfg.get("User")
    if user:
        result["user"] = user

    working_dir = cfg.get("WorkingDir")
    if working_dir:
        result["working_dir"] = working_dir

    # ExposedPorts: {"8080/tcp": {}} → [8080]
    ports: list[int] = []
    for port_proto in (cfg.get("ExposedPorts") or {}):
        with contextlib.suppress(ValueError):
            ports.append(int(port_proto.split("/")[0]))
    if ports:
        result["declared_ports"] = sorted(ports)

    # Baked env var *names* only — not values
    env_names = [e.split("=", 1)[0] for e in (cfg.get("Env") or []) if "=" in e]
    if env_names:
        result["baked_env_vars"] = env_names

    labels = {k: v for k, v in (cfg.get("Labels") or {}).items() if k in _SURFACED_LABELS}
    if labels:
        result["labels"] = labels

    return result


def _parse_alpine_packages(content: str) -> list[dict[str, str]]:
    """Parse Alpine /lib/apk/db/installed into a list of {name, version, description}."""
    packages: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in content.splitlines():
        if line.startswith("P:"):
            current["name"] = line[2:]
        elif line.startswith("V:") and "name" in current:
            current["version"] = line[2:]
        elif line.startswith("T:") and "name" in current:
            current["description"] = line[2:]
        elif line == "" and "name" in current:
            packages.append(current)
            current = {}
    if "name" in current:
        packages.append(current)
    return packages


def _parse_debian_packages(content: str) -> list[dict[str, str]]:
    """Parse Debian /var/lib/dpkg/status into a list of {name, version, description}."""
    packages: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in content.splitlines():
        if line.startswith("Package:"):
            if "name" in current:
                packages.append(current)
            current = {"name": line[len("Package:") :].strip()}
        elif line.startswith("Version:") and "name" in current:
            current["version"] = line[len("Version:") :].strip()
        elif line.startswith("Description:") and "name" in current:
            current["description"] = line[len("Description:") :].strip()
    if "name" in current:
        packages.append(current)
    return packages


def _scan_layer(
    ref: _ImageRef,
    digest: str,
    size: int,
    token: str | None,
    timeout: int,
    total_downloaded: list[int],
) -> dict[str, Any] | None:
    """Download one layer blob and scan it for OS package databases.

    Returns {"os": "alpine"|"debian", "packages": [...]} or None.
    Mutates total_downloaded[0] to track cumulative bytes fetched.
    """
    if size > _MAX_LAYER_BYTES or total_downloaded[0] + size > _MAX_TOTAL_BYTES:
        return None

    url = f"https://{ref.registry}/v2/{ref.repository}/blobs/{digest}"
    headers: dict[str, str] = {"Accept": "application/octet-stream"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        with urlopen(Request(url, headers=headers), timeout=timeout) as resp:
            raw = resp.read(_MAX_LAYER_BYTES)
        total_downloaded[0] += len(raw)
    except Exception as exc:
        logger.debug("Layer download failed %s: %s", digest[:16], exc)
        return None

    try:
        # Decompress gzip, then open as tar
        decompressed = io.BytesIO(gzip.decompress(raw))
        with tarfile.open(fileobj=decompressed) as tar:
            member_names = {m.name.lstrip("./"): m.name for m in tar.getmembers()}
            for db_path, os_name in _PKG_DB_PATHS.items():
                tar_name = member_names.get(db_path)
                if tar_name is None:
                    continue
                f = tar.extractfile(tar_name)
                if f is None:
                    continue
                content = f.read().decode("utf-8", errors="replace")
                pkgs = _parse_alpine_packages(content) if os_name == "alpine" else _parse_debian_packages(content)
                if pkgs:
                    return {"os": os_name, "packages": pkgs}
    except Exception as exc:
        logger.debug("Layer parse failed %s: %s", digest[:16], exc)

    return None


def _extract_packages(
    ref: _ImageRef,
    manifest: dict[str, Any],
    token: str | None,
    timeout: int,
) -> dict[str, Any] | None:
    """Scan image layers (smallest first) for OS package databases."""
    layers = manifest.get("layers") or []
    if not layers:
        return None

    sorted_layers = sorted(layers, key=lambda layer: layer.get("size", 0))
    total_downloaded: list[int] = [0]

    for layer in sorted_layers[:_MAX_LAYERS_SCANNED]:
        digest = layer.get("digest", "")
        size = layer.get("size", 0)
        if not digest:
            continue
        result = _scan_layer(ref, digest, size, token, timeout, total_downloaded)
        if result:
            return result

    return None


def apply_image_analysis(profile: WorkloadProfile, container_name: str, analysis: dict[str, Any]) -> None:
    """Merge image-layer analysis results into a WorkloadProfile.

    Populates:
    - profile.image_analysis[container_name] — full raw analysis
    - profile.network_listeners — from declared ports in image config
    - profile.env_vars — baked-in env var names from image config
    """
    profile.image_analysis[container_name] = analysis

    existing_ports = {nl.port for nl in profile.network_listeners}
    for port in analysis.get("declared_ports", []):
        if port not in existing_ports:
            profile.network_listeners.append(
                NetworkListener(
                    port=port,
                    protocol="TCP",
                    purpose="declared in image config",
                    evidence=f"image EXPOSE {port} (may be overridden by container args)",
                    verified=False,
                )
            )
            existing_ports.add(port)

    existing_env = {ev.name for ev in profile.env_vars}
    for env_name in analysis.get("baked_env_vars", []):
        if env_name not in existing_env and not env_name.startswith("PATH"):
            profile.env_vars.append(EnvVar(name=env_name, source="image_config", value_hash=""))
            existing_env.add(env_name)


def inspect_image(image_ref: str, timeout: int = 30) -> dict[str, Any] | None:
    """Extract operational knowledge from an OCI image without exec.

    Contacts the image's registry anonymously to retrieve:
    - Image config: entrypoint, declared ports, user, baked-in env var names, labels
    - Filesystem layers: installed OS packages (Alpine/Debian)

    Returns None if the registry is unreachable or the image is private.
    Callers should treat None as "unavailable" and not raise.

    Confidence of extracted data: 0.5 (image_inspect tier).
    """
    try:
        ref = _parse_image_ref(image_ref)
        token = _get_auth_token(ref, timeout)
        manifest = _resolve_manifest(ref, token, timeout)
        if manifest is None:
            logger.debug("No manifest for %s", image_ref)
            return None
        config = _fetch_config(ref, manifest, token, timeout)
        if config is None:
            logger.debug("No config blob for %s", image_ref)
            return None

        result = _extract_from_config(config)
        result["inspection_method"] = "image_layers"

        packages = _extract_packages(ref, manifest, token, timeout)
        if packages:
            result["packages"] = packages

        return result
    except Exception as exc:
        logger.debug("Image inspection failed for %s: %s", image_ref, exc)
        return None


class ImageInspectionTracker:
    """Stateful wrapper around inspect_image() that surfaces registry failures.

    Image inspection can fail silently for many reasons: air-gapped cluster,
    DNS resolution failure, network policy block, private registry without
    credentials. Without feedback, users would see partial profiles and not
    understand why packaged-state data is missing.

    This wrapper tracks failures per registry hostname. After the same
    registry fails `warn_after_failures` times, it emits a single warning via
    the supplied callback (intended to be the progress tracker's warning
    method). It keeps trying — the warning does not disable future attempts —
    but the user gets one clear signal per unreachable registry.
    """

    def __init__(
        self,
        timeout: int = 30,
        warn_callback: Callable[[str], None] | None = None,
        warn_after_failures: int = 3,
    ) -> None:
        self.timeout = timeout
        self._warn = warn_callback
        self._warn_threshold = warn_after_failures
        self._failures: dict[str, int] = {}
        self._warned: set[str] = set()
        self._successes: dict[str, int] = {}

    def inspect(self, image_ref: str) -> dict[str, Any] | None:
        """Call inspect_image() and track the outcome per registry."""
        result = inspect_image(image_ref, timeout=self.timeout)
        try:
            registry = _parse_image_ref(image_ref).registry
        except Exception:
            return result

        if result is None:
            self._failures[registry] = self._failures.get(registry, 0) + 1
            if (
                self._warn is not None
                and self._failures[registry] >= self._warn_threshold
                and registry not in self._warned
            ):
                self._warned.add(registry)
                self._warn(
                    f"image registry {registry!r} unreachable after "
                    f"{self._failures[registry]} attempts — packaged-state analysis "
                    f"will be missing for images pulled from it. "
                    f"Cluster may be air-gapped, or registry auth/network policy is blocking access."
                )
        else:
            self._successes[registry] = self._successes.get(registry, 0) + 1
        return result

    def summary(self) -> dict[str, dict[str, int]]:
        """Return per-registry success/failure counts for end-of-scan reporting."""
        registries = set(self._successes) | set(self._failures)
        return {
            r: {
                "successes": self._successes.get(r, 0),
                "failures": self._failures.get(r, 0),
            }
            for r in sorted(registries)
        }
