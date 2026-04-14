"""Tests for OCI image-layer inspection (no network — pure unit tests)."""

import pytest

from kube2docs.phases.image_inspect import (
    _ImageRef,
    _extract_from_config,
    _parse_alpine_packages,
    _parse_debian_packages,
    _parse_image_ref,
    _parse_www_authenticate,
)


class TestParseImageRef:
    """Image reference parsing covers the full Docker/OCI naming spec."""

    def test_bare_official_image(self) -> None:
        ref = _parse_image_ref("nginx")
        assert ref.registry == "registry-1.docker.io"
        assert ref.repository == "library/nginx"
        assert ref.reference == "latest"

    def test_official_image_with_tag(self) -> None:
        ref = _parse_image_ref("nginx:1.25")
        assert ref.registry == "registry-1.docker.io"
        assert ref.repository == "library/nginx"
        assert ref.reference == "1.25"

    def test_user_image_with_tag(self) -> None:
        ref = _parse_image_ref("myorg/myapp:v2.0")
        assert ref.registry == "registry-1.docker.io"
        assert ref.repository == "myorg/myapp"
        assert ref.reference == "v2.0"

    def test_ghcr_image(self) -> None:
        ref = _parse_image_ref("ghcr.io/owner/repo:sha-abc123")
        assert ref.registry == "ghcr.io"
        assert ref.repository == "owner/repo"
        assert ref.reference == "sha-abc123"

    def test_gcr_image(self) -> None:
        ref = _parse_image_ref("gcr.io/project/image:prod")
        assert ref.registry == "gcr.io"
        assert ref.repository == "project/image"
        assert ref.reference == "prod"

    def test_private_registry_with_port(self) -> None:
        ref = _parse_image_ref("registry.company.com:5000/app/service:v1.0")
        assert ref.registry == "registry.company.com:5000"
        assert ref.repository == "app/service"
        assert ref.reference == "v1.0"

    def test_digest_reference(self) -> None:
        digest = "sha256:abc123def456"
        ref = _parse_image_ref(f"nginx@{digest}")
        assert ref.reference == digest
        assert ref.registry == "registry-1.docker.io"
        assert ref.repository == "library/nginx"

    def test_docker_io_alias_normalized(self) -> None:
        ref = _parse_image_ref("docker.io/library/redis:7")
        assert ref.registry == "registry-1.docker.io"

    def test_localhost_registry(self) -> None:
        ref = _parse_image_ref("localhost:5000/myapp:dev")
        assert ref.registry == "localhost:5000"
        assert ref.repository == "myapp"
        assert ref.reference == "dev"

    def test_deep_nested_path(self) -> None:
        ref = _parse_image_ref("ghcr.io/org/team/service:latest")
        assert ref.registry == "ghcr.io"
        assert ref.repository == "org/team/service"


class TestExtractFromConfig:
    """OCI image config blob extraction."""

    def _make_config(self, **overrides: object) -> dict:
        base: dict = {
            "config": {
                "Entrypoint": ["/app/server"],
                "Cmd": ["--port=8080"],
                "User": "nonroot:nonroot",
                "WorkingDir": "/app",
                "ExposedPorts": {"8080/tcp": {}, "9090/tcp": {}},
                "Env": [
                    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                    "DATABASE_URL=",
                    "LOG_LEVEL=info",
                ],
                "Labels": {
                    "org.opencontainers.image.source": "https://github.com/org/repo",
                    "org.opencontainers.image.version": "1.2.3",
                    "internal.deploy.team": "platform",
                },
            }
        }
        base["config"].update(overrides)
        return base

    def test_extracts_entrypoint(self) -> None:
        result = _extract_from_config(self._make_config())
        assert result["entrypoint"] == ["/app/server"]

    def test_extracts_cmd(self) -> None:
        result = _extract_from_config(self._make_config())
        assert result["cmd"] == ["--port=8080"]

    def test_extracts_user(self) -> None:
        result = _extract_from_config(self._make_config())
        assert result["user"] == "nonroot:nonroot"

    def test_extracts_working_dir(self) -> None:
        result = _extract_from_config(self._make_config())
        assert result["working_dir"] == "/app"

    def test_extracts_declared_ports(self) -> None:
        result = _extract_from_config(self._make_config())
        assert sorted(result["declared_ports"]) == [8080, 9090]

    def test_extracts_env_var_names_not_values(self) -> None:
        result = _extract_from_config(self._make_config())
        env_names = result["baked_env_vars"]
        assert "DATABASE_URL" in env_names
        assert "LOG_LEVEL" in env_names
        # Values must never appear
        assert "info" not in env_names

    def test_surfaces_selected_labels_only(self) -> None:
        result = _extract_from_config(self._make_config())
        labels = result["labels"]
        assert "org.opencontainers.image.source" in labels
        assert "org.opencontainers.image.version" in labels
        # Internal/non-surfaced labels excluded
        assert "internal.deploy.team" not in labels

    def test_missing_entrypoint_omitted(self) -> None:
        result = _extract_from_config(self._make_config(Entrypoint=None))
        assert "entrypoint" not in result

    def test_no_exposed_ports(self) -> None:
        result = _extract_from_config(self._make_config(ExposedPorts={}))
        assert "declared_ports" not in result

    def test_flat_config_without_nesting(self) -> None:
        # Some registries return config at the top level without a "config" key
        flat = {
            "Entrypoint": ["/bin/app"],
            "ExposedPorts": {"3000/tcp": {}},
            "Env": ["NODE_ENV=production"],
        }
        result = _extract_from_config(flat)
        assert result["entrypoint"] == ["/bin/app"]
        assert result["declared_ports"] == [3000]
        assert "NODE_ENV" in result["baked_env_vars"]

    def test_invalid_port_format_ignored(self) -> None:
        cfg = self._make_config(ExposedPorts={"notaport/tcp": {}, "8080/tcp": {}})
        result = _extract_from_config(cfg)
        assert result["declared_ports"] == [8080]


class TestParseAlpinePackages:
    """Alpine /lib/apk/db/installed parser."""

    _SAMPLE = """\
C:Q1somebase64hash==
P:musl
V:1.2.4-r2
A:x86_64
S:383604
I:622592
T:the musl c library (libc) implementation
U:https://musl.libc.org/
L:MIT

C:Q1anotherhash==
P:busybox
V:1.36.1-r15
A:x86_64
T:Size optimized toolbox of many common UNIX utilities
L:GPL-2.0-only

P:ssl_client
V:1.36.1-r15
T:EXternal ssl_client for busybox wget
"""

    def test_parses_package_names(self) -> None:
        pkgs = _parse_alpine_packages(self._SAMPLE)
        names = [p["name"] for p in pkgs]
        assert "musl" in names
        assert "busybox" in names

    def test_parses_versions(self) -> None:
        pkgs = _parse_alpine_packages(self._SAMPLE)
        musl = next(p for p in pkgs if p["name"] == "musl")
        assert musl["version"] == "1.2.4-r2"

    def test_parses_descriptions(self) -> None:
        pkgs = _parse_alpine_packages(self._SAMPLE)
        musl = next(p for p in pkgs if p["name"] == "musl")
        assert "musl c library" in musl["description"]

    def test_handles_package_without_blank_line_at_end(self) -> None:
        # ssl_client above has no trailing blank line
        pkgs = _parse_alpine_packages(self._SAMPLE)
        names = [p["name"] for p in pkgs]
        assert "ssl_client" in names

    def test_empty_input(self) -> None:
        assert _parse_alpine_packages("") == []

    def test_single_package(self) -> None:
        content = "P:ca-certificates\nV:20240226-r0\nT:Common CA certificates\n\n"
        pkgs = _parse_alpine_packages(content)
        assert len(pkgs) == 1
        assert pkgs[0]["name"] == "ca-certificates"


class TestParseDebianPackages:
    """Debian /var/lib/dpkg/status parser."""

    _SAMPLE = """\
Package: base-files
Version: 12.4+deb12u1
Architecture: amd64
Maintainer: Santiago Vila <sanvila@debian.org>
Status: install ok installed
Description: Debian base system miscellaneous files
 This package contains the basic filesystem hierarchy required by Debian.

Package: libc6
Version: 2.36-9+deb12u7
Architecture: amd64
Description: GNU C Library: Shared libraries
 Contains the standard libraries that are used by nearly all programs on
 the system.

Package: libssl3
Version: 3.0.11-1~deb12u2
Architecture: amd64
Description: Secure Sockets Layer toolkit - shared libraries
"""

    def test_parses_package_names(self) -> None:
        pkgs = _parse_debian_packages(self._SAMPLE)
        names = [p["name"] for p in pkgs]
        assert "base-files" in names
        assert "libc6" in names
        assert "libssl3" in names

    def test_parses_versions(self) -> None:
        pkgs = _parse_debian_packages(self._SAMPLE)
        libc = next(p for p in pkgs if p["name"] == "libc6")
        assert libc["version"] == "2.36-9+deb12u7"

    def test_parses_description_first_line_only(self) -> None:
        pkgs = _parse_debian_packages(self._SAMPLE)
        libc = next(p for p in pkgs if p["name"] == "libc6")
        assert libc["description"] == "GNU C Library: Shared libraries"

    def test_handles_package_without_blank_line(self) -> None:
        # libssl3 has no trailing blank line
        pkgs = _parse_debian_packages(self._SAMPLE)
        names = [p["name"] for p in pkgs]
        assert "libssl3" in names

    def test_empty_input(self) -> None:
        assert _parse_debian_packages("") == []

    def test_single_package(self) -> None:
        content = "Package: tzdata\nVersion: 2024a-0+deb12u1\nDescription: time zone data\n"
        pkgs = _parse_debian_packages(content)
        assert len(pkgs) == 1
        assert pkgs[0]["name"] == "tzdata"
        assert pkgs[0]["version"] == "2024a-0+deb12u1"


class TestParseWwwAuthenticate:
    """WWW-Authenticate Bearer challenge parsing."""

    def test_docker_hub_format(self) -> None:
        header = 'Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/nginx:pull"'
        params = _parse_www_authenticate(header, "library/nginx")
        assert params["realm"] == "https://auth.docker.io/token"
        assert params["service"] == "registry.docker.io"
        assert "library/nginx" in params["scope"]

    def test_injects_default_scope_when_missing(self) -> None:
        header = 'Bearer realm="https://ghcr.io/token",service="ghcr.io"'
        params = _parse_www_authenticate(header, "org/repo")
        assert "org/repo" in params["scope"]

    def test_ignores_non_bearer_scheme(self) -> None:
        params = _parse_www_authenticate('Basic realm="Registry"', "repo")
        assert params == {}

    def test_empty_header(self) -> None:
        params = _parse_www_authenticate("", "repo")
        assert params == {}
