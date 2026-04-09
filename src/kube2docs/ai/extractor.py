"""Parse command outputs into structured data using regex-based extraction.

All parsing is deterministic and local — no AI calls. AI is reserved for
the interpretation/writer layer where human judgment is needed.
"""

import re
from typing import Any

from kube2docs.config import PORT_PROTOCOL_MAP
from kube2docs.security.hasher import hash_value, is_sensitive_key


class Extractor:
    """Extracts structured data from raw command outputs via regex parsing."""

    # ------------------------------------------------------------------
    # Process list
    # ------------------------------------------------------------------

    def extract_process_info(self, ps_output: str, pod_name: str) -> dict[str, Any]:
        """Identify main process, language/runtime from ps output."""
        return _parse_processes(ps_output)

    # ------------------------------------------------------------------
    # Network listeners
    # ------------------------------------------------------------------

    def extract_listeners(self, net_output: str, pod_name: str) -> list[dict[str, Any]]:
        """Extract listening ports from ss/netstat output."""
        return _parse_listeners(net_output)

    # ------------------------------------------------------------------
    # Outbound connections
    # ------------------------------------------------------------------

    def extract_connections(
        self,
        conn_output: str,
        pod_name: str,
        known_services: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Extract outbound connections from ss/netstat output."""
        return _parse_connections(conn_output, known_services or [])

    # ------------------------------------------------------------------
    # Environment variables
    # ------------------------------------------------------------------

    def extract_env(self, env_output: str) -> list[dict[str, Any]]:
        """Parse /proc/1/environ output into name/value pairs (values hashed)."""
        return _parse_env(env_output)

    # ------------------------------------------------------------------
    # Disk usage
    # ------------------------------------------------------------------

    def extract_disk_usage(self, df_output: str) -> list[dict[str, Any]]:
        """Parse df -h output."""
        return _parse_df(df_output)

    # ------------------------------------------------------------------
    # Config files
    # ------------------------------------------------------------------

    def extract_config_file(self, content: str, file_path: str) -> dict[str, Any]:
        """Parse a config file and identify key fields."""
        return _parse_config(content, file_path)

    # ------------------------------------------------------------------
    # Health endpoint probing
    # ------------------------------------------------------------------

    def extract_health_response(self, body: str, url: str) -> dict[str, Any]:
        """Parse a health endpoint response."""
        status = (
            "healthy"
            if any(kw in body.lower() for kw in ("ok", "healthy", "alive", "ready", "true", "pass", "{}"))
            else "unknown"
        )
        return {"url": url, "status": status, "body_snippet": body[:200]}

    # ------------------------------------------------------------------
    # Metrics detection
    # ------------------------------------------------------------------

    def detect_metrics(self, body: str) -> dict[str, Any]:
        """Check if a response body looks like Prometheus metrics."""
        is_prometheus = bool(
            re.search(r"^# (HELP|TYPE) ", body, re.MULTILINE)
            or re.search(r"^\w+\{.*\}\s+[\d.]+", body, re.MULTILINE)
            or re.search(r"^\w+\s+[\d.]+$", body, re.MULTILINE)
        )
        metric_count = 0
        if is_prometheus:
            metric_count = len(re.findall(r"^# TYPE \w+", body, re.MULTILINE))
        return {
            "prometheus": is_prometheus,
            "metric_families": metric_count,
        }


# ======================================================================
# Regex-based parsers
# ======================================================================


def _parse_processes(ps_output: str) -> dict[str, Any]:
    """Parse ps aux output.

    Handles both full Linux ``ps aux`` (11 columns) and BusyBox/Alpine
    ``ps aux`` (4 columns: PID USER TIME COMMAND).
    """
    lines = ps_output.strip().splitlines()
    pid1_cmd = ""
    all_commands: list[str] = []

    for line in lines:
        stripped = line.strip()
        if not stripped or "PID" in stripped.split()[0:2]:
            continue
        # BusyBox: "    1 root      0:00 nginx: master process ..."
        m = re.match(r"\s*(\d+)\s+\S+\s+\S+\s+(.*)", stripped)
        if m:
            pid = m.group(1)
            cmd = m.group(2).strip()
        else:
            # Full Linux ps aux: USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND
            parts = stripped.split(None, 10)
            if len(parts) >= 11:
                pid = parts[1]
                cmd = parts[10]
            else:
                continue
        all_commands.append(cmd)
        if pid == "1":
            pid1_cmd = cmd

    # /proc/1/cmdline format (single line, null-separated already converted)
    if not pid1_cmd and len(lines) >= 1 and "PID" not in lines[0]:
        pid1_cmd = lines[0]

    language = _guess_language(pid1_cmd, all_commands)
    runtime = _guess_runtime(pid1_cmd, all_commands)

    return {
        "main_process": pid1_cmd.split()[0] if pid1_cmd else "unknown",
        "language": language,
        "runtime": runtime,
        "pid1_command": pid1_cmd,
    }


def _guess_language(pid1_cmd: str, commands: list[str]) -> str:
    all_text = " ".join(commands + [pid1_cmd]).lower()
    checks = [
        ("java", ["java ", "java.", "/jre/", "/jdk/"]),
        ("python", ["python", "/python"]),
        ("node", ["node ", "node.", "/node", "npm", "yarn"]),
        ("go", ["go ", "/go/"]),
        ("ruby", ["ruby", "rails", "puma", "unicorn"]),
        ("rust", []),  # hard to detect
        ("php", ["php", "php-fpm"]),
        ("dotnet", ["dotnet", "aspnet"]),
        ("nginx", ["nginx"]),
        ("postgres", ["postgres", "postmaster"]),
        ("redis", ["redis-server"]),
    ]
    for lang, patterns in checks:
        if any(p in all_text for p in patterns):
            return lang
    return "unknown"


def _guess_runtime(pid1_cmd: str, commands: list[str]) -> str:
    all_text = " ".join(commands + [pid1_cmd]).lower()
    runtimes = [
        ("nginx", "nginx"),
        ("apache", "httpd"),
        ("postgres", "postgres"),
        ("redis-server", "redis"),
        ("mongod", "mongodb"),
        ("java", "jvm"),
        ("python", "cpython"),
        ("node", "node.js"),
        ("gunicorn", "gunicorn"),
        ("uvicorn", "uvicorn"),
        ("php-fpm", "php-fpm"),
    ]
    for pattern, runtime in runtimes:
        if pattern in all_text:
            return runtime
    return "unknown"


def _parse_listeners(net_output: str) -> list[dict[str, Any]]:
    """Parse ss -tlnp or netstat -tlnp output."""
    listeners: list[dict[str, Any]] = []
    seen_ports: set[int] = set()

    for line in net_output.strip().splitlines():
        if "LISTEN" not in line:
            continue

        port = _extract_port_from_line(line)
        if port and port not in seen_ports:
            seen_ports.add(port)
            process = _extract_process_from_line(line)
            listeners.append(
                {
                    "port": port,
                    "protocol": "TCP",
                    "address": "0.0.0.0",
                    "process": process,
                }
            )

    return listeners


def _extract_port_from_line(line: str) -> int | None:
    """Extract port number from a netstat/ss line."""
    matches = re.findall(r"[:\]](\d+)\s", line)
    for m in matches:
        port = int(m)
        if 1 <= port <= 65535:
            return port
    return None


def _extract_process_from_line(line: str) -> str:
    """Extract process name from netstat/ss output line."""
    # netstat: PID/Program name like "1/nginx"
    m = re.search(r"(\d+)/(\S+)", line)
    if m:
        return m.group(2)
    # ss: users:(("nginx",pid=1,fd=6))
    m = re.search(r'users:\(\("([^"]+)"', line)
    if m:
        return m.group(1)
    return ""


def _parse_connections(conn_output: str, known_services: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Parse ss -tnp or netstat -tnp for outbound connections."""
    connections: list[dict[str, Any]] = []
    seen: set[str] = set()

    ip_to_svc: dict[str, str] = {}
    for svc in known_services:
        ip = svc.get("clusterIP")
        if ip and ip != "None":
            ip_to_svc[ip] = f"{svc['name']}.{svc['namespace']}"

    for line in conn_output.strip().splitlines():
        if "ESTAB" not in line and "ESTABLISHED" not in line:
            continue

        # Find all ip:port pairs, take the second one as remote
        ip_ports = re.findall(r"(\d+\.\d+\.\d+\.\d+):(\d+)", line)
        if len(ip_ports) >= 2:
            remote_ip, remote_port = ip_ports[1]
            remote_port_int = int(remote_port)
            key = f"{remote_ip}:{remote_port}"
            if key not in seen:
                seen.add(key)
                matched = ip_to_svc.get(remote_ip, "")
                connections.append(
                    {
                        "destination_ip": remote_ip,
                        "destination_port": remote_port_int,
                        "protocol_guess": _guess_protocol_from_port(remote_port_int),
                        "matched_service": matched,
                    }
                )

    return connections


def _guess_protocol_from_port(port: int) -> str:
    return PORT_PROTOCOL_MAP.get(port, "TCP")


def _parse_env(env_output: str) -> list[dict[str, Any]]:
    """Parse environment variables (key=value per line), hash all values."""
    env_vars: list[dict[str, Any]] = []
    for line in env_output.strip().splitlines():
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if not key:
            continue
        env_vars.append(
            {
                "name": key,
                "value_hash": hash_value(value),
                "source": "runtime",
                "sensitive": is_sensitive_key(key),
            }
        )
    return env_vars


def _parse_df(df_output: str) -> list[dict[str, Any]]:
    """Parse df -h output."""
    entries: list[dict[str, Any]] = []
    for line in df_output.strip().splitlines():
        if line.startswith("Filesystem") or line.startswith("overlay"):
            continue
        parts = line.split()
        if len(parts) >= 6:
            entries.append(
                {
                    "filesystem": parts[0],
                    "size": parts[1],
                    "used": parts[2],
                    "available": parts[3],
                    "use_percent": parts[4],
                    "mounted_on": parts[5],
                }
            )
    return entries


def _parse_config(content: str, file_path: str) -> dict[str, Any]:
    """Best-effort local config file parsing."""
    fmt = "unknown"
    if file_path.endswith((".yaml", ".yml")):
        fmt = "yaml"
    elif file_path.endswith(".json"):
        fmt = "json"
    elif file_path.endswith(".toml"):
        fmt = "toml"
    elif file_path.endswith((".ini", ".cfg", ".conf")):
        fmt = "ini"
    elif file_path.endswith(".properties") or file_path.endswith(".env"):
        fmt = "properties"

    key_fields: list[dict[str, Any]] = []
    for line in content.splitlines()[:50]:
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        m = re.match(r"^([A-Za-z_][\w.-]*)\s*[=:]\s*(.*)", line)
        if m:
            key = m.group(1)
            key_fields.append(
                {
                    "key": key,
                    "description": "",
                    "sensitive": is_sensitive_key(key),
                }
            )

    return {"format": fmt, "key_fields": key_fields[:20]}
