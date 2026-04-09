"""Tests for scanner helpers."""

from kube2docs.knowledge.schemas import DependencyEdge
from kube2docs.scanner import _parse_connection_destination, _render_mermaid_topology


class TestParseConnectionDestination:
    """Tests for dependency destination parsing and resolution."""

    def test_service_dns_format(self) -> None:
        # "svc.namespace:port" → ("namespace/svc", port)
        label, port = _parse_connection_destination("postgres.app-team:5432")
        assert label == "app-team/postgres"
        assert port == 5432

    def test_external_hostname(self) -> None:
        # Multi-dot external hostname should return bare host as label,
        # port stored separately (no doubled-up port)
        label, port = _parse_connection_destination("smtp.company.internal:587")
        assert label == "smtp.company.internal"
        assert port == 587

    def test_ip_no_service_match(self) -> None:
        label, port = _parse_connection_destination("10.0.0.42:8080")
        assert label == "10.0.0.42"
        assert port == 8080

    def test_ip_resolved_via_registry(self) -> None:
        ip_map = {"10.96.1.1": {"name": "redis", "namespace": "app-team"}}
        label, port = _parse_connection_destination("10.96.1.1:6379", ip_map)
        assert label == "app-team/redis"
        assert port == 6379

    def test_invalid_port(self) -> None:
        label, port = _parse_connection_destination("host:abc")
        assert label == ""
        assert port == 0

    def test_no_port_separator(self) -> None:
        label, port = _parse_connection_destination("justhostname")
        assert label == ""
        assert port == 0

    def test_empty_string(self) -> None:
        label, port = _parse_connection_destination("")
        assert label == ""
        assert port == 0


class TestRenderMermaidTopology:
    """Tests for Mermaid diagram generation."""

    def test_empty_graph(self) -> None:
        result = _render_mermaid_topology([], set())
        assert result.startswith("flowchart LR")

    def test_internal_edge(self) -> None:
        edges = [
            DependencyEdge(
                source="app-team/web-api",
                destination="app-team/postgres",
                port=5432,
                protocol="PostgreSQL",
            )
        ]
        workloads = {"app-team/web-api", "app-team/postgres"}
        result = _render_mermaid_topology(edges, workloads)
        assert "subgraph app_team[app-team]" in result
        assert "web_api[web-api]" in result
        assert "postgres[postgres]" in result
        assert "app_team_web_api -->|PostgreSQL:5432| app_team_postgres" in result

    def test_external_edge_marked(self) -> None:
        edges = [
            DependencyEdge(
                source="app-team/worker",
                destination="smtp.company.com",
                port=587,
                protocol="SMTP",
                external=True,
            )
        ]
        workloads = {"app-team/worker"}
        result = _render_mermaid_topology(edges, workloads)
        assert "smtp_company_com" in result
        assert "([smtp.company.com])" in result
        assert ":::external" in result
        assert "classDef external" in result

    def test_multiple_namespaces(self) -> None:
        edges = [
            DependencyEdge(
                source="app-team/api",
                destination="data-team/db",
                port=5432,
                protocol="PostgreSQL",
            )
        ]
        workloads = {"app-team/api", "data-team/db"}
        result = _render_mermaid_topology(edges, workloads)
        assert "subgraph app_team[app-team]" in result
        assert "subgraph data_team[data-team]" in result
