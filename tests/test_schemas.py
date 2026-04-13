"""Tests for kube2docs.knowledge.schemas Pydantic models."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from kube2docs.knowledge.schemas import (
    ClusterOverview,
    ContainerInfo,
    DependencyEdge,
    EnvVar,
    NetworkListener,
    OutboundConnection,
    RbacRule,
    RbacSummary,
    ScanStatus,
    WorkloadProfile,
)

NOW = datetime.now(UTC)


class TestContainerInfo:
    def test_create_minimal(self):
        c = ContainerInfo(name="app", role="main", image="nginx:1.25")
        assert c.name == "app"
        assert c.role == "main"
        assert c.image_digest is None

    def test_role_must_be_valid(self):
        with pytest.raises(ValidationError):
            ContainerInfo(name="app", role="unknown", image="nginx:1.25")

    def test_all_valid_roles(self):
        for role in ("main", "sidecar", "init"):
            c = ContainerInfo(name="x", role=role, image="img")
            assert c.role == role

    def test_roundtrip_json(self):
        c = ContainerInfo(name="proxy", role="sidecar", image="envoy:1.0", image_digest="sha256:abc")
        parsed = ContainerInfo.model_validate_json(c.model_dump_json())
        assert parsed == c


class TestNetworkListener:
    def test_create_with_defaults(self):
        nl = NetworkListener(port=8080, protocol="tcp")
        assert nl.port == 8080
        assert nl.purpose is None
        assert nl.detected_endpoints == []

    def test_roundtrip_json(self):
        nl = NetworkListener(port=443, protocol="tcp", purpose="HTTPS", detected_endpoints=["/health"])
        parsed = NetworkListener.model_validate_json(nl.model_dump_json())
        assert parsed == nl


class TestOutboundConnection:
    def test_create_minimal(self):
        oc = OutboundConnection(destination="postgres.db:5432", protocol="tcp")
        assert oc.critical is None
        assert oc.failure_behavior is None

    def test_roundtrip_json(self):
        oc = OutboundConnection(destination="redis:6379", protocol="tcp", critical=True, failure_behavior="retry")
        parsed = OutboundConnection.model_validate_json(oc.model_dump_json())
        assert parsed == oc


class TestEnvVar:
    def test_create_minimal(self):
        ev = EnvVar(name="DB_HOST", source="configmap", value_hash="abc123")
        assert ev.purpose is None
        assert ev.required is None

    def test_roundtrip_json(self):
        ev = EnvVar(name="API_KEY", source="secret", value_hash="def456", purpose="auth", required=True)
        parsed = EnvVar.model_validate_json(ev.model_dump_json())
        assert parsed == ev


class TestDependencyEdge:
    def test_create(self):
        edge = DependencyEdge(source="web-api", destination="postgres", port=5432, protocol="tcp")
        assert edge.source == "web-api"
        assert edge.critical is None

    def test_roundtrip_json(self):
        edge = DependencyEdge(source="a", destination="b", port=80, protocol="http", critical=True)
        parsed = DependencyEdge.model_validate_json(edge.model_dump_json())
        assert parsed == edge


class TestWorkloadProfile:
    def test_create_minimal(self):
        wp = WorkloadProfile(
            name="web-api",
            namespace="app-team",
            workload_type="Deployment",
            explored_at=NOW,
            containers=[ContainerInfo(name="app", role="main", image="web:1.0")],
        )
        assert wp.api_version == "kube2docs.io/v1alpha1"
        assert wp.kind == "WorkloadProfile"
        assert wp.confidence == 0.0
        assert wp.inspection_source == "survey"
        assert wp.replicas == 1
        assert wp.network_listeners == []
        assert wp.outbound_connections == []
        assert wp.env_vars == []
        assert wp.config_files == []
        assert wp.secrets_referenced == []
        assert wp.volumes == []
        assert wp.resource_requested is None
        assert wp.resource_observed is None
        assert wp.health == {}
        assert wp.failure_modes == []

    def test_inspection_source_valid_values(self):
        for source in ("survey", "deep_inspect", "agentic"):
            wp = WorkloadProfile(
                name="x",
                namespace="ns",
                workload_type="Deployment",
                explored_at=NOW,
                containers=[ContainerInfo(name="c", role="main", image="i")],
                inspection_source=source,
            )
            assert wp.inspection_source == source

    def test_inspection_source_invalid_raises(self):
        with pytest.raises(ValidationError):
            WorkloadProfile(
                name="x",
                namespace="ns",
                workload_type="Deployment",
                explored_at=NOW,
                containers=[ContainerInfo(name="c", role="main", image="i")],
                inspection_source="manual",  # type: ignore[arg-type]
            )

    def test_roundtrip_json(self):
        wp = WorkloadProfile(
            name="redis",
            namespace="app-team",
            workload_type="Deployment",
            explored_at=NOW,
            containers=[ContainerInfo(name="redis", role="main", image="redis:7")],
            replicas=3,
            network_listeners=[NetworkListener(port=6379, protocol="tcp")],
        )
        parsed = WorkloadProfile.model_validate_json(wp.model_dump_json())
        assert parsed == wp

    def test_missing_required_fields_raises(self):
        with pytest.raises(ValidationError):
            WorkloadProfile(name="x")  # type: ignore[call-arg]

    def test_serialization_includes_defaults(self):
        wp = WorkloadProfile(
            name="test",
            namespace="ns",
            workload_type="StatefulSet",
            explored_at=NOW,
            containers=[ContainerInfo(name="c", role="main", image="i")],
        )
        data = wp.model_dump()
        assert "api_version" in data
        assert "kind" in data
        assert data["replicas"] == 1


class TestRbacRule:
    def test_create_minimal(self):
        rule = RbacRule(verbs=["get", "list"])
        assert rule.verbs == ["get", "list"]
        assert rule.api_groups == []
        assert rule.resources == []
        assert rule.resource_names == []
        assert rule.non_resource_urls == []

    def test_roundtrip_json(self):
        rule = RbacRule(
            verbs=["create", "delete"],
            api_groups=["apps"],
            resources=["deployments"],
        )
        parsed = RbacRule.model_validate_json(rule.model_dump_json())
        assert parsed == rule


class TestRbacSummary:
    def test_create_no_permissions(self):
        s = RbacSummary(service_account="default")
        assert s.roles == []
        assert s.rules == []
        assert s.high_risk == []

    def test_create_with_high_risk(self):
        s = RbacSummary(
            service_account="operator",
            roles=["clusterrole/cluster-admin"],
            rules=[RbacRule(verbs=["*"], resources=["*"])],
            high_risk=["*:*"],
        )
        assert s.high_risk == ["*:*"]

    def test_roundtrip_json(self):
        s = RbacSummary(
            service_account="my-sa",
            roles=["role/reader", "clusterrole/view"],
            rules=[RbacRule(verbs=["get", "list"], resources=["pods"])],
            high_risk=[],
        )
        parsed = RbacSummary.model_validate_json(s.model_dump_json())
        assert parsed == s


class TestWorkloadProfileRbacAndCron:
    def test_cron_fields_default_none(self):
        wp = WorkloadProfile(
            name="web",
            namespace="ns",
            workload_type="Deployment",
            explored_at=NOW,
            containers=[ContainerInfo(name="c", role="main", image="i")],
        )
        assert wp.cron_schedule is None
        assert wp.cron_suspend is None
        assert wp.cron_concurrency_policy is None
        assert wp.rbac is None

    def test_cron_fields_populated(self):
        wp = WorkloadProfile(
            name="nightly-job",
            namespace="batch",
            workload_type="CronJob",
            explored_at=NOW,
            containers=[ContainerInfo(name="worker", role="main", image="job:1.0")],
            replicas=0,
            cron_schedule="0 2 * * *",
            cron_suspend=False,
            cron_concurrency_policy="Forbid",
        )
        assert wp.cron_schedule == "0 2 * * *"
        assert wp.cron_suspend is False
        assert wp.cron_concurrency_policy == "Forbid"

    def test_rbac_field_populated(self):
        rbac = RbacSummary(
            service_account="my-sa",
            roles=["role/reader"],
            rules=[RbacRule(verbs=["get"], resources=["pods"])],
        )
        wp = WorkloadProfile(
            name="api",
            namespace="ns",
            workload_type="Deployment",
            explored_at=NOW,
            containers=[ContainerInfo(name="c", role="main", image="i")],
            rbac=rbac,
        )
        assert wp.rbac is not None
        assert wp.rbac.service_account == "my-sa"
        assert wp.rbac.high_risk == []

    def test_roundtrip_with_rbac_and_cron(self):
        wp = WorkloadProfile(
            name="cron-job",
            namespace="batch",
            workload_type="CronJob",
            explored_at=NOW,
            containers=[ContainerInfo(name="w", role="main", image="job:2.0")],
            replicas=0,
            cron_schedule="*/15 * * * *",
            cron_concurrency_policy="Allow",
            rbac=RbacSummary(service_account="batch-sa", high_risk=["secrets:get,list"]),
        )
        parsed = WorkloadProfile.model_validate_json(wp.model_dump_json())
        assert parsed == wp
        assert parsed.cron_schedule == "*/15 * * * *"
        assert parsed.rbac is not None
        assert parsed.rbac.high_risk == ["secrets:get,list"]


class TestClusterOverview:
    def test_create_with_dependencies(self):
        edge = DependencyEdge(source="web", destination="db", port=5432, protocol="tcp")
        overview = ClusterOverview(
            scanned_at=NOW,
            namespaces=["app-team", "vendor-apps"],
            node_count=3,
            total_workloads=5,
            total_pods=10,
            dependencies=[edge],
        )
        assert len(overview.dependencies) == 1
        assert overview.issues_found == 0

    def test_roundtrip_json(self):
        overview = ClusterOverview(
            scanned_at=NOW,
            namespaces=["default"],
            node_count=1,
            total_workloads=2,
            total_pods=4,
            dependencies=[],
            issues_found=3,
        )
        parsed = ClusterOverview.model_validate_json(overview.model_dump_json())
        assert parsed == overview


class TestScanStatus:
    def test_valid_states(self):
        for state in ("starting", "running", "completed", "failed"):
            s = ScanStatus(
                state=state,
                phase="test",
                started_at=NOW,
                progress={"total": 0, "completed": 0},
                findings={"workloads": 0},
            )
            assert s.state == state

    def test_invalid_state_raises(self):
        with pytest.raises(ValidationError):
            ScanStatus(
                state="paused",
                phase="test",
                started_at=NOW,
                progress={},
                findings={},
            )

    def test_errors_default_empty(self):
        s = ScanStatus(
            state="running",
            phase="survey",
            started_at=NOW,
            progress={"total": 5, "completed": 2},
            findings={"workloads": 2},
        )
        assert s.errors == []

    def test_roundtrip_json(self):
        s = ScanStatus(
            state="failed",
            phase="deep-inspect",
            started_at=NOW,
            progress={"total": 10, "completed": 7},
            findings={"workloads": 5, "issues": 3},
            errors=["timeout on pod-x", "exec failed on pod-y"],
        )
        parsed = ScanStatus.model_validate_json(s.model_dump_json())
        assert parsed == s
