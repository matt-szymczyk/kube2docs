"""Pydantic models for all Explorer data structures."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class ContainerInfo(BaseModel):
    name: str
    role: Literal["main", "sidecar", "init"]
    image: str
    image_digest: str | None = None


class NetworkListener(BaseModel):
    port: int
    protocol: str
    purpose: str | None = None
    detected_endpoints: list[str] = Field(default_factory=list)


class OutboundConnection(BaseModel):
    destination: str
    protocol: str
    critical: bool | None = None
    failure_behavior: str | None = None


class EnvVar(BaseModel):
    name: str
    source: str
    value_hash: str
    purpose: str | None = None
    required: bool | None = None


class VolumeInfo(BaseModel):
    name: str
    mount_path: str
    volume_type: str
    size: str | None = None
    current_usage: str | None = None
    growth_rate: str | None = None


class ResourceObservation(BaseModel):
    cpu_p50: str | None = None
    cpu_p95: str | None = None
    memory_steady: str | None = None
    memory_pattern: str | None = None


class ResilienceInfo(BaseModel):
    pod_disruption_budget: bool = False
    anti_affinity: bool = False
    topology_spread: bool = False
    all_replicas_same_node: bool | None = None
    horizontal_pod_autoscaler: bool = False


class FailureMode(BaseModel):
    scenario: str
    tested: bool = False
    method: str | None = None
    impact: Literal["critical", "degraded", "brief", "none"] | None = None
    behavior: str | None = None
    cascade_effect: list[str] = Field(default_factory=list)
    recovery: str | None = None
    time_to_impact: str | None = None


class WorkloadProfile(BaseModel):
    api_version: str = "kube2docs.io/v1alpha1"
    kind: str = "WorkloadProfile"
    name: str
    namespace: str
    workload_type: str
    explored_at: datetime
    confidence: float = 0.0
    containers: list[ContainerInfo]
    init_containers: list[ContainerInfo] = Field(default_factory=list)
    image_fingerprint: dict[str, str] = Field(default_factory=dict)
    replicas: int = 1
    network_listeners: list[NetworkListener] = Field(default_factory=list)
    outbound_connections: list[OutboundConnection] = Field(default_factory=list)
    env_vars: list[EnvVar] = Field(default_factory=list)
    config_files: list[dict[str, Any]] = Field(default_factory=list)
    secrets_referenced: list[dict[str, Any]] = Field(default_factory=list)
    volumes: list[VolumeInfo] = Field(default_factory=list)
    resource_requested: dict[str, Any] | None = None
    resource_observed: ResourceObservation | None = None
    resource_recommendation: dict[str, Any] | None = None
    health: dict[str, Any] = Field(default_factory=dict)
    resilience: ResilienceInfo = Field(default_factory=ResilienceInfo)
    failure_modes: list[FailureMode] = Field(default_factory=list)
    summary: str | None = None


class DependencyEdge(BaseModel):
    source: str
    destination: str
    port: int
    protocol: str
    critical: bool | None = None
    external: bool = False


class ClusterOverview(BaseModel):
    scanned_at: datetime
    namespaces: list[str]
    node_count: int
    total_workloads: int
    total_pods: int
    dependencies: list[DependencyEdge]
    issues_found: int = 0


class ScanStatus(BaseModel):
    state: Literal["starting", "running", "completed", "failed"]
    phase: str
    started_at: datetime
    progress: dict[str, Any]
    findings: dict[str, Any]
    errors: list[str] = Field(default_factory=list)
