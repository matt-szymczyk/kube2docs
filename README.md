# cluster-explorer

AI agent that reverse-engineers Kubernetes workloads into operational knowledge.

## Install
```bash
uv venv && uv pip install -e ".[dev]"
```

## Usage
```bash
cluster-explorer scan --kubeconfig ~/.kube/config --output ./kb/
```
