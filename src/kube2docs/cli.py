"""kube2docs CLI entry point."""

import logging
from pathlib import Path
from typing import Any

import click

from kube2docs import __version__
from kube2docs.config import ScanConfig
from kube2docs.scanner import run_scan


@click.group()
@click.version_option(version=__version__)
def main() -> None:
    """kube2docs — Crawl a Kubernetes cluster and produce operational knowledge."""
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")


@main.command()
@click.option("--kubeconfig", type=click.Path(), default=None, help="Path to kubeconfig")
@click.option("--context", default=None, help="Kubeconfig context to use")
@click.option("--namespaces", default=None, help="Comma-separated namespace filter")
@click.option("--output", type=click.Path(), required=True, help="Output directory for knowledge base")
@click.option("--depth", type=click.Choice(["survey", "deep"]), default="deep", help="Exploration depth")
@click.option("--force-rescan", is_flag=True, default=False, help="Ignore fingerprints, rescan all")
@click.option("--reveal-configmap-values", is_flag=True, default=False, help="Show ConfigMap values in plaintext")
@click.option("--timeout", default=300, type=click.IntRange(min=1), help="Per-operation timeout in seconds")
@click.option("--dry-run", is_flag=True, default=False, help="Survey only, print commands that would run, then exit")
@click.option("--agentic", is_flag=True, default=False, help="Use LLM-driven inspection instead of deterministic exec")
@click.option("--model", default=None, help="Model for agentic scan (required with --agentic)")
@click.option(
    "--api-key",
    default=None,
    help="API key for agentic scan (falls back to provider env var: ANTHROPIC_API_KEY, OPENAI_API_KEY, etc.)",
)
@click.option(
    "--api-base",
    default=None,
    help="Override API base URL (e.g. http://localhost:11434 for Ollama, self-hosted vLLM/LM Studio)",
)
@click.option("--max-calls", default=200, type=click.IntRange(min=1), help="Global LLM call budget for agentic scan")
@click.option("--max-rounds", default=5, type=click.IntRange(min=1), help="Max LLM rounds per workload in agentic mode")
def scan(**kwargs: Any) -> None:
    """Scan a Kubernetes cluster and produce operational knowledge."""
    ns_list = None
    if kwargs.get("namespaces"):
        ns_list = [n.strip() for n in kwargs["namespaces"].split(",")]

    if kwargs.get("agentic") and not kwargs.get("model"):
        click.echo("Error: --model is required when using --agentic", err=True)
        raise SystemExit(1)

    config = ScanConfig(
        kubeconfig=kwargs.get("kubeconfig"),
        context=kwargs.get("context"),
        namespaces=ns_list,
        output=Path(kwargs["output"]),
        depth=kwargs["depth"],
        force_rescan=kwargs["force_rescan"],
        reveal_configmap_values=kwargs["reveal_configmap_values"],
        timeout=kwargs["timeout"],
        dry_run=kwargs.get("dry_run", False),
        agentic=kwargs.get("agentic", False),
        agentic_model=kwargs.get("model"),
        agentic_api_key=kwargs.get("api_key"),
        agentic_api_base=kwargs.get("api_base"),
        agentic_max_calls=kwargs.get("max_calls", 200),
        agentic_max_rounds=kwargs.get("max_rounds", 5),
    )
    run_scan(config)


@main.command()
@click.option("--output", type=click.Path(), required=True, help="Output directory to read status from")
def status(output: str) -> None:
    """Show exploration progress."""
    from rich.console import Console
    from rich.table import Table

    from kube2docs.knowledge.schemas import ScanStatus

    console = Console()
    status_file = Path(output) / "kube2docs-status.json"

    if not status_file.exists():
        console.print(f"[red]No status file found at {status_file}[/red]")
        raise SystemExit(1)

    try:
        data = status_file.read_text()
        scan_status = ScanStatus.model_validate_json(data)
    except Exception as exc:
        console.print(f"[red]Failed to read status file: {exc}[/red]")
        raise SystemExit(1) from None

    state_colors = {
        "starting": "yellow",
        "running": "blue",
        "completed": "green",
        "failed": "red",
    }
    color = state_colors.get(scan_status.state, "white")

    console.print()
    console.print("[bold]kube2docs scan status[/bold]")
    console.print(f"  State:      [{color}]{scan_status.state}[/{color}]")
    console.print(f"  Phase:      {scan_status.phase}")
    console.print(f"  Started at: {scan_status.started_at:%Y-%m-%d %H:%M:%S UTC}")

    if scan_status.progress:
        console.print()
        table = Table(title="Progress", show_header=True)
        table.add_column("Key")
        table.add_column("Value")
        for key, value in scan_status.progress.items():
            table.add_row(str(key), str(value))
        console.print(table)

    if scan_status.findings:
        console.print()
        table = Table(title="Findings", show_header=True)
        table.add_column("Category")
        table.add_column("Count")
        for key, value in scan_status.findings.items():
            table.add_row(str(key), str(value))
        console.print(table)

    if scan_status.errors:
        console.print()
        console.print(f"[red bold]Errors ({len(scan_status.errors)}):[/red bold]")
        for err in scan_status.errors:
            console.print(f"  [red]- {err}[/red]")


@main.command()
@click.option("--input", "input_dir", type=click.Path(exists=True), required=True, help="Knowledge base directory")
@click.option("--output", type=click.Path(), required=True, help="Output directory for generated docs")
@click.option(
    "--model",
    required=True,
    help="litellm model identifier (e.g. claude-haiku-4-5, gpt-4o-mini, openrouter/..., ollama/llama3.1)",
)
@click.option(
    "--api-key",
    default=None,
    help="API key (falls back to provider env var: ANTHROPIC_API_KEY, OPENAI_API_KEY, etc.)",
)
@click.option(
    "--api-base",
    default=None,
    help="Override API base URL (e.g. http://localhost:11434 for Ollama, self-hosted vLLM/LM Studio)",
)
@click.option("--max-calls", default=50, type=click.IntRange(min=1), help="Max AI calls budget")
@click.option("--timeout", default=120, type=click.IntRange(min=1), help="Per-call timeout in seconds")
@click.option("--recommendations", is_flag=True, default=False, help="Also generate recommendations")
@click.option("--instructions", default="", help="Additional instructions for the AI writer")
@click.option("--workers", default=4, type=click.IntRange(min=1), help="Parallel AI calls (default 4)")
def generate(
    input_dir: str,
    output: str,
    model: str,
    api_key: str | None,
    api_base: str | None,
    max_calls: int,
    timeout: int,
    recommendations: bool,
    instructions: str,
    workers: int,
) -> None:
    """Generate Markdown documentation from a scanned knowledge base."""
    from kube2docs.ai.provider import AIProvider
    from kube2docs.ai.writer import generate_docs
    from kube2docs.progress.tracker import ProgressTracker

    ai = AIProvider(
        model=model,
        api_key=api_key,
        api_base=api_base,
        max_calls=max_calls,
        timeout=timeout,
    )
    tracker = ProgressTracker(Path(input_dir))

    generate_docs(
        input_dir=Path(input_dir),
        output_dir=Path(output),
        ai=ai,
        tracker=tracker,
        instructions=instructions,
        recommendations=recommendations,
        workers=workers,
    )
    tracker.complete()


if __name__ == "__main__":
    main()
