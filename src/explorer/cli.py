"""cluster-explorer CLI entry point."""
import click


@click.group()
@click.version_option(version="0.1.0")
def main() -> None:
    """Explorer — Reverse-engineer Kubernetes workloads into operational knowledge."""
    pass


@main.command()
@click.option("--kubeconfig", type=click.Path(), default=None, help="Path to kubeconfig")
@click.option("--context", default=None, help="Kubeconfig context to use")
@click.option("--namespaces", default=None, help="Comma-separated namespace filter")
@click.option("--output", type=click.Path(), required=True, help="Output directory for knowledge base")
@click.option("--ai-provider", default="anthropic/claude-haiku-4-5-20251001", help="litellm model for extraction")
@click.option("--ai-planner", default="anthropic/claude-sonnet-4-20250514", help="litellm model for planning")
@click.option("--ai-key", envvar="ANTHROPIC_API_KEY", default=None, help="AI API key")
@click.option("--max-ai-calls", default=500, type=int, help="Budget cap for AI calls")
@click.option("--depth", type=click.Choice(["survey", "deep", "full"]), default="deep", help="Exploration depth")
@click.option("--destructive", is_flag=True, default=False, help="Enable failure testing (v0.2)")
@click.option("--force-rescan", is_flag=True, default=False, help="Ignore fingerprints, rescan all")
@click.option("--reveal-configmap-values", is_flag=True, default=False, help="Show ConfigMap values in plaintext")
@click.option("--timeout", default=300, type=int, help="Per-operation timeout in seconds")
def scan(**kwargs) -> None:
    """Scan a Kubernetes cluster and produce operational knowledge."""
    if kwargs.get("destructive"):
        click.echo("Error: --destructive is not yet implemented. Coming in v0.2.", err=True)
        raise SystemExit(1)
    click.echo("TODO: Implement scanning")


@main.command()
@click.option("--output", type=click.Path(), required=True, help="Output directory to read status from")
def status(output: str) -> None:
    """Show exploration progress."""
    click.echo("TODO: Implement status")


@main.command()
@click.option("--kubeconfig", type=click.Path(), default=None)
@click.option("--knowledge-base", type=click.Path(), required=True, help="Path to existing knowledge base")
@click.option("--output", type=click.Path(), required=True, help="Where to write validation report")
def validate(**kwargs) -> None:
    """Validate an existing knowledge base against the cluster."""
    click.echo("TODO: Implement validate")


if __name__ == "__main__":
    main()
