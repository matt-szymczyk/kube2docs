"""Progress tracking via status file and rich terminal output."""

import logging
from datetime import UTC, datetime
from pathlib import Path

from rich.console import Console
from rich.progress import Progress

from kube2docs.knowledge.schemas import ScanStatus

logger = logging.getLogger(__name__)


class ProgressTracker:
    """Tracks scan progress, writes status file, and displays rich terminal output."""

    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir
        self.status_file = output_dir / "kube2docs-status.json"
        self.console = Console()
        self.status = ScanStatus(
            state="starting",
            phase="initializing",
            started_at=datetime.now(UTC),
            progress={"total": 0, "completed": 0, "current": ""},
            findings={"workloads": 0, "services": 0, "dependencies": 0, "issues": 0},
            errors=[],
        )
        self._progress: Progress | None = None

    def start(self, phase: str, total: int) -> None:
        self.status.state = "running"
        self.status.phase = phase
        self.status.progress["total"] = total
        self.status.progress["completed"] = 0
        self._write_status()

    def update(self, current: str, completed: int | None = None) -> None:
        self.status.progress["current"] = current
        if completed is not None:
            self.status.progress["completed"] = completed
        self._write_status()

    def log(self, message: str) -> None:
        self.console.print(f"  [dim]{message}[/dim]")

    def phase_header(self, title: str) -> None:
        self.console.print(f"\n[bold cyan]▶ {title}[/bold cyan]")

    def item(self, label: str, detail: str = "") -> None:
        suffix = f" [dim]{detail}[/dim]" if detail else ""
        self.console.print(f"  [green]✓[/green] {label}{suffix}")

    def warning(self, message: str) -> None:
        self.console.print(f"  [yellow]⚠[/yellow] {message}")

    def error(self, message: str) -> None:
        self.status.errors.append(message)
        self.console.print(f"  [red]✗[/red] {message}")
        self._write_status()

    def set_findings(self, **kwargs: int) -> None:
        self.status.findings.update(kwargs)
        self._write_status()

    def complete(self) -> None:
        self.status.state = "completed"
        self._write_status()
        self.console.print("\n[bold green]✓ Scan complete[/bold green]")

    def fail(self, reason: str) -> None:
        self.status.state = "failed"
        self.status.errors.append(reason)
        self._write_status()
        self.console.print(f"\n[bold red]✗ Scan failed: {reason}[/bold red]")

    def _write_status(self) -> None:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.status_file.write_text(self.status.model_dump_json(indent=2))
