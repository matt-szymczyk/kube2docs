"""Knowledge base read/write operations."""

import json
import logging
from pathlib import Path
from typing import Any

from pydantic import BaseModel

logger = logging.getLogger(__name__)


class KnowledgeStore:
    """Manages reading and writing knowledge base files to the output directory."""

    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def namespace_dir(self, namespace: str) -> Path:
        d = self.output_dir / namespace
        d.mkdir(parents=True, exist_ok=True)
        return d

    def write_model(self, path: Path, model: BaseModel) -> None:
        """Write a Pydantic model as JSON."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(model.model_dump_json(indent=2))
        logger.debug("Wrote %s", path)

    def write_json(self, path: Path, data: dict[str, Any] | list[Any]) -> None:
        """Write raw JSON data."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2, default=str))
        logger.debug("Wrote %s", path)

    def read_json(self, path: Path) -> dict[str, Any] | list[Any] | None:
        """Read JSON data, returning None if file doesn't exist."""
        if not path.exists():
            return None
        return json.loads(path.read_text())  # type: ignore[no-any-return]
