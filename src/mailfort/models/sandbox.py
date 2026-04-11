"""Sandbox run request model."""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any


@dataclass
class SandboxRequest:
    """Describes what the sandbox orchestrator should detonate."""

    message_id: str
    artifact_type: str    # url | attachment
    artifact_ref: str     # URL string or attachment SHA-256
    detonate_links: bool = True
    detonate_attachments: bool = True
    timeout_seconds: int = 120
    environment: str = "default"
    metadata: Dict[str, Any] = field(default_factory=dict)
