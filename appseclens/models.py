from dataclasses import dataclass, field
from typing import Any


@dataclass
class Finding:
    """Represents one security finding."""

    check: str
    title: str
    severity: str
    description: str
    evidence: str
    remediation: str
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert the finding into a dictionary."""

        return {
            "check": self.check,
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "references": self.references,
        }


@dataclass
class ScanResult:
    """Stores the complete result of scanning one URL."""

    url: str
    final_url: str = ""
    status_code: int | None = None
    server: str = ""
    content_type: str = ""
    elapsed_ms: float | None = None

    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert the scan result into a dictionary."""

        return {
            "url": self.url,
            "final_url": self.final_url,
            "status_code": self.status_code,
            "server": self.server,
            "content_type": self.content_type,
            "elapsed_ms": self.elapsed_ms,
            "findings": [
                finding.to_dict()
                for finding in self.findings
            ],
            "errors": self.errors,
        }
