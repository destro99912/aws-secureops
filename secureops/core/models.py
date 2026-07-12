from dataclasses import asdict, dataclass
from typing import Any, ClassVar


@dataclass(frozen=True)
class Finding:
    """
    Represents a single cloud security finding in AWS SecureOps.
    Instances are read-only (frozen) and severity validated.
    """
    service: str
    severity: str
    title: str
    resource: str
    evidence: str
    recommendation: str
    region: str | None = None

    ALLOWED_SEVERITIES: ClassVar[frozenset[str]] = frozenset(
        {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
    )

    def __post_init__(self) -> None:
        if self.severity not in self.ALLOWED_SEVERITIES:
            raise ValueError(
                f"Invalid severity '{self.severity}'. "
                f"Expected one of: {', '.join(sorted(self.ALLOWED_SEVERITIES))}"
            )

    def to_dict(self) -> dict[str, Any]:
        """
        Converts the Finding instance to a dictionary.
        """
        return asdict(self)
