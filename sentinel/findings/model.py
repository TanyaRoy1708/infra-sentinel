from dataclasses import dataclass, field, asdict


@dataclass
class Finding:
    resource_id: str
    finding_type: str
    severity: str
    reasons: list[str] = field(default_factory=list)
    confidence: int = 0
    region: str = ""

    def to_dict(self) -> dict:
        return asdict(self)
