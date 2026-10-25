from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class LayerResult:
    name: str
    score: Optional[float]          # 0-100 risk, None when the layer had nothing to judge
    reasons: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    @property
    def available(self) -> bool:
        return self.score is not None
