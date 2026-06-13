from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List


@dataclass
class Alarm:
    alarm_type: str
    severity: str
    context: Dict[str, Any]
    recommended_action: str
    created_at: str

    @classmethod
    def create(cls, alarm_type: str, severity: str, context: Dict[str, Any], recommended_action: str) -> "Alarm":
        return cls(
            alarm_type=alarm_type,
            severity=severity,
            context=context,
            recommended_action=recommended_action,
            created_at=datetime.now(timezone.utc).isoformat(),
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class AlarmDispatcher:
    def __init__(self) -> None:
        self._alarms: List[Alarm] = []

    def emit(self, alarm_type: str, severity: str, context: Dict[str, Any], recommended_action: str) -> Alarm:
        alarm = Alarm.create(alarm_type, severity, context, recommended_action)
        self._alarms.append(alarm)
        return alarm

    def all(self) -> List[Dict[str, Any]]:
        return [alarm.to_dict() for alarm in self._alarms]

    def has_high_or_critical(self) -> bool:
        return any(alarm.severity in {"high", "critical"} for alarm in self._alarms)
