"""
Ground truth recording for ARGUS lab attack simulation.

Records when simulated events happen so detection results can be
measured against a known baseline.
"""

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import ClassVar


@dataclass
class GroundTruthEvent:
    """A single recorded event in the lab scenario."""

    event_type: str
    timestamp: str
    pid: int | None
    process_name: str | None
    detail: str
    expected_detection_rule: str | None


class GroundTruthLog:
    """
    Accumulates GroundTruthEvent records for a named scenario.

    Usage::

        log = GroundTruthLog("reverse_shell_exfiltration")
        log.record("INITIAL_ACCESS", "Socket connect attempt to 127.0.0.1:4444",
                   expected_rule="NET-001-SUSPICIOUS-OUTBOUND")
        log.save("/tmp/ground_truth.json")
        loaded = GroundTruthLog.load("/tmp/ground_truth.json")
    """

    def __init__(self, scenario_name: str) -> None:
        self._scenario_name = scenario_name
        self._events: list[GroundTruthEvent] = []

    # ------------------------------------------------------------------
    # Mutation
    # ------------------------------------------------------------------

    def record(
        self,
        event_type: str,
        detail: str,
        expected_rule: str | None = None,
        pid: int | None = None,
        process_name: str | None = None,
    ) -> None:
        """
        Append a new event to the log.

        Args:
            event_type:      Free-form label for the event category (e.g. "EXECUTION").
            detail:          Human-readable description of what happened.
            expected_rule:   Detection rule ID expected to fire for this event.
            pid:             PID of the relevant process, if any.
            process_name:    Name of the relevant process, if any.
        """
        self._events.append(
            GroundTruthEvent(
                event_type=event_type,
                timestamp=datetime.now(tz=timezone.utc).isoformat(),
                pid=pid,
                process_name=process_name,
                detail=detail,
                expected_detection_rule=expected_rule,
            )
        )

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, path: str) -> None:
        """Serialise the log to a JSON file at *path*."""
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2)

    @classmethod
    def load(cls, path: str) -> "GroundTruthLog":
        """
        Reconstruct a GroundTruthLog from a JSON file previously saved by
        :meth:`save`.
        """
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)

        instance = cls(scenario_name=data["scenario_name"])
        for raw in data.get("events", []):
            instance._events.append(
                GroundTruthEvent(
                    event_type=raw["event_type"],
                    timestamp=raw["timestamp"],
                    pid=raw.get("pid"),
                    process_name=raw.get("process_name"),
                    detail=raw["detail"],
                    expected_detection_rule=raw.get("expected_detection_rule"),
                )
            )
        return instance

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    @property
    def events(self) -> list[GroundTruthEvent]:
        """The ordered list of recorded events (read-only copy)."""
        return list(self._events)

    def to_dict(self) -> dict:
        """Return the full log as a JSON-serialisable dict."""
        return {
            "scenario_name": self._scenario_name,
            "event_count": len(self._events),
            "events": [asdict(e) for e in self._events],
        }
