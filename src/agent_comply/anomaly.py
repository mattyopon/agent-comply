"""Behavioral anomaly detection for AI agent sessions.

Detects unusual patterns by building per-agent baselines and scoring each
session against them.  Designed for streaming ingestion — events can be fed
one at a time.
"""

from __future__ import annotations

import math
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from agent_comply.ledger import EventLedger, LedgerEvent


# ── Models ─────────────────────────────────────────────────────────────
class AlertSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AnomalyAlert(BaseModel):
    alert_id: str = ""
    event_id: str = ""
    agent_id: str = ""
    rule: str = ""
    severity: AlertSeverity = AlertSeverity.LOW
    description: str = ""
    score: float = 0.0  # 0..1


class SessionRiskReport(BaseModel):
    session_id: str = ""
    agent_id: str = ""
    total_events: int = 0
    risk_score: float = 0.0  # 0..1
    alerts: list[AnomalyAlert] = Field(default_factory=list)
    summary: str = ""


# ── Baseline statistics ───────────────────────────────────────────────
@dataclass
class _AgentBaseline:
    """Running statistics for a single agent identity."""

    event_counts: list[int] = field(default_factory=list)  # per session
    tool_freq: Counter = field(default_factory=Counter)
    error_rates: list[float] = field(default_factory=list)
    durations_ms: list[float] = field(default_factory=list)
    unique_tools_per_session: list[int] = field(default_factory=list)

    @property
    def mean_events(self) -> float:
        return statistics.mean(self.event_counts) if self.event_counts else 0

    @property
    def std_events(self) -> float:
        return statistics.pstdev(self.event_counts) if len(self.event_counts) > 1 else 0

    @property
    def mean_error_rate(self) -> float:
        return statistics.mean(self.error_rates) if self.error_rates else 0

    @property
    def mean_duration(self) -> float:
        return statistics.mean(self.durations_ms) if self.durations_ms else 0

    @property
    def std_duration(self) -> float:
        return statistics.pstdev(self.durations_ms) if len(self.durations_ms) > 1 else 0


# ── Detector ──────────────────────────────────────────────────────────
class AnomalyDetector:
    """Detects anomalous agent behaviour by comparing sessions against baselines."""

    def __init__(self, z_threshold: float = 2.0) -> None:
        self._baselines: dict[str, _AgentBaseline] = defaultdict(_AgentBaseline)
        self._z_threshold = z_threshold

    # ── training ───────────────────────────────────────────────────────
    def train(self, ledger: EventLedger) -> None:
        """Ingest a ledger to update baselines.  Can be called repeatedly."""
        sessions: dict[str, list[LedgerEvent]] = defaultdict(list)
        for ev in ledger.events:
            sid = ev.payload.get("session_id", "default")
            sessions[sid].append(ev)

        for sid, events in sessions.items():
            agent_id = events[0].payload.get("agent_id", "unknown")
            bl = self._baselines[agent_id]

            bl.event_counts.append(len(events))
            errors = sum(1 for e in events if e.payload.get("error"))
            bl.error_rates.append(errors / max(len(events), 1))

            tools: set[str] = set()
            for e in events:
                dur = e.payload.get("duration_ms")
                if isinstance(dur, (int, float)):
                    bl.durations_ms.append(dur)
                fname = e.payload.get("function_name", "")
                if e.payload.get("event_type") == "tool_call":
                    bl.tool_freq[fname] += 1
                    tools.add(fname)
            bl.unique_tools_per_session.append(len(tools))

    # ── detection ──────────────────────────────────────────────────────
    def analyse(self, ledger: EventLedger) -> list[SessionRiskReport]:
        """Analyse every session in *ledger* and return risk reports."""
        sessions: dict[str, list[LedgerEvent]] = defaultdict(list)
        for ev in ledger.events:
            sid = ev.payload.get("session_id", "default")
            sessions[sid].append(ev)

        reports: list[SessionRiskReport] = []
        for sid, events in sessions.items():
            agent_id = events[0].payload.get("agent_id", "unknown")
            alerts = self._check_session(agent_id, sid, events)
            risk = self._aggregate_risk(alerts)
            reports.append(
                SessionRiskReport(
                    session_id=sid,
                    agent_id=agent_id,
                    total_events=len(events),
                    risk_score=round(risk, 4),
                    alerts=alerts,
                    summary=self._summarise(sid, alerts, risk),
                )
            )
        return reports

    def analyse_events(self, events: list[dict[str, Any]], agent_id: str = "unknown") -> list[AnomalyAlert]:
        """Quick analysis of raw event dicts without a full ledger."""
        alerts: list[AnomalyAlert] = []
        bl = self._baselines.get(agent_id)

        # Rule: excessive errors
        errors = sum(1 for e in events if e.get("error"))
        rate = errors / max(len(events), 1)
        if rate > 0.3:
            alerts.append(AnomalyAlert(
                rule="high_error_rate",
                agent_id=agent_id,
                severity=AlertSeverity.HIGH if rate > 0.5 else AlertSeverity.MEDIUM,
                description=f"Error rate {rate:.0%} exceeds threshold",
                score=min(rate, 1.0),
            ))

        # Rule: unknown tools (if baseline exists)
        if bl and bl.tool_freq:
            known = set(bl.tool_freq.keys())
            for e in events:
                if e.get("event_type") == "tool_call":
                    fn = e.get("function_name", "")
                    if fn and fn not in known:
                        alerts.append(AnomalyAlert(
                            event_id=e.get("event_id", ""),
                            rule="unknown_tool",
                            agent_id=agent_id,
                            severity=AlertSeverity.MEDIUM,
                            description=f"Tool '{fn}' not in baseline",
                            score=0.6,
                        ))

        return alerts

    # ── internal checks ────────────────────────────────────────────────
    def _check_session(
        self, agent_id: str, session_id: str, events: list[LedgerEvent]
    ) -> list[AnomalyAlert]:
        alerts: list[AnomalyAlert] = []
        bl = self._baselines.get(agent_id)
        n = len(events)

        # --- 1. Unusual session length ---
        if bl and bl.std_events > 0:
            z = (n - bl.mean_events) / bl.std_events
            if abs(z) > self._z_threshold:
                sev = AlertSeverity.HIGH if abs(z) > 3.0 else AlertSeverity.MEDIUM
                alerts.append(AnomalyAlert(
                    rule="unusual_session_length",
                    agent_id=agent_id,
                    severity=sev,
                    description=f"Session has {n} events (z-score={z:.2f}, baseline={bl.mean_events:.1f})",
                    score=min(abs(z) / 5.0, 1.0),
                ))

        # --- 2. High error rate ---
        errors = sum(1 for e in events if e.payload.get("error"))
        error_rate = errors / max(n, 1)
        threshold = max(bl.mean_error_rate + 0.15, 0.2) if bl else 0.2
        if error_rate > threshold:
            alerts.append(AnomalyAlert(
                rule="high_error_rate",
                agent_id=agent_id,
                severity=AlertSeverity.HIGH if error_rate > 0.5 else AlertSeverity.MEDIUM,
                description=f"Error rate {error_rate:.0%} exceeds threshold {threshold:.0%}",
                score=min(error_rate, 1.0),
            ))

        # --- 3. Unknown / unexpected tool usage ---
        if bl and bl.tool_freq:
            known_tools = set(bl.tool_freq.keys())
            for e in events:
                if e.payload.get("event_type") == "tool_call":
                    fn = e.payload.get("function_name", "")
                    if fn and fn not in known_tools:
                        alerts.append(AnomalyAlert(
                            event_id=e.event_id,
                            rule="unknown_tool",
                            agent_id=agent_id,
                            severity=AlertSeverity.MEDIUM,
                            description=f"Tool '{fn}' not in agent baseline",
                            score=0.6,
                        ))

        # --- 4. Excessive data access ---
        data_access = sum(
            1 for e in events if e.payload.get("event_type") == "data_access"
        )
        if data_access > 20:
            alerts.append(AnomalyAlert(
                rule="excessive_data_access",
                agent_id=agent_id,
                severity=AlertSeverity.HIGH,
                description=f"{data_access} data access events in one session",
                score=min(data_access / 50.0, 1.0),
            ))

        # --- 5. Abnormally slow calls ---
        if bl and bl.std_duration > 0:
            for e in events:
                dur = e.payload.get("duration_ms")
                if isinstance(dur, (int, float)):
                    z = (dur - bl.mean_duration) / bl.std_duration
                    if z > self._z_threshold * 1.5:
                        alerts.append(AnomalyAlert(
                            event_id=e.event_id,
                            rule="slow_call",
                            agent_id=agent_id,
                            severity=AlertSeverity.LOW,
                            description=f"Call took {dur:.0f}ms (z={z:.1f})",
                            score=min(z / 5.0, 1.0),
                        ))

        # --- 6. Policy violation patterns ---
        for e in events:
            meta = e.payload.get("metadata", {})
            if isinstance(meta, dict) and meta.get("policy_violation"):
                alerts.append(AnomalyAlert(
                    event_id=e.event_id,
                    rule="policy_violation",
                    agent_id=agent_id,
                    severity=AlertSeverity.CRITICAL,
                    description=f"Policy violation: {meta['policy_violation']}",
                    score=1.0,
                ))

        return alerts

    @staticmethod
    def _aggregate_risk(alerts: list[AnomalyAlert]) -> float:
        """Combine alert scores into an overall session risk (0..1)."""
        if not alerts:
            return 0.0
        weights = {
            AlertSeverity.LOW: 0.1,
            AlertSeverity.MEDIUM: 0.3,
            AlertSeverity.HIGH: 0.6,
            AlertSeverity.CRITICAL: 1.0,
        }
        weighted = sum(a.score * weights[a.severity] for a in alerts)
        # Sigmoid-like saturation
        return 1.0 - math.exp(-weighted)

    @staticmethod
    def _summarise(session_id: str, alerts: list[AnomalyAlert], risk: float) -> str:
        if not alerts:
            return f"Session {session_id}: No anomalies detected."
        lines = [f"Session {session_id}: risk={risk:.2f}, {len(alerts)} alert(s)"]
        for a in alerts:
            lines.append(f"  [{a.severity.value.upper()}] {a.rule}: {a.description}")
        return "\n".join(lines)
