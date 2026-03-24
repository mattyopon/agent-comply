# Copyright (c) 2025-2026 Yutaro Maeda. All rights reserved.
# Licensed under the Business Source License 1.1. See LICENSE file for details.

"""Regulatory compliance mapper — map ledger events to framework-specific requirements.

Supported frameworks:
  * EU AI Act
  * SOC 2 Type II
  * HIPAA
  * GDPR
  * DORA (Digital Operational Resilience Act)

Each framework defines a set of *controls*.  The mapper evaluates ledger events
against those controls and produces a structured compliance report.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from agent_comply.ledger import EventLedger


# ── Enums & models ─────────────────────────────────────────────────────
class Framework(str, Enum):
    EU_AI_ACT = "eu-ai-act"
    SOC2 = "soc2"
    HIPAA = "hipaa"
    GDPR = "gdpr"
    DORA = "dora"


class ControlStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    PARTIAL = "partial"
    NOT_APPLICABLE = "n/a"


class ControlResult(BaseModel):
    control_id: str
    control_name: str
    framework: Framework
    status: ControlStatus
    evidence: list[str] = Field(default_factory=list)
    findings: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class ComplianceReport(BaseModel):
    framework: Framework
    total_controls: int = 0
    passed: int = 0
    failed: int = 0
    partial: int = 0
    not_applicable: int = 0
    score: float = 0.0  # 0-100
    controls: list[ControlResult] = Field(default_factory=list)
    summary: str = ""


# ── Control definitions ───────────────────────────────────────────────
@dataclass
class _Control:
    control_id: str
    name: str
    description: str
    check: "ControlCheck"  # callable


ControlCheck = Any  # Callable[[EventLedger], ControlResult]


def _pct(n: int, total: int) -> str:
    if total == 0:
        return "0%"
    return f"{n / total * 100:.0f}%"


# ── Framework control definitions ─────────────────────────────────────

def _eu_ai_act_controls() -> list[_Control]:
    """EU AI Act Articles 13-15, 26: transparency, oversight, logging."""

    def check_transparency(ledger: EventLedger) -> ControlResult:
        """Art 13: All agent decisions must be logged with inputs/outputs."""
        events = ledger.events
        total = len(events)
        with_io = sum(
            1
            for e in events
            if e.payload.get("inputs") and e.payload.get("output") is not None
        )
        status = ControlStatus.PASS if total > 0 and with_io == total else (
            ControlStatus.PARTIAL if with_io > 0 else ControlStatus.FAIL
        )
        return ControlResult(
            control_id="EU-AI-13.1",
            control_name="Decision Transparency",
            framework=Framework.EU_AI_ACT,
            status=status,
            evidence=[f"{with_io}/{total} events have full I/O logging"],
            findings=[] if status == ControlStatus.PASS else [
                f"{total - with_io} events missing input/output data"
            ],
            recommendations=[] if status == ControlStatus.PASS else [
                "Ensure all agent calls are wrapped with @audit decorator"
            ],
        )

    def check_human_oversight(ledger: EventLedger) -> ControlResult:
        """Art 14: Evidence of human-in-the-loop capability."""
        events = ledger.events
        has_human = any(
            e.payload.get("event_type") in ("human_review", "human_override", "human_approval")
            for e in events
        )
        return ControlResult(
            control_id="EU-AI-14.1",
            control_name="Human Oversight",
            framework=Framework.EU_AI_ACT,
            status=ControlStatus.PASS if has_human else ControlStatus.FAIL,
            evidence=["Human oversight events found" if has_human else "No human oversight events"],
            findings=[] if has_human else ["No evidence of human-in-the-loop"],
            recommendations=[] if has_human else [
                "Implement human review checkpoints for high-risk decisions"
            ],
        )

    def check_logging(ledger: EventLedger) -> ControlResult:
        """Art 12: Automatic logging with integrity."""
        ok, errors = ledger.verify_chain()
        return ControlResult(
            control_id="EU-AI-12.1",
            control_name="Automatic Logging with Integrity",
            framework=Framework.EU_AI_ACT,
            status=ControlStatus.PASS if ok else ControlStatus.FAIL,
            evidence=[f"Chain integrity: {'verified' if ok else 'BROKEN'}"],
            findings=errors,
            recommendations=[] if ok else ["Investigate ledger tampering"],
        )

    def check_risk_classification(ledger: EventLedger) -> ControlResult:
        """Art 6: High-risk AI system classification metadata."""
        events = ledger.events
        has_risk = any(e.payload.get("metadata", {}).get("risk_level") for e in events)
        return ControlResult(
            control_id="EU-AI-6.1",
            control_name="Risk Classification",
            framework=Framework.EU_AI_ACT,
            status=ControlStatus.PASS if has_risk else ControlStatus.PARTIAL,
            evidence=["Risk classification metadata present" if has_risk else "No risk metadata"],
            findings=[] if has_risk else ["Events lack risk_level metadata"],
            recommendations=[] if has_risk else [
                "Add risk_level to event metadata for high-risk classification"
            ],
        )

    return [
        _Control("EU-AI-13.1", "Decision Transparency", "Art 13", check_transparency),
        _Control("EU-AI-14.1", "Human Oversight", "Art 14", check_human_oversight),
        _Control("EU-AI-12.1", "Automatic Logging", "Art 12", check_logging),
        _Control("EU-AI-6.1", "Risk Classification", "Art 6", check_risk_classification),
    ]


def _soc2_controls() -> list[_Control]:
    """SOC 2 Type II — trust service criteria for audit trails."""

    def check_audit_completeness(ledger: EventLedger) -> ControlResult:
        events = ledger.events
        all_have_ts = all(e.timestamp for e in events)
        all_have_id = all(e.event_id for e in events)
        ok = bool(events) and all_have_ts and all_have_id
        return ControlResult(
            control_id="SOC2-CC7.2",
            control_name="Audit Trail Completeness",
            framework=Framework.SOC2,
            status=ControlStatus.PASS if ok else ControlStatus.FAIL,
            evidence=[f"{len(events)} events, all with timestamp/ID: {ok}"],
            findings=[] if ok else ["Incomplete audit records"],
        )

    def check_integrity(ledger: EventLedger) -> ControlResult:
        ok, errors = ledger.verify_all()
        return ControlResult(
            control_id="SOC2-CC7.3",
            control_name="Audit Trail Integrity",
            framework=Framework.SOC2,
            status=ControlStatus.PASS if ok else ControlStatus.FAIL,
            evidence=[f"Chain + Merkle: {'intact' if ok else 'COMPROMISED'}"],
            findings=errors,
        )

    def check_retention(ledger: EventLedger) -> ControlResult:
        """Check that events span a reasonable retention period."""
        events = ledger.events
        if len(events) < 2:
            return ControlResult(
                control_id="SOC2-CC7.4",
                control_name="Audit Retention",
                framework=Framework.SOC2,
                status=ControlStatus.PARTIAL,
                evidence=["Insufficient events to assess retention"],
            )
        return ControlResult(
            control_id="SOC2-CC7.4",
            control_name="Audit Retention",
            framework=Framework.SOC2,
            status=ControlStatus.PASS,
            evidence=[
                f"Earliest: {events[0].timestamp}",
                f"Latest: {events[-1].timestamp}",
            ],
        )

    return [
        _Control("SOC2-CC7.2", "Audit Trail Completeness", "", check_audit_completeness),
        _Control("SOC2-CC7.3", "Audit Trail Integrity", "", check_integrity),
        _Control("SOC2-CC7.4", "Audit Retention", "", check_retention),
    ]


def _hipaa_controls() -> list[_Control]:
    """HIPAA — data access logging for healthcare agents."""

    def check_access_logging(ledger: EventLedger) -> ControlResult:
        """164.312(b): Audit controls — record access to ePHI."""
        events = ledger.events
        access_events = [
            e for e in events
            if e.payload.get("event_type") in ("data_access", "tool_call", "function_call")
        ]
        has_agent = all(e.payload.get("agent_id") for e in access_events)
        return ControlResult(
            control_id="HIPAA-164.312b",
            control_name="Audit Controls (ePHI Access)",
            framework=Framework.HIPAA,
            status=ControlStatus.PASS if access_events and has_agent else ControlStatus.PARTIAL,
            evidence=[f"{len(access_events)} access events, agent_id present: {has_agent}"],
            findings=[] if has_agent else ["Some access events lack agent_id"],
            recommendations=[] if has_agent else ["Ensure agent_id is set in AuditContext"],
        )

    def check_integrity_hipaa(ledger: EventLedger) -> ControlResult:
        """164.312(c)(1): Integrity — protect ePHI from improper alteration."""
        ok, errors = ledger.verify_chain()
        return ControlResult(
            control_id="HIPAA-164.312c1",
            control_name="Integrity Controls",
            framework=Framework.HIPAA,
            status=ControlStatus.PASS if ok else ControlStatus.FAIL,
            evidence=[f"Hash chain integrity: {'verified' if ok else 'BROKEN'}"],
            findings=errors,
        )

    def check_person_authentication(ledger: EventLedger) -> ControlResult:
        """164.312(d): Verify agent identity."""
        events = ledger.events
        ids = {e.payload.get("agent_id") for e in events}
        ids.discard(None)
        ids.discard("")
        return ControlResult(
            control_id="HIPAA-164.312d",
            control_name="Entity Authentication",
            framework=Framework.HIPAA,
            status=ControlStatus.PASS if ids else ControlStatus.FAIL,
            evidence=[f"Unique agent identities: {ids or 'NONE'}"],
            findings=[] if ids else ["No agent identity found"],
        )

    return [
        _Control("HIPAA-164.312b", "Audit Controls", "", check_access_logging),
        _Control("HIPAA-164.312c1", "Integrity Controls", "", check_integrity_hipaa),
        _Control("HIPAA-164.312d", "Entity Authentication", "", check_person_authentication),
    ]


def _gdpr_controls() -> list[_Control]:
    """GDPR — data processing records (Art 30) and right to explanation (Art 22)."""

    def check_processing_records(ledger: EventLedger) -> ControlResult:
        """Art 30: Records of processing activities."""
        events = ledger.events
        has_purpose = any(e.payload.get("metadata", {}).get("purpose") for e in events)
        return ControlResult(
            control_id="GDPR-30.1",
            control_name="Records of Processing Activities",
            framework=Framework.GDPR,
            status=ControlStatus.PASS if events and has_purpose else ControlStatus.PARTIAL,
            evidence=[f"Events: {len(events)}, purpose metadata: {has_purpose}"],
            findings=[] if has_purpose else ["No processing purpose metadata found"],
            recommendations=[] if has_purpose else [
                "Add 'purpose' to event metadata for GDPR Art 30 compliance"
            ],
        )

    def check_right_to_explanation(ledger: EventLedger) -> ControlResult:
        """Art 22: Right to explanation for automated decisions."""
        events = ledger.events
        has_io = sum(
            1 for e in events
            if e.payload.get("inputs") and e.payload.get("output") is not None
        )
        ratio = has_io / max(len(events), 1)
        status = ControlStatus.PASS if ratio >= 0.9 else (
            ControlStatus.PARTIAL if ratio > 0.5 else ControlStatus.FAIL
        )
        return ControlResult(
            control_id="GDPR-22.1",
            control_name="Right to Explanation",
            framework=Framework.GDPR,
            status=status,
            evidence=[f"{_pct(has_io, len(events))} of decisions are explainable"],
        )

    return [
        _Control("GDPR-30.1", "Processing Records", "", check_processing_records),
        _Control("GDPR-22.1", "Right to Explanation", "", check_right_to_explanation),
    ]


def _dora_controls() -> list[_Control]:
    """DORA — ICT incident reporting for financial services."""

    def check_ict_logging(ledger: EventLedger) -> ControlResult:
        """Art 11: ICT-related incident management — logging of ICT events."""
        events = ledger.events
        error_events = [e for e in events if e.payload.get("error")]
        logged = all(e.timestamp and e.event_id for e in error_events)
        return ControlResult(
            control_id="DORA-11.1",
            control_name="ICT Incident Logging",
            framework=Framework.DORA,
            status=ControlStatus.PASS if logged else ControlStatus.PARTIAL,
            evidence=[
                f"{len(error_events)} error events, fully logged: {logged}"
            ],
        )

    def check_resilience_testing(ledger: EventLedger) -> ControlResult:
        """Art 25: Operational resilience — evidence of anomaly detection."""
        events = ledger.events
        has_anomaly_check = any(
            e.payload.get("event_type") == "anomaly_check" for e in events
        )
        return ControlResult(
            control_id="DORA-25.1",
            control_name="Operational Resilience Testing",
            framework=Framework.DORA,
            status=ControlStatus.PASS if has_anomaly_check else ControlStatus.PARTIAL,
            evidence=["Anomaly detection active" if has_anomaly_check else "No anomaly checks found"],
            recommendations=[] if has_anomaly_check else [
                "Enable AnomalyDetector to satisfy DORA resilience requirements"
            ],
        )

    def check_third_party_risk(ledger: EventLedger) -> ControlResult:
        """Art 28: Third-party ICT risk — tool call monitoring."""
        events = ledger.events
        tool_calls = [e for e in events if e.payload.get("event_type") == "tool_call"]
        unique_tools = {e.payload.get("function_name", "unknown") for e in tool_calls}
        return ControlResult(
            control_id="DORA-28.1",
            control_name="Third-Party ICT Risk Monitoring",
            framework=Framework.DORA,
            status=ControlStatus.PASS if tool_calls else ControlStatus.NOT_APPLICABLE,
            evidence=[
                f"{len(tool_calls)} tool calls to {len(unique_tools)} unique tools"
            ],
        )

    return [
        _Control("DORA-11.1", "ICT Incident Logging", "", check_ict_logging),
        _Control("DORA-25.1", "Resilience Testing", "", check_resilience_testing),
        _Control("DORA-28.1", "Third-Party Risk", "", check_third_party_risk),
    ]


# ── Registry ──────────────────────────────────────────────────────────
_FRAMEWORK_CONTROLS: dict[Framework, list[_Control]] = {
    Framework.EU_AI_ACT: _eu_ai_act_controls(),
    Framework.SOC2: _soc2_controls(),
    Framework.HIPAA: _hipaa_controls(),
    Framework.GDPR: _gdpr_controls(),
    Framework.DORA: _dora_controls(),
}


# ── Compliance mapper ─────────────────────────────────────────────────
class ComplianceMapper:
    """Evaluate a ledger against one or more regulatory frameworks."""

    def __init__(self, ledger: EventLedger) -> None:
        self._ledger = ledger

    def evaluate(self, framework: Framework) -> ComplianceReport:
        controls = _FRAMEWORK_CONTROLS.get(framework, [])
        results: list[ControlResult] = []
        for ctrl in controls:
            result = ctrl.check(self._ledger)
            results.append(result)

        passed = sum(1 for r in results if r.status == ControlStatus.PASS)
        failed = sum(1 for r in results if r.status == ControlStatus.FAIL)
        partial = sum(1 for r in results if r.status == ControlStatus.PARTIAL)
        na = sum(1 for r in results if r.status == ControlStatus.NOT_APPLICABLE)
        applicable = len(results) - na
        score = (passed + partial * 0.5) / max(applicable, 1) * 100

        return ComplianceReport(
            framework=framework,
            total_controls=len(results),
            passed=passed,
            failed=failed,
            partial=partial,
            not_applicable=na,
            score=round(score, 1),
            controls=results,
            summary=self._generate_summary(framework, results, score),
        )

    def evaluate_all(self) -> list[ComplianceReport]:
        return [self.evaluate(fw) for fw in Framework]

    @staticmethod
    def _generate_summary(
        framework: Framework, results: list[ControlResult], score: float
    ) -> str:
        lines = [f"Compliance Report: {framework.value.upper()}"]
        lines.append(f"Overall Score: {score:.1f}%")
        lines.append("")
        for r in results:
            icon = {"pass": "OK", "fail": "FAIL", "partial": "WARN", "n/a": "N/A"}[
                r.status.value
            ]
            lines.append(f"  [{icon}] {r.control_id}: {r.control_name}")
            for f in r.findings:
                lines.append(f"        Finding: {f}")
            for rec in r.recommendations:
                lines.append(f"        Recommendation: {rec}")
        return "\n".join(lines)
