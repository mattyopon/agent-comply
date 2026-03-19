"""Tests for regulatory compliance mapping."""

import pytest

from agent_comply.compliance import (
    ComplianceMapper,
    ComplianceReport,
    ControlStatus,
    Framework,
)
from agent_comply.ledger import EventLedger


def _compliant_ledger() -> EventLedger:
    """A ledger with events that satisfy most controls."""
    ledger = EventLedger()
    ledger.append({
        "event_type": "function_call",
        "function_name": "analyse",
        "agent_id": "agent-1",
        "session_id": "S1",
        "inputs": {"query": "patient vitals"},
        "output": "analysis result",
        "metadata": {"risk_level": "high", "purpose": "medical analysis"},
    })
    ledger.append({
        "event_type": "human_review",
        "function_name": "doctor_approval",
        "agent_id": "agent-1",
        "session_id": "S1",
        "inputs": {"analysis": "analysis result"},
        "output": "approved",
        "metadata": {"risk_level": "high", "purpose": "human oversight"},
    })
    ledger.append({
        "event_type": "tool_call",
        "function_name": "update_record",
        "agent_id": "agent-1",
        "session_id": "S1",
        "inputs": {"record_id": "R123"},
        "output": "updated",
        "metadata": {"purpose": "record update"},
    })
    return ledger


def _minimal_ledger() -> EventLedger:
    """A bare-bones ledger that fails many controls."""
    ledger = EventLedger()
    ledger.append({"event_type": "function_call"})
    return ledger


class TestEUAIAct:
    def test_compliant_ledger_scores_high(self):
        ledger = _compliant_ledger()
        mapper = ComplianceMapper(ledger)
        report = mapper.evaluate(Framework.EU_AI_ACT)
        assert report.score >= 75
        assert report.passed >= 2

    def test_transparency_passes_with_io(self):
        ledger = _compliant_ledger()
        mapper = ComplianceMapper(ledger)
        report = mapper.evaluate(Framework.EU_AI_ACT)
        transparency = next(c for c in report.controls if c.control_id == "EU-AI-13.1")
        assert transparency.status == ControlStatus.PASS

    def test_human_oversight_detected(self):
        ledger = _compliant_ledger()
        mapper = ComplianceMapper(ledger)
        report = mapper.evaluate(Framework.EU_AI_ACT)
        oversight = next(c for c in report.controls if c.control_id == "EU-AI-14.1")
        assert oversight.status == ControlStatus.PASS

    def test_minimal_ledger_fails_oversight(self):
        ledger = _minimal_ledger()
        mapper = ComplianceMapper(ledger)
        report = mapper.evaluate(Framework.EU_AI_ACT)
        oversight = next(c for c in report.controls if c.control_id == "EU-AI-14.1")
        assert oversight.status == ControlStatus.FAIL


class TestSOC2:
    def test_integrity_passes(self):
        ledger = _compliant_ledger()
        mapper = ComplianceMapper(ledger)
        report = mapper.evaluate(Framework.SOC2)
        integrity = next(c for c in report.controls if c.control_id == "SOC2-CC7.3")
        assert integrity.status == ControlStatus.PASS

    def test_tampered_ledger_fails_integrity(self):
        ledger = _compliant_ledger()
        ledger._events[1].payload["tampered"] = True
        mapper = ComplianceMapper(ledger)
        report = mapper.evaluate(Framework.SOC2)
        integrity = next(c for c in report.controls if c.control_id == "SOC2-CC7.3")
        assert integrity.status == ControlStatus.FAIL


class TestHIPAA:
    def test_access_logging(self):
        ledger = _compliant_ledger()
        mapper = ComplianceMapper(ledger)
        report = mapper.evaluate(Framework.HIPAA)
        access = next(c for c in report.controls if c.control_id == "HIPAA-164.312b")
        assert access.status in (ControlStatus.PASS, ControlStatus.PARTIAL)

    def test_entity_auth_present(self):
        ledger = _compliant_ledger()
        mapper = ComplianceMapper(ledger)
        report = mapper.evaluate(Framework.HIPAA)
        auth = next(c for c in report.controls if c.control_id == "HIPAA-164.312d")
        assert auth.status == ControlStatus.PASS


class TestGDPR:
    def test_processing_records_with_purpose(self):
        ledger = _compliant_ledger()
        mapper = ComplianceMapper(ledger)
        report = mapper.evaluate(Framework.GDPR)
        records = next(c for c in report.controls if c.control_id == "GDPR-30.1")
        assert records.status == ControlStatus.PASS

    def test_right_to_explanation(self):
        ledger = _compliant_ledger()
        mapper = ComplianceMapper(ledger)
        report = mapper.evaluate(Framework.GDPR)
        explanation = next(c for c in report.controls if c.control_id == "GDPR-22.1")
        assert explanation.status == ControlStatus.PASS


class TestDORA:
    def test_tool_call_monitoring(self):
        ledger = _compliant_ledger()
        mapper = ComplianceMapper(ledger)
        report = mapper.evaluate(Framework.DORA)
        third_party = next(c for c in report.controls if c.control_id == "DORA-28.1")
        assert third_party.status == ControlStatus.PASS


class TestEvaluateAll:
    def test_all_frameworks(self):
        ledger = _compliant_ledger()
        mapper = ComplianceMapper(ledger)
        reports = mapper.evaluate_all()
        assert len(reports) == len(Framework)
        for r in reports:
            assert isinstance(r, ComplianceReport)
            assert r.total_controls > 0
