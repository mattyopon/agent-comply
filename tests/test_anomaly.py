"""Tests for behavioral anomaly detection."""


from agent_comply.anomaly import AlertSeverity, AnomalyDetector
from agent_comply.ledger import EventLedger


def _normal_ledger(n_sessions: int = 5, events_per: int = 10) -> EventLedger:
    """Generate a ledger with several 'normal' sessions for baseline training."""
    ledger = EventLedger()
    for s in range(n_sessions):
        sid = f"S-{s}"
        for i in range(events_per):
            ledger.append({
                "event_type": "function_call",
                "function_name": "process",
                "agent_id": "agent-1",
                "session_id": sid,
                "inputs": {"step": i},
                "output": f"result-{i}",
                "duration_ms": 50 + (i % 5),
            })
    return ledger


def _anomalous_ledger() -> EventLedger:
    """A ledger with sessions exhibiting anomalous behaviour."""
    ledger = EventLedger()
    sid = "S-bad"
    # Very many events (outlier length)
    for i in range(100):
        ledger.append({
            "event_type": "function_call",
            "function_name": "process",
            "agent_id": "agent-1",
            "session_id": sid,
            "inputs": {"step": i},
            "output": f"result-{i}",
            "error": "Timeout" if i % 3 == 0 else None,
            "duration_ms": 5000 if i % 10 == 0 else 60,
        })
    return ledger


class TestBaseline:
    def test_train_builds_baseline(self):
        detector = AnomalyDetector()
        ledger = _normal_ledger()
        detector.train(ledger)
        # Should have baseline for agent-1
        assert "agent-1" in detector._baselines
        bl = detector._baselines["agent-1"]
        assert len(bl.event_counts) == 5
        assert bl.mean_events == 10

    def test_train_incremental(self):
        detector = AnomalyDetector()
        detector.train(_normal_ledger(3))
        detector.train(_normal_ledger(2))
        bl = detector._baselines["agent-1"]
        assert len(bl.event_counts) == 5


class TestDetection:
    def test_normal_session_low_risk(self):
        detector = AnomalyDetector()
        detector.train(_normal_ledger())
        reports = detector.analyse(_normal_ledger(1))
        assert len(reports) == 1
        # Normal session should have low risk
        assert reports[0].risk_score < 0.3

    def test_anomalous_session_high_risk(self):
        detector = AnomalyDetector()
        detector.train(_normal_ledger())
        reports = detector.analyse(_anomalous_ledger())
        assert len(reports) == 1
        assert reports[0].risk_score > 0.3
        assert len(reports[0].alerts) >= 1

    def test_high_error_rate_detected(self):
        detector = AnomalyDetector()
        ledger = EventLedger()
        for i in range(10):
            ledger.append({
                "event_type": "function_call",
                "function_name": "broken",
                "agent_id": "agent-1",
                "session_id": "S-err",
                "error": "crash" if i < 8 else None,
            })
        reports = detector.analyse(ledger)
        alert_rules = {a.rule for a in reports[0].alerts}
        assert "high_error_rate" in alert_rules

    def test_unknown_tool_detected(self):
        detector = AnomalyDetector()
        # Train on known tools
        train_ledger = EventLedger()
        for i in range(5):
            train_ledger.append({
                "event_type": "tool_call",
                "function_name": "known_tool",
                "agent_id": "agent-2",
                "session_id": "S-train",
            })
        detector.train(train_ledger)

        # Analyse session with unknown tool
        test_ledger = EventLedger()
        test_ledger.append({
            "event_type": "tool_call",
            "function_name": "suspicious_tool",
            "agent_id": "agent-2",
            "session_id": "S-test",
        })
        reports = detector.analyse(test_ledger)
        alert_rules = {a.rule for a in reports[0].alerts}
        assert "unknown_tool" in alert_rules

    def test_excessive_data_access(self):
        detector = AnomalyDetector()
        ledger = EventLedger()
        for i in range(30):
            ledger.append({
                "event_type": "data_access",
                "function_name": "read_db",
                "agent_id": "agent-1",
                "session_id": "S-data",
            })
        reports = detector.analyse(ledger)
        alert_rules = {a.rule for a in reports[0].alerts}
        assert "excessive_data_access" in alert_rules

    def test_policy_violation_critical(self):
        detector = AnomalyDetector()
        ledger = EventLedger()
        ledger.append({
            "event_type": "function_call",
            "function_name": "action",
            "agent_id": "agent-1",
            "session_id": "S-pol",
            "metadata": {"policy_violation": "unauthorized_access"},
        })
        reports = detector.analyse(ledger)
        critical_alerts = [a for a in reports[0].alerts if a.severity == AlertSeverity.CRITICAL]
        assert len(critical_alerts) >= 1


class TestAnalyseEvents:
    def test_raw_event_analysis(self):
        detector = AnomalyDetector()
        events = [
            {"event_type": "function_call", "error": "fail"},
            {"event_type": "function_call", "error": "fail"},
            {"event_type": "function_call", "error": "fail"},
            {"event_type": "function_call", "error": None},
        ]
        alerts = detector.analyse_events(events)
        assert any(a.rule == "high_error_rate" for a in alerts)


class TestRiskAggregation:
    def test_no_alerts_zero_risk(self):
        detector = AnomalyDetector()
        risk = detector._aggregate_risk([])
        assert risk == 0.0

    def test_risk_increases_with_alerts(self):
        from agent_comply.anomaly import AnomalyAlert
        detector = AnomalyDetector()
        alerts_low = [AnomalyAlert(rule="test", severity=AlertSeverity.LOW, score=0.2)]
        alerts_high = [AnomalyAlert(rule="test", severity=AlertSeverity.CRITICAL, score=1.0)]
        risk_low = detector._aggregate_risk(alerts_low)
        risk_high = detector._aggregate_risk(alerts_high)
        assert risk_high > risk_low
