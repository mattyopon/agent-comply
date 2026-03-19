"""Tests for the decision reconstruction engine."""

import pytest

from agent_comply.ledger import EventLedger
from agent_comply.reconstruct import DecisionReconstructor, EdgeType


def _make_ledger() -> EventLedger:
    """Build a small ledger simulating an agent session."""
    ledger = EventLedger()
    ledger.append({
        "event_type": "function_call",
        "function_name": "plan_research",
        "session_id": "S1",
        "agent_id": "agent-1",
        "inputs": {"query": "climate data"},
        "output": "plan-object",
    })
    ledger.append({
        "event_type": "tool_call",
        "function_name": "web_search",
        "session_id": "S1",
        "agent_id": "agent-1",
        "inputs": {"url": "https://example.com"},
        "output": "search-results",
    })
    ledger.append({
        "event_type": "function_call",
        "function_name": "summarise",
        "session_id": "S1",
        "agent_id": "agent-1",
        "inputs": {"data": "search-results"},
        "output": "summary-text",
    })
    ledger.append({
        "event_type": "function_call",
        "function_name": "final_answer",
        "session_id": "S1",
        "agent_id": "agent-1",
        "inputs": {"text": "summary-text"},
        "output": "The answer is 42",
    })
    return ledger


class TestCausalChain:
    def test_chain_from_last_event(self):
        ledger = _make_ledger()
        recon = DecisionReconstructor(ledger)
        last_id = ledger.events[-1].event_id
        chain = recon.get_causal_chain(last_id)

        assert chain.target_event_id == last_id
        assert len(chain.chain) >= 2  # at minimum temporal ancestors
        # The chain should include the target itself
        ids = [e.event_id for e in chain.chain]
        assert last_id in ids

    def test_chain_includes_data_flow(self):
        ledger = _make_ledger()
        recon = DecisionReconstructor(ledger)
        # event 2 (summarise) takes "search-results" which is output of event 1
        ev2_id = ledger.events[2].event_id
        chain = recon.get_causal_chain(ev2_id)
        chain_ids = {e.event_id for e in chain.chain}
        # Should include event 1 via data_flow
        assert ledger.events[1].event_id in chain_ids

    def test_chain_unknown_event_raises(self):
        ledger = _make_ledger()
        recon = DecisionReconstructor(ledger)
        with pytest.raises(KeyError):
            recon.get_causal_chain("EVT-nonexistent")


class TestDecisionTree:
    def test_tree_structure(self):
        ledger = _make_ledger()
        recon = DecisionReconstructor(ledger)
        tree = recon.build_decision_tree()
        assert tree.event_id == ledger.events[0].event_id
        assert tree.depth == 0
        # Root should have children (temporal successors)
        assert len(tree.children) >= 1

    def test_tree_from_specific_root(self):
        ledger = _make_ledger()
        recon = DecisionReconstructor(ledger)
        mid_id = ledger.events[1].event_id
        tree = recon.build_decision_tree(mid_id)
        assert tree.event_id == mid_id

    def test_tree_empty_ledger_raises(self):
        ledger = EventLedger()
        recon = DecisionReconstructor(ledger)
        with pytest.raises(ValueError):
            recon.build_decision_tree()


class TestCounterfactual:
    def test_counterfactual_impact(self):
        ledger = _make_ledger()
        recon = DecisionReconstructor(ledger)
        first_id = ledger.events[0].event_id
        result = recon.counterfactual(first_id, "output", "different-plan")

        assert result.original_event_id == first_id
        assert result.modified_field == "output"
        assert result.counterfactual_value == "different-plan"
        # The first event should affect downstream events
        assert len(result.affected_events) >= 1
        assert result.impact_score > 0

    def test_counterfactual_last_event_no_downstream(self):
        ledger = _make_ledger()
        recon = DecisionReconstructor(ledger)
        last_id = ledger.events[-1].event_id
        result = recon.counterfactual(last_id, "output", "new-answer")
        # Last event has no descendants
        assert result.impact_score == 0.0


class TestEventContext:
    def test_context_has_parents_and_children(self):
        ledger = _make_ledger()
        recon = DecisionReconstructor(ledger)
        mid_id = ledger.events[1].event_id
        ctx = recon.get_event_context(mid_id)
        assert "event" in ctx
        assert "parents" in ctx
        assert "children" in ctx
        assert len(ctx["parents"]) >= 1
        assert len(ctx["children"]) >= 1

    def test_context_unknown_event(self):
        ledger = _make_ledger()
        recon = DecisionReconstructor(ledger)
        with pytest.raises(KeyError):
            recon.get_event_context("EVT-nope")


class TestToolCallEdges:
    def test_tool_call_edge_inferred(self):
        ledger = _make_ledger()
        recon = DecisionReconstructor(ledger)
        # event 0 is function_call, event 1 is tool_call in same session
        ev1_id = ledger.events[1].event_id
        ctx = recon.get_event_context(ev1_id)
        edge_types = {e.edge_type for e in ctx["edges_in"]}
        assert EdgeType.TOOL_CALL in edge_types or EdgeType.TEMPORAL in edge_types
