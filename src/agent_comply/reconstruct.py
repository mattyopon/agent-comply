"""Decision reconstruction engine — rebuild the full causal chain behind any agent output.

Given a set of ledger events, this module can:
  1. Build a directed acyclic graph (DAG) of event dependencies.
  2. Extract the causal chain leading to any specific event.
  3. Perform counterfactual analysis (what-if scenarios).
  4. Generate visual decision trees.

PATENTABLE TECHNOLOGY — do not disclose implementation details externally without
legal review.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

from pydantic import BaseModel, Field

from agent_comply.ledger import EventLedger, LedgerEvent


# ── Data models ────────────────────────────────────────────────────────
class EdgeType(str, Enum):
    DATA_FLOW = "data_flow"
    TEMPORAL = "temporal"
    TOOL_CALL = "tool_call"
    DECISION = "decision"


class CausalEdge(BaseModel):
    source_id: str
    target_id: str
    edge_type: EdgeType
    label: str = ""


class DecisionNode(BaseModel):
    event_id: str
    function_name: str
    event_type: str
    timestamp: str
    inputs_summary: str = ""
    output_summary: str = ""
    depth: int = 0
    children: list["DecisionNode"] = Field(default_factory=list)


class CausalChain(BaseModel):
    """The fully-resolved causal chain leading to a target event."""

    target_event_id: str
    chain: list[LedgerEvent] = Field(default_factory=list)
    edges: list[CausalEdge] = Field(default_factory=list)
    depth: int = 0


class CounterfactualResult(BaseModel):
    """Result of a what-if analysis."""

    original_event_id: str
    modified_field: str
    original_value: Any = None
    counterfactual_value: Any = None
    affected_events: list[str] = Field(default_factory=list)
    impact_score: float = 0.0  # 0..1


# ── Dependency graph ───────────────────────────────────────────────────
@dataclass
class _DependencyGraph:
    """Internal DAG representation built from ledger events."""

    adjacency: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    reverse: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    edges: dict[tuple[str, str], CausalEdge] = field(default_factory=dict)
    nodes: dict[str, LedgerEvent] = field(default_factory=dict)

    def add_edge(self, source_id: str, target_id: str, edge_type: EdgeType, label: str = "") -> None:
        self.adjacency[source_id].append(target_id)
        self.reverse[target_id].append(source_id)
        edge = CausalEdge(
            source_id=source_id,
            target_id=target_id,
            edge_type=edge_type,
            label=label,
        )
        self.edges[(source_id, target_id)] = edge


# ── Reconstruction engine ─────────────────────────────────────────────
class DecisionReconstructor:
    """Reconstructs causal chains and decision trees from ledger events."""

    def __init__(self, ledger: EventLedger) -> None:
        self._ledger = ledger
        self._graph = _DependencyGraph()
        self._build_graph()

    # ── graph construction ─────────────────────────────────────────────
    def _build_graph(self) -> None:
        """Analyse ledger events and infer causal edges."""
        events = self._ledger.events
        if not events:
            return

        # Index events
        for ev in events:
            self._graph.nodes[ev.event_id] = ev

        # 1. Temporal edges: each event depends on the immediately preceding one
        for i in range(1, len(events)):
            prev, curr = events[i - 1], events[i]
            self._graph.add_edge(
                prev.event_id,
                curr.event_id,
                EdgeType.TEMPORAL,
                "temporal_sequence",
            )

        # 2. Data-flow edges: if an event's input references another event's
        #    output (matched by event_id or by value overlap)
        output_index: dict[str, str] = {}  # serialised-output → event_id
        for ev in events:
            out = ev.payload.get("output")
            if out is not None:
                key = str(out)[:256]
                output_index[key] = ev.event_id

        for ev in events:
            inputs = ev.payload.get("inputs", {})
            for _param_name, val in (inputs.items() if isinstance(inputs, dict) else []):
                key = str(val)[:256]
                if key in output_index and output_index[key] != ev.event_id:
                    self._graph.add_edge(
                        output_index[key],
                        ev.event_id,
                        EdgeType.DATA_FLOW,
                        "data_flow",
                    )

            # Explicit parent link
            parent_id = ev.payload.get("parent_event_id")
            if parent_id and parent_id in self._graph.nodes:
                self._graph.add_edge(
                    parent_id,
                    ev.event_id,
                    EdgeType.DECISION,
                    "explicit_parent",
                )

        # 3. Tool-call edges: function_call → tool_call within same session
        session_events: dict[str, list[LedgerEvent]] = defaultdict(list)
        for ev in events:
            sid = ev.payload.get("session_id", "")
            session_events[sid].append(ev)

        for _sid, sevents in session_events.items():
            last_function: LedgerEvent | None = None
            for ev in sevents:
                etype = ev.payload.get("event_type", "")
                if etype == "function_call":
                    last_function = ev
                elif etype == "tool_call" and last_function is not None:
                    self._graph.add_edge(
                        last_function.event_id,
                        ev.event_id,
                        EdgeType.TOOL_CALL,
                        "invoked_tool",
                    )

    # ── causal chain extraction ────────────────────────────────────────
    def get_causal_chain(self, target_event_id: str) -> CausalChain:
        """BFS backward from *target_event_id* to find all ancestors."""
        if target_event_id not in self._graph.nodes:
            raise KeyError(f"Event {target_event_id!r} not found in ledger")

        visited: set[str] = set()
        queue: deque[str] = deque([target_event_id])
        chain_ids: list[str] = []
        edges: list[CausalEdge] = []

        while queue:
            nid = queue.popleft()
            if nid in visited:
                continue
            visited.add(nid)
            chain_ids.append(nid)

            for parent_id in self._graph.reverse.get(nid, []):
                edge = self._graph.edges.get((parent_id, nid))
                if edge:
                    edges.append(edge)
                if parent_id not in visited:
                    queue.append(parent_id)

        chain_events = [
            self._graph.nodes[eid]
            for eid in reversed(chain_ids)
            if eid in self._graph.nodes
        ]
        return CausalChain(
            target_event_id=target_event_id,
            chain=chain_events,
            edges=edges,
            depth=len(chain_events) - 1,
        )

    # ── decision tree ──────────────────────────────────────────────────
    def build_decision_tree(self, root_event_id: str | None = None) -> DecisionNode:
        """Build a tree rooted at *root_event_id* (default: first event).

        Produces a nested ``DecisionNode`` suitable for visualisation.
        """
        events = self._ledger.events
        if not events:
            raise ValueError("Ledger is empty")

        root_id = root_event_id or events[0].event_id
        if root_id not in self._graph.nodes:
            raise KeyError(f"Event {root_id!r} not found")

        return self._subtree(root_id, depth=0, visited=set())

    def _subtree(self, event_id: str, depth: int, visited: set[str]) -> DecisionNode:
        if event_id in visited:
            ev = self._graph.nodes[event_id]
            return DecisionNode(
                event_id=event_id,
                function_name=ev.payload.get("function_name", ""),
                event_type=ev.payload.get("event_type", ""),
                timestamp=ev.timestamp,
                depth=depth,
            )
        visited.add(event_id)
        ev = self._graph.nodes[event_id]
        children: list[DecisionNode] = []
        for child_id in self._graph.adjacency.get(event_id, []):
            children.append(self._subtree(child_id, depth + 1, visited))

        inputs = ev.payload.get("inputs", {})
        output = ev.payload.get("output")

        return DecisionNode(
            event_id=event_id,
            function_name=ev.payload.get("function_name", ""),
            event_type=ev.payload.get("event_type", ""),
            timestamp=ev.timestamp,
            inputs_summary=_summarise(inputs, max_len=120),
            output_summary=_summarise(output, max_len=120),
            depth=depth,
            children=children,
        )

    # ── counterfactual analysis ────────────────────────────────────────
    def counterfactual(
        self,
        event_id: str,
        field: str,
        new_value: Any,
        propagate_fn: Callable[[LedgerEvent, str, Any], list[str]] | None = None,
    ) -> CounterfactualResult:
        """Estimate the downstream impact of changing *field* on *event_id*.

        If *propagate_fn* is provided it is called as
        ``propagate_fn(event, field, new_value)`` and should return a list of
        affected event IDs.  Otherwise a default BFS forward-propagation is used.
        """
        if event_id not in self._graph.nodes:
            raise KeyError(f"Event {event_id!r} not found")

        ev = self._graph.nodes[event_id]
        original_value = ev.payload.get(field)

        if propagate_fn is not None:
            affected = propagate_fn(ev, field, new_value)
        else:
            affected = self._forward_reach(event_id)

        total = max(len(self._graph.nodes) - 1, 1)
        impact = len(affected) / total

        return CounterfactualResult(
            original_event_id=event_id,
            modified_field=field,
            original_value=original_value,
            counterfactual_value=new_value,
            affected_events=affected,
            impact_score=round(impact, 4),
        )

    def _forward_reach(self, event_id: str) -> list[str]:
        """BFS forward to find all descendants."""
        visited: set[str] = set()
        queue: deque[str] = deque([event_id])
        result: list[str] = []
        while queue:
            nid = queue.popleft()
            if nid in visited:
                continue
            visited.add(nid)
            if nid != event_id:
                result.append(nid)
            for child in self._graph.adjacency.get(nid, []):
                if child not in visited:
                    queue.append(child)
        return result

    # ── utilities ──────────────────────────────────────────────────────
    def get_event_context(self, event_id: str) -> dict[str, Any]:
        """Return rich context for a single event: parents, children, edges."""
        if event_id not in self._graph.nodes:
            raise KeyError(event_id)
        parents = self._graph.reverse.get(event_id, [])
        children = self._graph.adjacency.get(event_id, [])
        edges_in = [
            self._graph.edges[(p, event_id)]
            for p in parents
            if (p, event_id) in self._graph.edges
        ]
        edges_out = [
            self._graph.edges[(event_id, c)]
            for c in children
            if (event_id, c) in self._graph.edges
        ]
        return {
            "event": self._graph.nodes[event_id],
            "parents": parents,
            "children": children,
            "edges_in": edges_in,
            "edges_out": edges_out,
        }


# ── helpers ────────────────────────────────────────────────────────────
def _summarise(value: Any, max_len: int = 120) -> str:
    s = str(value)
    if len(s) > max_len:
        return s[: max_len - 3] + "..."
    return s
