"""Report generation — compliance reports, timelines, executive summaries.

Generates structured text reports (and optionally rich terminal output).
PDF generation uses a minimal approach without heavy dependencies.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from agent_comply.anomaly import AnomalyDetector, SessionRiskReport
from agent_comply.compliance import ComplianceMapper, ComplianceReport, Framework
from agent_comply.ledger import EventLedger
from agent_comply.reconstruct import DecisionReconstructor


class ReportSection(BaseModel):
    title: str
    content: str


class FullReport(BaseModel):
    title: str
    generated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    sections: list[ReportSection] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def to_text(self) -> str:
        lines: list[str] = []
        lines.append("=" * 72)
        lines.append(self.title.center(72))
        lines.append(f"Generated: {self.generated_at}".center(72))
        lines.append("=" * 72)
        lines.append("")
        for section in self.sections:
            lines.append(f"--- {section.title} ---")
            lines.append(section.content)
            lines.append("")
        lines.append("=" * 72)
        return "\n".join(lines)


class ReportGenerator:
    """Generates compliance and audit reports from ledger data."""

    def __init__(self, ledger: EventLedger) -> None:
        self._ledger = ledger

    def compliance_report(
        self, framework: Framework | None = None
    ) -> FullReport:
        """Generate a compliance report for one or all frameworks."""
        mapper = ComplianceMapper(self._ledger)
        if framework:
            reports = [mapper.evaluate(framework)]
        else:
            reports = mapper.evaluate_all()

        sections: list[ReportSection] = []

        # Executive summary
        avg_score = sum(r.score for r in reports) / max(len(reports), 1)
        total_fail = sum(r.failed for r in reports)
        exec_lines = [
            f"Frameworks evaluated: {len(reports)}",
            f"Average compliance score: {avg_score:.1f}%",
            f"Total failed controls: {total_fail}",
            "",
        ]
        if total_fail > 0:
            exec_lines.append("ACTION REQUIRED: Address failed controls immediately.")
        else:
            exec_lines.append("All evaluated controls are passing or partially met.")
        sections.append(ReportSection(
            title="Executive Summary",
            content="\n".join(exec_lines),
        ))

        # Per-framework detail
        for r in reports:
            sections.append(ReportSection(
                title=f"Framework: {r.framework.value.upper()}",
                content=r.summary,
            ))

        return FullReport(
            title="Agent Compliance Report",
            sections=sections,
            metadata={"frameworks": [r.framework.value for r in reports]},
        )

    def timeline_report(self) -> FullReport:
        """Generate a chronological timeline of all events."""
        events = self._ledger.events
        sections: list[ReportSection] = []

        lines: list[str] = []
        for i, ev in enumerate(events):
            fn = ev.payload.get("function_name", "unknown")
            etype = ev.payload.get("event_type", "event")
            error = ev.payload.get("error")
            dur = ev.payload.get("duration_ms", "?")
            status = "ERROR" if error else "OK"
            lines.append(
                f"  [{i:04d}] {ev.timestamp}  {etype:<16} {fn:<30} "
                f"{dur}ms  [{status}]"
            )
            if error:
                lines.append(f"         Error: {error}")

        sections.append(ReportSection(
            title=f"Event Timeline ({len(events)} events)",
            content="\n".join(lines) if lines else "(no events)",
        ))

        # Integrity check
        ok, errors = self._ledger.verify_all()
        integrity_content = "Chain and Merkle integrity: VERIFIED" if ok else (
            "INTEGRITY ISSUES DETECTED:\n" + "\n".join(f"  - {e}" for e in errors)
        )
        sections.append(ReportSection(
            title="Integrity Verification",
            content=integrity_content,
        ))

        return FullReport(title="Agent Decision Timeline", sections=sections)

    def anomaly_report(self) -> FullReport:
        """Run anomaly detection and generate a risk report."""
        detector = AnomalyDetector()
        detector.train(self._ledger)
        session_reports = detector.analyse(self._ledger)

        sections: list[ReportSection] = []

        # Summary
        total_alerts = sum(len(r.alerts) for r in session_reports)
        max_risk = max((r.risk_score for r in session_reports), default=0)
        summary_lines = [
            f"Sessions analysed: {len(session_reports)}",
            f"Total alerts: {total_alerts}",
            f"Maximum session risk: {max_risk:.2f}",
        ]
        sections.append(ReportSection(
            title="Anomaly Detection Summary",
            content="\n".join(summary_lines),
        ))

        for sr in session_reports:
            if sr.alerts:
                sections.append(ReportSection(
                    title=f"Session {sr.session_id} (risk={sr.risk_score:.2f})",
                    content=sr.summary,
                ))

        return FullReport(
            title="Agent Behavioral Anomaly Report",
            sections=sections,
        )

    def decision_chain_report(self, event_id: str) -> FullReport:
        """Reconstruct and report the decision chain for a specific event."""
        recon = DecisionReconstructor(self._ledger)
        chain = recon.get_causal_chain(event_id)

        sections: list[ReportSection] = []

        lines = [f"Target event: {event_id}", f"Chain depth: {chain.depth}", ""]
        for i, ev in enumerate(chain.chain):
            fn = ev.payload.get("function_name", "?")
            lines.append(f"  {'  ' * i}{ev.event_id}  {fn}  ({ev.timestamp})")

        sections.append(ReportSection(
            title="Causal Chain",
            content="\n".join(lines),
        ))

        edge_lines = []
        for e in chain.edges:
            edge_lines.append(f"  {e.source_id} --[{e.edge_type.value}]--> {e.target_id}")
        sections.append(ReportSection(
            title="Dependency Edges",
            content="\n".join(edge_lines) if edge_lines else "(none)",
        ))

        return FullReport(
            title=f"Decision Reconstruction: {event_id}",
            sections=sections,
        )

    def export_text(self, report: FullReport, path: str | Path) -> None:
        """Write a report as plain text."""
        Path(path).write_text(report.to_text(), encoding="utf-8")

    def export_json(self, report: FullReport, path: str | Path) -> None:
        """Write a report as JSON."""
        Path(path).write_text(
            report.model_dump_json(indent=2), encoding="utf-8"
        )

    def evidence_package(self, output_dir: str | Path) -> Path:
        """Create a full evidence package for auditors.

        Writes:
          - events.jsonl  (raw ledger)
          - compliance.json
          - timeline.txt
          - anomaly.json
          - integrity.json
        """
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        # Events
        self._ledger.export_jsonl(out / "events.jsonl")

        # Compliance
        cr = self.compliance_report()
        self.export_json(cr, out / "compliance.json")

        # Timeline
        tr = self.timeline_report()
        self.export_text(tr, out / "timeline.txt")

        # Anomaly
        ar = self.anomaly_report()
        self.export_json(ar, out / "anomaly.json")

        # Integrity
        ok, errors = self._ledger.verify_all()
        integrity = {
            "verified": ok,
            "merkle_root": self._ledger.merkle_root,
            "event_count": len(self._ledger),
            "errors": errors,
        }
        (out / "integrity.json").write_text(
            json.dumps(integrity, indent=2), encoding="utf-8"
        )

        return out
