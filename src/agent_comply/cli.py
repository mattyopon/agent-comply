"""CLI interface for agent-comply."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from agent_comply.anomaly import AnomalyDetector
from agent_comply.compliance import ComplianceMapper, Framework
from agent_comply.ledger import EventLedger
from agent_comply.reconstruct import DecisionReconstructor
from agent_comply.reporter import ReportGenerator

app = typer.Typer(
    name="agent-comply",
    help="Compliance and audit trail for AI agent workflows.",
    no_args_is_help=True,
)
console = Console()


@app.command()
def verify(
    events_file: Path = typer.Argument(..., help="Path to events JSONL file"),
) -> None:
    """Verify ledger integrity (hash chain + Merkle tree)."""
    if not events_file.exists():
        console.print(f"[red]File not found: {events_file}[/red]")
        raise typer.Exit(1)

    ledger = EventLedger.import_jsonl(events_file)
    ok, errors = ledger.verify_all()

    console.print(f"\nEvents loaded: {len(ledger)}")
    console.print(f"Merkle root:   {ledger.merkle_root[:32]}...")

    if ok:
        console.print("[green]Integrity: VERIFIED[/green]")
    else:
        console.print("[red]Integrity: FAILED[/red]")
        for err in errors:
            console.print(f"  [red]- {err}[/red]")
        raise typer.Exit(1)


@app.command()
def reconstruct(
    events_file: Path = typer.Argument(..., help="Path to events JSONL file"),
    event_id: str = typer.Option(..., "--event-id", "-e", help="Target event ID"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file"),
) -> None:
    """Reconstruct the decision chain leading to a specific event."""
    ledger = EventLedger.import_jsonl(events_file)
    rg = ReportGenerator(ledger)

    try:
        report = rg.decision_chain_report(event_id)
    except KeyError:
        console.print(f"[red]Event {event_id!r} not found[/red]")
        raise typer.Exit(1)

    text = report.to_text()
    if output:
        output.write_text(text, encoding="utf-8")
        console.print(f"Report written to {output}")
    else:
        console.print(text)


@app.command()
def report(
    events_file: Path = typer.Argument(..., help="Path to events JSONL file"),
    framework: str = typer.Option(
        "all",
        "--framework",
        "-f",
        help="Regulatory framework (eu-ai-act, soc2, hipaa, gdpr, dora, all)",
    ),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file"),
    fmt: str = typer.Option("text", "--format", help="Output format (text, json)"),
) -> None:
    """Generate a compliance report."""
    ledger = EventLedger.import_jsonl(events_file)
    rg = ReportGenerator(ledger)

    fw: Framework | None = None
    if framework != "all":
        try:
            fw = Framework(framework)
        except ValueError:
            console.print(f"[red]Unknown framework: {framework}[/red]")
            console.print(f"Available: {', '.join(f.value for f in Framework)}")
            raise typer.Exit(1)

    full_report = rg.compliance_report(fw)

    if fmt == "json":
        content = full_report.model_dump_json(indent=2)
    else:
        content = full_report.to_text()

    if output:
        output.write_text(content, encoding="utf-8")
        console.print(f"Report written to {output}")
    else:
        console.print(content)


@app.command()
def anomaly(
    events_file: Path = typer.Argument(..., help="Path to events JSONL file"),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
) -> None:
    """Detect behavioral anomalies in agent sessions."""
    ledger = EventLedger.import_jsonl(events_file)
    rg = ReportGenerator(ledger)
    full_report = rg.anomaly_report()

    text = full_report.to_text()
    if output:
        output.write_text(text, encoding="utf-8")
        console.print(f"Report written to {output}")
    else:
        console.print(text)


@app.command()
def evidence(
    events_file: Path = typer.Argument(..., help="Path to events JSONL file"),
    output_dir: Path = typer.Option(
        "evidence-package", "--output-dir", "-d", help="Output directory"
    ),
) -> None:
    """Export a full evidence package for auditors."""
    ledger = EventLedger.import_jsonl(events_file)
    rg = ReportGenerator(ledger)
    out = rg.evidence_package(output_dir)
    console.print(f"[green]Evidence package written to {out}[/green]")


@app.command()
def info(
    events_file: Path = typer.Argument(..., help="Path to events JSONL file"),
) -> None:
    """Show summary information about a ledger file."""
    ledger = EventLedger.import_jsonl(events_file)

    table = Table(title="Ledger Summary")
    table.add_column("Property", style="bold")
    table.add_column("Value")

    table.add_row("Total events", str(len(ledger)))
    table.add_row("Merkle root", ledger.merkle_root[:32] + "...")

    ok, errors = ledger.verify_chain()
    table.add_row("Chain integrity", "[green]OK[/green]" if ok else "[red]BROKEN[/red]")

    if ledger.events:
        table.add_row("First event", ledger.events[0].timestamp)
        table.add_row("Last event", ledger.events[-1].timestamp)

        agents = {e.payload.get("agent_id", "?") for e in ledger.events}
        sessions = {e.payload.get("session_id", "?") for e in ledger.events}
        table.add_row("Agents", ", ".join(str(a) for a in agents))
        table.add_row("Sessions", str(len(sessions)))

    console.print(table)


if __name__ == "__main__":
    app()
