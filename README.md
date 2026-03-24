# agent-comply

**Tamper-proof compliance auditing for AI agent workflows.**

[![Part of AI Agent Security Suite](https://img.shields.io/badge/Part%20of-AI%20Agent%20Security%20Suite-blueviolet)](https://github.com/mattyopon/ai-agent-security-suite)

Capture every decision your AI agents make, prove nothing was altered, reconstruct the causal chain behind any output, and map it all to the regulatory frameworks that matter.

---

## The Problem

AI agents are making consequential decisions in regulated industries — healthcare, finance, insurance, legal. Regulators demand explainability, auditability, and proof of compliance. Traditional logging is insufficient: logs can be tampered with, causal chains are invisible, and mapping agent behavior to specific regulatory controls requires manual effort that does not scale.

**agent-comply** solves this by providing a cryptographically verifiable audit trail with built-in decision reconstruction and automated regulatory compliance mapping.

## Key Features

- **Tamper-proof ledger** — Append-only event store with SHA-256 hash chaining and Merkle tree integrity verification. Any modification to historical events is cryptographically detectable.
- **Causal decision reconstruction** — Automatically builds a directed acyclic graph (DAG) of event dependencies (temporal, data-flow, tool-call edges) and extracts the full causal chain behind any agent output, with counterfactual what-if analysis.
- **Multi-framework compliance mapping** — Evaluates agent audit trails against 5 regulatory frameworks and 16 controls, producing structured reports with per-control evidence, findings, and recommendations.
- **Behavioral anomaly detection** — Builds per-agent baselines and scores sessions using z-score analysis across 6 detection rules (unusual session length, high error rate, unknown tools, excessive data access, slow calls, policy violations).
- **Zero-overhead capture SDK** — A single `@audit` decorator transparently captures inputs, outputs, errors, and timing for sync and async functions.
- **Evidence packaging** — One command exports a complete auditor-ready evidence package (events, compliance report, timeline, anomaly report, integrity proof).

## Architecture

```
                         ┌──────────────────────────────────────┐
                         │           Your AI Agent Code         │
                         │                                      │
                         │   @audit                             │
                         │   def search(query): ...             │
                         │                                      │
                         └──────────────┬───────────────────────┘
                                        │  captures events
                                        ▼
┌───────────────────────────────────────────────────────────────────┐
│                        agent-comply                               │
│                                                                   │
│  ┌─────────────┐   ┌──────────────┐   ┌───────────────────────┐  │
│  │   Capture    │──▶│   Ledger     │──▶│   Merkle Tree         │  │
│  │   SDK        │   │  (append-    │   │   (O(log n) proofs)   │  │
│  │  (@audit)    │   │   only,      │   │                       │  │
│  │              │   │   hash-      │   └───────────────────────┘  │
│  └─────────────┘   │   chained)   │                              │
│                     └──────┬───────┘                              │
│                            │                                      │
│            ┌───────────────┼───────────────┐                     │
│            ▼               ▼               ▼                     │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐             │
│  │ Reconstruct  │ │  Compliance  │ │   Anomaly    │             │
│  │  (DAG-based  │ │   Mapper     │ │  Detector    │             │
│  │   causal     │ │ (5 frameworks│ │ (z-score     │             │
│  │   chains,    │ │  16 controls)│ │  baselines)  │             │
│  │   counter-   │ │              │ │              │             │
│  │   factuals)  │ │              │ │              │             │
│  └──────┬───────┘ └──────┬───────┘ └──────┬───────┘             │
│         └────────────────┼────────────────┘                     │
│                          ▼                                       │
│                 ┌──────────────┐                                 │
│                 │   Reporter   │                                 │
│                 │  (text, JSON,│                                 │
│                 │   evidence   │                                 │
│                 │   packages)  │                                 │
│                 └──────────────┘                                 │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
                                │
                                ▼
                         ┌──────────────┐
                         │     CLI      │
                         │  agent-comply│
                         └──────────────┘
```

## Quick Start

### Installation

```bash
pip install agent-comply
```

Or install from source:

```bash
git clone https://github.com/mattyopon/agent-comply.git
cd agent-comply
pip install -e ".[dev]"
```

### Instrument Your Agent

```python
from agent_comply import audit, AuditContext

@audit
def search_database(query: str) -> list[str]:
    """Your existing agent tool — no changes needed inside."""
    return ["result_1", "result_2"]

@audit(event_type="tool_call", metadata={"tool": "web_search"})
async def web_search(url: str) -> str:
    """Works with async functions too."""
    return "<html>...</html>"

# Run within an audit context
with AuditContext(agent_id="claims-agent") as ctx:
    results = search_database("patient records")
    # Every call is now captured in the tamper-proof ledger

    # Export for verification
    ctx.ledger.export_jsonl("events.jsonl")
```

### Verify and Report

```bash
# Verify ledger integrity
agent-comply verify events.jsonl

# Generate a compliance report
agent-comply report events.jsonl --framework eu-ai-act

# Detect anomalies
agent-comply anomaly events.jsonl

# Reconstruct a decision chain
agent-comply reconstruct events.jsonl --event-id EVT-abc123def456

# Export a full evidence package
agent-comply evidence events.jsonl --output-dir evidence-package/
```

## CLI Reference

| Command       | Description                                         | Key Options                                      |
|---------------|-----------------------------------------------------|--------------------------------------------------|
| `verify`      | Verify ledger integrity (hash chain + Merkle tree)  | `EVENTS_FILE`                                    |
| `reconstruct` | Reconstruct the causal chain for a specific event   | `--event-id`, `--output`                         |
| `report`      | Generate a compliance report                        | `--framework` (eu-ai-act, soc2, hipaa, gdpr, dora, all), `--format` (text, json), `--output` |
| `anomaly`     | Detect behavioral anomalies in agent sessions       | `--output`                                       |
| `evidence`    | Export a full evidence package for auditors          | `--output-dir`                                   |
| `info`        | Show summary information about a ledger file        | `EVENTS_FILE`                                    |

## Supported Regulatory Frameworks

| Framework    | Controls | Focus                                              |
|--------------|----------|----------------------------------------------------|
| **EU AI Act**| 4        | Decision transparency (Art 13), human oversight (Art 14), automatic logging (Art 12), risk classification (Art 6) |
| **SOC 2**   | 3        | Audit trail completeness (CC7.2), integrity (CC7.3), retention (CC7.4) |
| **HIPAA**   | 3        | ePHI access audit (164.312b), integrity (164.312c1), entity authentication (164.312d) |
| **GDPR**    | 2        | Records of processing activities (Art 30), right to explanation (Art 22) |
| **DORA**    | 3        | ICT incident logging (Art 11), resilience testing (Art 25), third-party risk (Art 28) |

## SDK Usage

### The `@audit` Decorator

The decorator captures inputs, outputs, errors, and execution time with zero changes to your function logic:

```python
from agent_comply import audit, AuditContext, EventLedger

# Basic usage — captures everything automatically
@audit
def classify_risk(document: str) -> str:
    return "high"

# With metadata and event type customization
@audit(event_type="tool_call", metadata={"tool": "llm", "model": "gpt-4"})
def call_llm(prompt: str) -> str:
    return "LLM response"

# Async support
@audit
async def fetch_records(patient_id: str) -> dict:
    return {"id": patient_id, "records": [...]}
```

### Programmatic Compliance Checks

```python
from agent_comply import EventLedger, ComplianceMapper, DecisionReconstructor, AnomalyDetector

# Load and verify a ledger
ledger = EventLedger.import_jsonl("events.jsonl")
ok, errors = ledger.verify_all()
assert ok, f"Ledger tampered: {errors}"

# Compliance evaluation
mapper = ComplianceMapper(ledger)
report = mapper.evaluate(Framework.HIPAA)
print(f"HIPAA score: {report.score}%")

# Decision reconstruction
recon = DecisionReconstructor(ledger)
chain = recon.get_causal_chain("EVT-target123")
print(f"Causal depth: {chain.depth}, events in chain: {len(chain.chain)}")

# Counterfactual analysis
result = recon.counterfactual("EVT-abc123", "output", "alternative_value")
print(f"Impact score: {result.impact_score}, affected: {len(result.affected_events)} events")

# Anomaly detection
detector = AnomalyDetector(z_threshold=2.0)
detector.train(ledger)
session_reports = detector.analyse(ledger)
for sr in session_reports:
    if sr.risk_score > 0.5:
        print(f"HIGH RISK session {sr.session_id}: {sr.risk_score}")
```

## How It Works

### Hash Chain Integrity

Every event in the ledger stores a SHA-256 hash of its contents and a reference to the previous event's hash, forming an unbreakable chain. Modifying any historical event changes its hash, which invalidates every subsequent event in the chain.

### Merkle Tree Verification

A Merkle tree is maintained in parallel with the hash chain. This enables O(log n) membership proofs — you can verify that a specific event exists in the ledger and has not been modified without checking every other event.

### Causal DAG Reconstruction

The decision reconstructor analyzes ledger events and infers three types of causal edges:

1. **Temporal** — Sequential ordering of events
2. **Data-flow** — When one event's input references another event's output
3. **Tool-call** — Function-to-tool invocation within a session

This produces a DAG that can be traversed backward (to find root causes) or forward (for counterfactual impact analysis).

## Requirements

- Python 3.11+
- Dependencies: `pydantic>=2.0`, `rich>=13.0`, `typer>=0.9`, `httpx>=0.25`, `pyyaml>=6.0`

## License

BSL-1.1 (Business Source License 1.1)
