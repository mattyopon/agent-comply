# PROVISIONAL PATENT APPLICATION

## Title

System and Method for Tamper-Proof Compliance Auditing and Causal Decision Reconstruction of AI Agent Workflows

## Inventor

Yutaro Maeda

## Filing Date

[TO BE DETERMINED]

---

## ABSTRACT

A system and method for creating tamper-proof audit trails of artificial intelligence agent workflows and reconstructing the causal decision chains that led to specific agent outputs. The system employs an append-only event ledger secured by SHA-256 hash chaining and parallel Merkle tree verification to ensure cryptographic integrity of all recorded events. A directed acyclic graph (DAG) construction engine analyzes recorded events to infer temporal, data-flow, and tool-call causal relationships, enabling backward traversal to reconstruct the full decision chain behind any agent output and forward traversal for counterfactual impact analysis. An automated regulatory compliance mapper evaluates the audit trail against multiple regulatory frameworks including EU AI Act, SOC 2, HIPAA, GDPR, and DORA, mapping agent behavior to specific regulatory controls and producing structured compliance reports with per-control evidence, findings, and recommendations. A behavioral anomaly detection subsystem builds statistical baselines of agent behavior and detects deviations using z-score analysis across multiple behavioral dimensions including session length, error rates, tool usage patterns, data access frequency, execution timing, and policy violations.

---

## FIELD OF THE INVENTION

The present invention relates generally to systems and methods for auditing and monitoring artificial intelligence agent workflows. More specifically, the invention relates to tamper-proof event recording, causal decision reconstruction, automated regulatory compliance mapping, and behavioral anomaly detection for AI agent systems operating in regulated industries.

## BACKGROUND OF THE INVENTION

### The Rise of AI Agents in Regulated Industries

Artificial intelligence agents — autonomous software systems that make decisions and take actions on behalf of users — are increasingly deployed in regulated industries including healthcare, financial services, insurance, and legal services. These agents make consequential decisions such as claims processing, patient triage, risk assessment, and compliance monitoring.

### Regulatory Requirements

Regulatory frameworks including the European Union AI Act, SOC 2 Type II, HIPAA, GDPR, and DORA impose requirements for transparency, explainability, audit trail integrity, and human oversight of automated decision-making systems. Organizations deploying AI agents must demonstrate compliance with these requirements or face significant penalties.

### Limitations of Existing Approaches

Existing approaches to AI agent auditing suffer from several critical limitations:

1. **Mutable logs**: Traditional logging systems store events in databases or files that can be modified or deleted, providing no cryptographic guarantee of integrity. An auditor cannot verify that the log accurately represents what occurred.

2. **Lack of causal reconstruction**: Standard audit logs record individual events in isolation. They do not capture or enable reconstruction of the causal relationships between events — why a particular decision was made, which prior events influenced it, and what would have happened if an earlier event had been different.

3. **Manual compliance mapping**: Mapping agent behavior to specific regulatory controls is a manual, labor-intensive process that requires specialized knowledge of each regulatory framework. This process does not scale with the volume and velocity of AI agent operations.

4. **Reactive anomaly detection**: Existing monitoring tools detect infrastructure-level anomalies (CPU, memory, latency) but do not build behavioral baselines of agent decision-making patterns or detect anomalies in agent behavior that may indicate compliance violations, security breaches, or system degradation.

5. **Blockchain overhead**: Distributed ledger (blockchain) approaches provide tamper evidence but introduce unnecessary consensus overhead, latency, and infrastructure complexity for single-organization audit trails where a centralized append-only structure is sufficient.

### Need for the Present Invention

There is a need for a system that provides cryptographic tamper evidence for AI agent audit trails without blockchain overhead, reconstructs causal decision chains from event streams, automates compliance mapping across multiple regulatory frameworks, and detects behavioral anomalies in agent operations — all integrated into a unified platform with minimal instrumentation overhead.

## SUMMARY OF THE INVENTION

The present invention provides a system and method for tamper-proof compliance auditing and causal decision reconstruction of AI agent workflows comprising:

1. An append-only event ledger that secures recorded events using a SHA-256 hash chain linking each event to its predecessor and a parallel Merkle tree enabling O(log n) integrity proofs for any subset of events.

2. A causal decision reconstruction engine that constructs a directed acyclic graph (DAG) from ledger events by inferring temporal, data-flow, and tool-call edges, enabling backward traversal to reconstruct the full causal chain behind any agent output and forward traversal for counterfactual impact analysis.

3. An automated regulatory compliance mapper that evaluates the audit trail against multiple regulatory frameworks (EU AI Act, SOC 2, HIPAA, GDPR, DORA) by executing framework-specific control checks against ledger events and producing structured reports with per-control status, evidence, findings, and recommendations.

4. A behavioral anomaly detection subsystem that builds per-agent statistical baselines from historical event data and scores individual sessions against those baselines using z-score analysis across multiple behavioral dimensions.

5. A capture SDK providing a decorator-based instrumentation mechanism that transparently records function inputs, outputs, errors, and timing metadata for both synchronous and asynchronous functions without modifying the instrumented function's logic.

---

## DETAILED DESCRIPTION OF THE INVENTION

### Overview

The system comprises five principal subsystems operating on a shared data model:

1. **Capture SDK** — Instruments agent function calls to produce structured events
2. **Event Ledger** — Stores events in a tamper-proof, append-only structure
3. **Decision Reconstructor** — Builds and queries causal graphs from event streams
4. **Compliance Mapper** — Evaluates events against regulatory control libraries
5. **Anomaly Detector** — Identifies behavioral deviations from agent baselines

### 1. Append-Only Ledger with SHA-256 Hash Chain

#### 1.1 Event Data Model

Each event in the ledger is represented as an immutable record containing:

- A unique event identifier (e.g., "EVT-{random_hex}")
- A monotonically increasing sequence number
- An ISO 8601 timestamp in UTC
- A payload dictionary containing the event data (function name, inputs, outputs, errors, timing, metadata)
- A payload hash: the SHA-256 digest of the canonicalized (sorted-key) JSON serialization of the payload
- A previous hash: the event hash of the immediately preceding event in the ledger (or a genesis hash for the first event)
- An event hash: the SHA-256 digest of the canonicalized JSON serialization of (event_id, sequence, timestamp, payload_hash, previous_hash)

#### 1.2 Hash Chain Construction

Events are appended sequentially. Each new event's `previous_hash` field is set to the `event_hash` of the most recent existing event (or a deterministic genesis hash, defined as SHA-256("GENESIS"), for the first event). The `event_hash` is then computed from the event's immutable fields including the `previous_hash`, creating a cryptographic chain where any modification to a historical event invalidates all subsequent events.

**Verification procedure**: The system walks the chain from event 0 to event N, recomputing each event's hash from its fields and verifying that: (a) the recomputed hash matches the stored event hash, (b) the payload hash matches the SHA-256 digest of the stored payload, and (c) the previous hash matches the event hash of the preceding event. Any mismatch indicates tampering.

#### 1.3 Genesis Hash

The first event in the ledger uses a deterministic genesis hash (SHA-256 of the string "GENESIS") as its previous_hash, anchoring the chain to a known, reproducible starting point.

### 2. Merkle Tree Integrity Verification with O(log n) Proofs

#### 2.1 Tree Structure

A Merkle tree is maintained in parallel with the hash chain. The tree uses a flat array representation where index 1 is the root and leaf nodes occupy indices [n, 2n-1] where n is the next power of 2 greater than or equal to the number of leaves. Empty leaf positions are filled with the SHA-256 hash of an empty string. Internal nodes are computed as SHA-256(left_child || right_child).

#### 2.2 Incremental Maintenance

Each new event appended to the ledger also adds a new leaf to the Merkle tree (the leaf value is the event's event_hash). The tree is rebuilt from the leaf level upward, maintaining correctness with O(1) amortized insertion cost.

#### 2.3 Proof Generation

For any leaf at index i, the system generates an audit proof consisting of a sequence of (sibling_hash, side) pairs, where side indicates whether the sibling is to the left or right. This proof has O(log n) elements.

#### 2.4 Proof Verification

Given a leaf hash, its index, and a proof, verification proceeds by iteratively combining the current hash with each sibling hash (respecting the side indicator) until the root is reached. The computed root is compared against the stored Merkle root. Agreement proves the leaf's membership and integrity.

#### 2.5 Combined Verification

The system provides a combined verification mode that performs both full hash chain verification and per-event Merkle proof verification, producing a list of any detected integrity violations.

### 3. Causal Chain Reconstruction via DAG

#### 3.1 Dependency Graph Construction

Given a set of ledger events, the system constructs a directed acyclic graph (DAG) by inferring three types of causal edges:

**3.1.1 Temporal Edges**: Each event is connected to the immediately preceding event in the sequence, establishing the temporal ordering of the workflow.

**3.1.2 Data-Flow Edges**: If the input of event B contains a value that matches the output of event A (detected by string-prefix matching of serialized values), a data-flow edge is created from A to B. Additionally, if an event contains an explicit parent_event_id reference in its payload, a decision edge is created from the parent to the child.

**3.1.3 Tool-Call Edges**: Within each session (identified by session_id), if a "function_call" event is followed by a "tool_call" event, a tool-call edge is created from the function call to the tool call, representing the invocation relationship.

The graph maintains both forward (adjacency) and reverse (predecessor) index structures for efficient traversal in both directions.

#### 3.2 Backward Causal Chain Extraction

Given a target event, the system performs breadth-first search (BFS) backward through the reverse graph to collect all ancestor events. The result is a CausalChain object containing the ordered sequence of events from root cause to target event, all connecting edges, and the chain depth.

#### 3.3 Decision Tree Construction

The system can build a nested decision tree structure rooted at any event, recursively expanding all descendants through the forward adjacency graph. Each node in the tree carries summarized input/output data for visualization purposes.

#### 3.4 Counterfactual Analysis Engine

Given an event ID, a field to modify, and a hypothetical new value, the system estimates the downstream impact by performing BFS forward from the modified event through the adjacency graph to identify all affected descendant events. The impact score is computed as the ratio of affected events to total events in the graph, providing a quantitative measure of how critical a particular decision point was to subsequent outcomes.

An optional user-supplied propagation function can override the default BFS forward propagation with domain-specific impact logic.

### 4. Multi-Framework Regulatory Compliance Mapping

#### 4.1 Framework and Control Model

The system defines a registry of regulatory frameworks, each containing a set of controls. Each control consists of:

- A control identifier (e.g., "EU-AI-13.1", "HIPAA-164.312b")
- A human-readable control name
- A check function that evaluates the ledger events against the control's requirements
- The check function returns a structured result with: status (pass/fail/partial/not-applicable), evidence (supporting data), findings (identified issues), and recommendations (remediation guidance)

#### 4.2 Supported Frameworks and Controls

**4.2.1 EU AI Act (4 controls)**:
- EU-AI-13.1 Decision Transparency (Art 13): Verifies all agent decisions are logged with complete inputs and outputs.
- EU-AI-14.1 Human Oversight (Art 14): Checks for evidence of human-in-the-loop events (human_review, human_override, human_approval).
- EU-AI-12.1 Automatic Logging with Integrity (Art 12): Verifies the hash chain integrity of the audit log.
- EU-AI-6.1 Risk Classification (Art 6): Checks for risk_level metadata on events for high-risk AI classification.

**4.2.2 SOC 2 Type II (3 controls)**:
- SOC2-CC7.2 Audit Trail Completeness: Verifies all events have timestamps and unique identifiers.
- SOC2-CC7.3 Audit Trail Integrity: Performs full chain and Merkle tree verification.
- SOC2-CC7.4 Audit Retention: Verifies events span a reasonable retention period.

**4.2.3 HIPAA (3 controls)**:
- HIPAA-164.312b Audit Controls (ePHI Access): Verifies access events are logged with agent identifiers.
- HIPAA-164.312c1 Integrity Controls: Verifies hash chain integrity for ePHI protection.
- HIPAA-164.312d Entity Authentication: Verifies unique agent identities are present in the audit trail.

**4.2.4 GDPR (2 controls)**:
- GDPR-30.1 Records of Processing Activities (Art 30): Checks for processing purpose metadata on events.
- GDPR-22.1 Right to Explanation (Art 22): Verifies that a sufficient percentage (90%+) of decisions have complete input/output data to support explainability.

**4.2.5 DORA (3 controls)**:
- DORA-11.1 ICT Incident Logging (Art 11): Verifies error events are fully logged with timestamps and identifiers.
- DORA-25.1 Operational Resilience Testing (Art 25): Checks for evidence of anomaly detection activity.
- DORA-28.1 Third-Party ICT Risk Monitoring (Art 28): Monitors tool call events and identifies unique third-party tool integrations.

**Total: 5 frameworks, 15 controls.**

#### 4.3 Scoring Algorithm

For each framework, the compliance score is computed as:

```
score = (passed + partial * 0.5) / applicable * 100
```

where `applicable = total_controls - not_applicable`. This produces a 0-100 percentage score reflecting the degree of compliance.

#### 4.4 Report Generation

The system generates structured compliance reports containing: an executive summary with average scores and failed control counts, per-framework detail sections with control-level status, and actionable recommendations for each failed or partially-met control.

### 5. Behavioral Anomaly Detection with Z-Score Baselines

#### 5.1 Baseline Construction

The anomaly detector builds per-agent statistical baselines from historical ledger data. For each unique agent identity, the following metrics are tracked across sessions:

- Event counts per session (mean, standard deviation)
- Tool usage frequency distribution
- Error rates per session
- Call durations in milliseconds (mean, standard deviation)
- Unique tools per session

#### 5.2 Detection Rules

The system applies six detection rules to each session:

**5.2.1 Unusual Session Length**: Computes the z-score of the session's event count against the agent's baseline. If |z| exceeds the configurable threshold (default: 2.0), an alert is raised. Severity is HIGH for |z| > 3.0, MEDIUM otherwise.

**5.2.2 High Error Rate**: Computes the session's error rate and compares against a dynamic threshold derived from the agent's baseline mean error rate plus a margin. Alerts are raised for rates exceeding 20% (or baseline + 15%).

**5.2.3 Unknown Tool Usage**: Compares tools invoked in the session against the set of tools observed in the agent's baseline. Any tool not previously seen triggers a MEDIUM severity alert.

**5.2.4 Excessive Data Access**: Flags sessions with more than 20 data access events as HIGH severity, with score proportional to the count (saturating at 50 events).

**5.2.5 Abnormally Slow Calls**: For individual function calls, computes the z-score of execution duration against the agent's baseline. Alerts are raised when z exceeds 1.5 times the threshold.

**5.2.6 Policy Violations**: Detects events explicitly flagged with policy_violation metadata. These are always CRITICAL severity with a maximum score of 1.0.

#### 5.3 Risk Aggregation

Individual alert scores are aggregated into a session-level risk score using severity-weighted summation followed by sigmoid-like saturation:

```
weighted = sum(alert.score * weight[alert.severity])
risk = 1.0 - exp(-weighted)
```

Severity weights are: LOW=0.1, MEDIUM=0.3, HIGH=0.6, CRITICAL=1.0. The exponential saturation ensures the risk score approaches but never exceeds 1.0 regardless of the number of alerts.

### 6. Capture SDK

#### 6.1 Decorator-Based Instrumentation

The system provides a decorator (`@audit`) that wraps both synchronous and asynchronous functions. The decorator:

1. Introspects the function signature to capture named arguments
2. Records the start time with nanosecond precision
3. Executes the original function without modification
4. Captures the return value (or error) and elapsed time
5. Creates a structured event record and appends it to the active audit context's ledger

#### 6.2 Context Management

An `AuditContext` object manages an auditing session using Python context variables (contextvars), ensuring thread-safe and async-safe operation. Multiple audit contexts can be active simultaneously in different threads or coroutines without interference. The context carries the agent identity, session identity, and a reference to the backing event ledger.

#### 6.3 Safe Serialization

All captured values (inputs, outputs) are recursively serialized to JSON-safe types with configurable depth limits to prevent unbounded recursion or memory consumption. Pydantic model instances are serialized using their `model_dump()` method.

### 7. Evidence Package Generation

The system can export a complete evidence package to a directory, containing:

- `events.jsonl`: The raw ledger in newline-delimited JSON format
- `compliance.json`: Full multi-framework compliance report
- `timeline.txt`: Chronological event timeline with status indicators
- `anomaly.json`: Behavioral anomaly detection report
- `integrity.json`: Chain and Merkle verification results with the current Merkle root

This package provides all materials an external auditor needs to independently verify the integrity and compliance of the AI agent's operations.

---

## CLAIMS

### Independent Claim 1: Tamper-Proof Event Ledger

**1.** A computer-implemented method for creating and verifying a tamper-proof audit trail of artificial intelligence agent operations, comprising:

(a) receiving, at a computing device, a stream of events generated by one or more AI agent functions, each event comprising at minimum a unique identifier, a timestamp, and a payload containing function inputs, outputs, and execution metadata;

(b) for each received event, computing a payload hash as the SHA-256 digest of the canonicalized JSON serialization of the event payload;

(c) for each received event, setting a previous hash field to the event hash of the immediately preceding event in the ledger, or to a deterministic genesis hash for the first event;

(d) computing an event hash as the SHA-256 digest of the canonicalized JSON serialization of the event's immutable fields including the event identifier, sequence number, timestamp, payload hash, and previous hash, thereby forming a hash chain;

(e) adding the event hash as a leaf node in a Merkle tree maintained in parallel with the hash chain, where internal nodes of the Merkle tree are computed as SHA-256 digests of the concatenation of their child nodes;

(f) providing a verification procedure that, given the ledger, walks the hash chain from the first event to the last event, recomputing each event hash and verifying: (i) the recomputed hash matches the stored event hash, (ii) the payload hash matches the SHA-256 digest of the stored payload, and (iii) the previous hash matches the event hash of the preceding event; and

(g) providing Merkle proof generation that, for any event at index i, produces an O(log n) sequence of sibling hashes sufficient to recompute the Merkle root, and a proof verification procedure that confirms the recomputed root matches the stored root.

### Dependent Claims on Claim 1

**2.** The method of claim 1, wherein the genesis hash is computed as the SHA-256 digest of a predetermined constant string, providing a deterministic and reproducible anchor for the hash chain.

**3.** The method of claim 1, wherein the Merkle tree uses a flat array representation with the root at index 1 and leaf nodes at indices [n, 2n-1] where n is the smallest power of 2 greater than or equal to the number of events, and empty leaf positions are filled with the SHA-256 hash of an empty string.

**4.** The method of claim 1, further comprising serializing the ledger to a newline-delimited JSON format and deserializing a ledger from said format with automatic integrity re-verification upon import.

**5.** The method of claim 1, wherein the event payload includes a duration measurement captured with nanosecond-precision timing of the instrumented function's execution.

**6.** The method of claim 1, further comprising a combined verification mode that performs both the hash chain verification of step (f) and the Merkle proof verification of step (g) for every event in the ledger, returning a consolidated list of all detected integrity violations.

### Independent Claim 2: Causal Decision Reconstruction

**7.** A computer-implemented method for reconstructing causal decision chains from an audit trail of AI agent operations, comprising:

(a) receiving a set of events from a tamper-proof event ledger, each event comprising a unique identifier, a timestamp, a payload with function name, inputs, outputs, and session identifier;

(b) constructing a directed acyclic graph (DAG) by inferring causal edges of three types: (i) temporal edges connecting each event to the immediately preceding event in sequence, (ii) data-flow edges connecting events where the output of a first event matches an input value of a second event, detected by string-prefix comparison of serialized values, and (iii) tool-call edges connecting function-call events to subsequent tool-call events within the same session;

(c) maintaining both forward adjacency and reverse predecessor index structures for the DAG;

(d) given a target event identifier, performing breadth-first search backward through the reverse index to collect all ancestor events and connecting edges, producing a causal chain ordered from root cause to target event; and

(e) computing a chain depth as the number of events in the causal chain minus one.

### Dependent Claims on Claim 2

**8.** The method of claim 7, further comprising constructing a nested decision tree structure rooted at a specified event by recursively expanding all descendant events through the forward adjacency structure, with cycle detection to prevent infinite recursion, each node carrying summarized input and output data.

**9.** The method of claim 7, further comprising counterfactual analysis wherein, given an event identifier, a field name, and a hypothetical new value, the method performs breadth-first search forward through the adjacency structure from the specified event to identify all descendant events that would be affected, and computes an impact score as the ratio of affected events to total events in the graph.

**10.** The method of claim 9, wherein the counterfactual analysis accepts an optional user-supplied propagation function that overrides the default BFS forward propagation with domain-specific impact logic.

**11.** The method of claim 7, wherein the data-flow edge inference uses a truncated string representation of serialized values (limited to 256 characters) for comparison to bound computational cost while maintaining sufficient specificity.

**12.** The method of claim 7, further comprising generating a structured context report for any event that includes the event's parent events, child events, incoming edges, and outgoing edges, providing a complete local view of the event's position in the causal graph.

### Independent Claim 3: Automated Regulatory Compliance Mapping

**13.** A computer-implemented method for automated regulatory compliance evaluation of AI agent audit trails, comprising:

(a) receiving a set of events from a tamper-proof event ledger generated by AI agent operations;

(b) maintaining a registry of regulatory frameworks, each framework comprising a set of controls, each control comprising a control identifier, a control name, and an executable check function;

(c) for a specified framework, executing each control's check function against the set of events, where each check function evaluates the events according to the control's specific requirements and returns a structured result comprising: (i) a status of pass, fail, partial, or not-applicable, (ii) evidence items supporting the status determination, (iii) findings describing identified issues, and (iv) recommendations for remediation;

(d) computing a framework compliance score as (passed_controls + partial_controls * 0.5) / applicable_controls * 100, where applicable controls excludes not-applicable controls; and

(e) generating a structured compliance report comprising an executive summary with aggregate metrics and per-framework sections with control-level detail.

### Dependent Claims on Claim 3

**14.** The method of claim 13, wherein the registry of regulatory frameworks includes the EU AI Act, SOC 2 Type II, HIPAA, GDPR, and DORA, with a combined total of at least 15 controls across said frameworks.

**15.** The method of claim 13, further comprising an evaluate-all mode that iterates over every framework in the registry and produces a combined report with cross-framework aggregate metrics.

**16.** The method of claim 13, further comprising a behavioral anomaly detection subsystem that builds per-agent statistical baselines from historical event data and evaluates sessions against said baselines using z-score analysis, wherein the anomaly detection subsystem applies at least: (i) a session length check comparing event count against the agent's mean and standard deviation, (ii) an error rate check against a dynamic threshold, (iii) an unknown tool usage check against the agent's observed tool set, and (iv) a policy violation check for events explicitly flagged with violation metadata.

**17.** The method of claim 16, wherein session-level risk scores are computed by severity-weighted aggregation of individual alert scores followed by exponential saturation, using the formula: risk = 1.0 - exp(-sum(alert_score * severity_weight)), where severity weights are configurable per severity level.

---

## PRIOR ART DIFFERENTIATION

### vs. Blockchain-Based Audit Systems

Blockchain audit systems (e.g., Hyperledger-based audit trails) provide tamper evidence through distributed consensus. However, they introduce significant overhead:

1. **Consensus latency**: Blockchain systems require multi-node consensus for each write, adding latency measured in seconds. The present invention uses a single-node append-only structure with sub-millisecond append latency.

2. **Infrastructure complexity**: Blockchain deployments require multiple nodes, network configuration, and consensus protocol management. The present invention operates as a library within the application process with zero external infrastructure.

3. **No causal reconstruction**: Blockchain audit systems record events but do not construct causal DAGs or support backward chain extraction or counterfactual analysis. The present invention provides integrated causal graph construction with three edge types and bidirectional traversal.

4. **No regulatory mapping**: Blockchain systems provide tamper evidence but do not automatically map recorded events to regulatory framework controls. The present invention includes a pluggable control registry covering 5 frameworks and 15+ controls.

### vs. Traditional Compliance and Audit Tools

Traditional compliance tools (e.g., GRC platforms, SIEM systems) focus on infrastructure monitoring and manual compliance checklist management:

1. **No cryptographic integrity**: Traditional audit logs are stored in mutable databases. The present invention provides SHA-256 hash chain and Merkle tree verification, making any tampering cryptographically detectable.

2. **No AI agent awareness**: Traditional tools monitor system-level events (network, access, configuration changes). The present invention is purpose-built for AI agent workflows, capturing function-level inputs, outputs, decisions, and tool invocations.

3. **No automated control evaluation**: Traditional tools require human analysts to evaluate evidence against control requirements. The present invention automatically executes control check functions against the event stream and produces per-control pass/fail determinations with evidence.

4. **No behavioral baselines**: Traditional anomaly detection operates on infrastructure metrics. The present invention builds agent-specific behavioral baselines (event volume, tool usage patterns, error rates, execution timing) and detects deviations at the decision-making level.

### vs. Application Performance Monitoring (APM)

APM tools (e.g., Datadog, New Relic) provide distributed tracing and performance monitoring:

1. **Mutable data stores**: APM data is stored in time-series databases without cryptographic integrity guarantees. The present invention's hash chain and Merkle tree ensure any modification is detectable.

2. **Performance focus, not compliance focus**: APM tools optimize for latency, throughput, and error rate monitoring. The present invention is designed for regulatory compliance with framework-specific control libraries.

3. **No counterfactual analysis**: APM traces show what happened but do not support "what if" analysis. The present invention's counterfactual engine quantifies the downstream impact of hypothetical changes to any event.

### Novel Combination

The present invention is differentiated by the combination of: (1) tamper-proof ledger with dual integrity mechanisms (hash chain + Merkle tree), (2) causal DAG construction with three inferred edge types and bidirectional traversal, (3) counterfactual impact analysis, (4) multi-framework automated compliance mapping with a pluggable control registry, and (5) agent-behavioral anomaly detection with z-score baselines — all integrated into a single system with a zero-modification decorator-based capture SDK. No prior art combines all five capabilities for AI agent workflows.

---

## DRAWINGS

[To be provided in the formal filing. Drawings will include:]

1. FIG. 1 — System architecture block diagram showing the five subsystems and data flow
2. FIG. 2 — Hash chain construction and verification flow
3. FIG. 3 — Merkle tree structure with proof generation and verification paths
4. FIG. 4 — Causal DAG construction showing temporal, data-flow, and tool-call edges
5. FIG. 5 — Backward causal chain extraction via BFS
6. FIG. 6 — Forward counterfactual impact propagation
7. FIG. 7 — Regulatory compliance mapping flow from events to framework scores
8. FIG. 8 — Anomaly detection pipeline from baseline construction to risk scoring
