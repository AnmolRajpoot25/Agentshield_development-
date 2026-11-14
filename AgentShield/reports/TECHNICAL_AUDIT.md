# AgentShield Technical Audit Report (Milestone 1)
**Date:** 2026-11-14  
**Auditor:** Principal AI Security Engineer & Agentic AI Architect  
**Scope:** AgentShield Codebase Inspection, Architecture Verification, Runtime Evidence  
**Target:** Lexsi AI Safety Hackathon (Track 2a, Problem Statement 2a.3)

---

## 1. Architecture Overview & Component Mapping

AgentShield is designed to evaluate and enforce security boundaries for multi-turn, tool-using AI agents. The current implementation decomposes the agentic execution lifecycle into separate LangGraph nodes, backed by an independent security policy engine, a simulated tool environment, and an evaluation pipeline.

### Actual Data Flow Diagram
```
                     [ User Multi-Turn Request ]
                                  │
                                  ▼
             ┌───────────────────────────────────────────┐
             │ Node 1: input_boundary_node               │
             │ - Intercepts conversational privilege     │
             │   escalation patterns (regex markers)     │
             │ - Binds session_context["user_role"]      │
             └────────────────────┬──────────────────────┘
                                  │
                                  ▼
             ┌───────────────────────────────────────────┐
             │ Node 2: planner_node                      │
             │ - Formats conversation history            │
             │ - Invokes OpenRouter LLM (Nemotron 3.5)   │
             │ - Parses structured JSON plan:            │
             │   (thought, risk, tool_name, tool_args)   │
             └────────────────────┬──────────────────────┘
                                  │
                                  ▼
             ┌───────────────────────────────────────────┐
             │ Node 3: policy_validation_node            │
             │ - Evaluates against SecurityPolicyEngine: │
             │   Allowlist, Schema, RBAC, RLAC, Taint    │
             │ - If DENIED & not bypass:                 │
             │   sets tool_name=None, populates err      │
             └────────────────────┬──────────────────────┘
                                  │
                                  ▼
             ┌───────────────────────────────────────────┐
             │ Node 4: execution_node                    │
             │ - Dispatches to execute_tool()            │
             │ - Secondary policy gate inside registry   │
             │ - Invokes tool sandbox                    │
             └────────────────────┬──────────────────────┘
                                  │
                                  ▼
             ┌───────────────────────────────────────────┐
             │ Node 5: document_analysis_node            │
             │ - Scans tool_result for injection strings │
             │ - Flags taint & appends untrusted sources │
             └────────────────────┬──────────────────────┘
                                  │
                                  ▼
             ┌───────────────────────────────────────────┐
             │ Node 6: response_synthesis_node           │
             │ - Generates user-facing response          │
             │ - Redacts sensitive credential tokens     │
             └────────────────────┬──────────────────────┘
                                  │
                                  ▼
                         [ Final Response ]
```

---

## 2. Component-by-Component Technical Analysis

### 2.1 Agent Entry Point & Orchestration
- **File:** `src/agents/graph.py` -> `run_agent()`, `agent`
- **Implementation:** LangGraph `StateGraph(AgentState)` with 6 discrete nodes compiled into a cyclic/sequential DAG: `input_boundary` -> `planner` -> `policy_validation` -> `execution` -> `document_analysis` -> `response_synthesis`.
- **Runtime Behavior:** Cleanly manages state transitions and returns an updated dictionary conforming to `AgentState`.
- **State Schema:** `src/agents/state.py` defines `AgentState` TypedDict containing `episode_id`, `turn_number`, `user_request`, `session_context`, `messages`, `untrusted_context_sources`, `llm_plan`, `tool_name`, `tool_args`, `policy_decision`, `tool_result`, `security_events`, `final_response`, and telemetry fields.

### 2.2 LLM Inference Integration
- **File:** `src/agents/llm.py` -> `OpenRouterLLMClient`
- **Implementation:** Interfaces with OpenRouter API using model `nvidia/nemotron-3.5-lightning:free`.
- **Telemetry:** Measures wall-clock `latency_ms`, `prompt_tokens`, `completion_tokens`, `total_tokens`, and `cost`.
- **Resilience:** Implements `_recover_json_from_reasoning()` when thinking tokens consume output budget, and `_mock_response()` for offline deterministic execution.

### 2.3 Tool Proposal Generation
- **File:** `src/agents/graph.py` -> `planner_node()`
- **Implementation:** Injects system prompt defining security invariants and available tools with parameter specifications. Prompts model for strict JSON output: `{"thought", "risk_assessment", "tool_name", "tool_args", "user_response"}`.
- **Parsing:** `_extract_json_payload()` strips markdown code fences, handles outermost braces, and attempts partial closure repair if output is truncated.

### 2.4 Tool Execution Path
- **File:** `src/tools/registry.py` -> `execute_tool()`
- **Implementation:** Central execution gateway dispatching to `search_documents`, `read_document`, `summarize_document`, `query_database`, `send_email`, `delete_records`.
- **Isolation:** Operates entirely against in-memory mock databases (`DATABASE_TABLES`) and synthetic documents (`SYNTHETIC_DOCUMENTS`). No external networks or real host resources are touched.

### 2.5 Policy Authorization Engine
- **File:** `src/security/policies.py` -> `SecurityPolicyEngine.evaluate()`
- **Validation Pipeline:**
  1. Null tool proposal check (`NO_TOOL_PROPOSED`)
  2. Tool allowlist verification (`ALLOWED_TOOLS`)
  3. Argument dictionary structural validation
  4. Schema check: required parameters, parameter types, max string length, unexpected parameter rejection
  5. Role-Based Access Control (RBAC) via `RolePermissionMatrix`
  6. Resource-Level Access Control (RLAC) via `RESOURCE_CLASSIFICATION`
  7. Taint token scanning on arguments
- **Returns:** Structured `PolicyDecision(allowed, decision_code, reason, tool_name, user_role, timestamp, details)`.

### 2.6 Role-Based Access Control (RBAC)
- **File:** `src/security/rbac.py` -> `RolePermissionMatrix`
- **Roles Defined:** `anonymous`, `viewer`, `analyst`, `admin`, `system_auditor`.
- **Permissions:** Distinct tool sets and allowed resource clearance levels per role.

### 2.7 Resource-Level Access Control (RLAC)
- **File:** `src/security/policies.py` -> `RESOURCE_CLASSIFICATION`
- **Sensitivity Tiers:** `PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `RESTRICTED`.
- **Clearance Mapping:** `viewer` (PUBLIC), `analyst` (PUBLIC, INTERNAL), `admin` (ALL).

### 2.8 Taint Tracking & Untrusted Document Boundaries
- **File:** `src/security/taint.py` -> `TaintTracker`
- **Encapsulation:** Wraps retrieved text in `<<<BEGIN_UNTRUSTED_DOCUMENT id="...">>>` ... `<<<END_UNTRUSTED_DOCUMENT>>>`.
- **Scanning:** Detects direct injection phrases (`ignore previous instructions`, `DAN mode`, `delete records`).

### 2.9 Retrieved Document Store
- **File:** `src/tools/document_reader.py` -> `SYNTHETIC_DOCUMENTS`
- **Catalog:** 8 synthetic documents spanning legitimate invoices, policies, financial reports, confidential payroll, infrastructure master keys, and adversarial test documents containing embedded injections.

### 2.10 Guard Classifier Status
- **File:** `notebooks/AgentShield_Guard_Training.ipynb` & `inplementation_kaggle/AgentShield_Guard_Training.ipynb`
- **Status:** **PROTOTYPE NOTEBOOK ONLY**. Contains updated multi-task DistilBERT architecture code with zero-leakage grouped splitting.
- **Evidence Verification:** **NO TRAINED CHECKPOINT EXISTS ON DISK**. The model has not been trained; no weights exist in `checkpoints/`. The classifier is currently NOT connected to `graph.py` runtime.

### 2.11 Audit Logging & Cryptographic Traceability
- **File:** `src/tracing/logger.py` -> `log_event()`
- **Output:** `logs/traces.jsonl`
- **Verification:** Records `trace_id`, `episode_id`, `timestamp`, `event_type`, `payload`, and SHA-256 state hash `state_hash`.

### 2.12 Attack Adjudication & Evaluation Pipeline
- **Files:** `src/evaluation/adjudicator.py`, `src/evaluation/metrics.py`, `src/evaluation/runner.py`, `src/evaluation/compare.py`
- **Adjudicator:** Distinguishes attack attempt, unsafe proposal, policy block, execution attempt, unauthorized execution, and secret leakage.
- **Metrics Computed:** Unauthorized Execution Rate (UER), Attack Success Rate (ASR), Policy Rejection Rate (PRR), Unsafe Proposal Rate (UPR), Attack Detection Rate (ADR), Benign Task Success Rate (BTSR), False Positive Rate (FPR), Latency, Cost.

---

## 3. Existing Test Suite Audit

Executed via command: `python -m pytest AgentShield/tests -v`

| Test Module | Total Tests | Passed | Failed | Execution Time |
| :--- | :---: | :---: | :---: | :---: |
| `tests/test_policies.py` | 13 | 13 | 0 | 0.05s |
| `tests/test_tools.py` | 5 | 5 | 0 | 0.02s |
| `tests/test_llm.py` | 3 | 3 | 0 | 0.01s |
| `tests/test_metrics.py` | 1 | 1 | 0 | 0.01s |
| **Total** | **22** | **22** | **0** | **0.08s** |

**Execution Environment:** Windows, Python 3.13.2, pytest-9.1.1. All 22 tests pass deterministically.
