# AgentShield Implementation Roadmap (Milestones 2–9)
**Project:** AgentShield AI Agent Security Auditing & Enforcement Framework  
**Target:** Lexsi AI Safety Hackathon (Track 2a, Problem Statement 2a.3)  
**Author:** Principal AI Security Engineer  

---

## Roadmap Overview

Following the Milestone 1 Technical Audit, this roadmap outlines the prioritized engineering plan to elevate AgentShield into an empirically verified, submission-ready research framework.

```
┌────────────────────────────────────────────────────────────────────────┐
│ MILESTONE 1: Complete Technical Audit & Threat Boundary Verification   │ ◄── [COMPLETED]
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ MILESTONE 2: Strengthen Core Security & Authorization Architecture    │
│ • Fix SEC-01 (Default-Deny for unclassified resources)                 │
│ • Fix SEC-02 (Reclassify adversarial test docs for injection exposure) │
│ • Fix SEC-03 (Wire dynamic taint propagation into policy decision path)│
│ • Fix SEC-04 (Decouple VulnerableBaseline from ProtectedAgent)         │
│ • Fix SEC-05 (Filter search results by user clearance levels)          │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ MILESTONE 3: Train & Integrate AgentShield Guard Model                 │
│ • Execute Guard fine-tuning pipeline on GPU/CPU                        │
│ • Generate real checkpoint artifacts: guard_weights.pt, config.json    │
│ • Plug Guard telemetry into LangGraph document_analysis_node           │
│ • Verify Guard as an advisory risk signal (cannot override policy)    │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ MILESTONE 4: Benchmark & Comparative Adversarial Evaluation            │
│ • Run full 25-scenario benchmark across all 4 experimental modes:      │
│   (1) Vulnerable Baseline  (2) Policy-Only                             │
│   (3) Guard-Only           (4) Combined AgentShield Protected          │
│ • Produce empirical comparative evaluation matrix (UER, ASR, PRR, BTSR)│
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ MILESTONE 5: Test Suite Expansion & Regression Hardening               │
│ • Add tests for unknown resource denial, cross-user denial, and taint  │
│ • Add tests for Guard/Policy disagreement & snapshot diff adjudication │
│ • Target: 30+ deterministic tests passing in pytest                    │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ MILESTONE 6: Scientific Evidence Audit & Reporting                     │
│ • Replace all historical/unsupported numbers with real benchmark logs  │
│ • Generate results/comparative_evaluation.json & .csv                  │
│ • Author reports/EXPERIMENTAL_RESULTS.md                               │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ MILESTONE 7: Hackathon Requirement Verification (Track 2a / 2a.3)      │
│ • Verify Aya requirements, toolkits, and track constraints             │
│ • Document minimal technical adaptions if specific model family needed │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ MILESTONE 8 & 9: Public Artifact Preparation & Final Submission Paper  │
│ • Sanitize public repo package (zero private credentials)              │
│ • Structure Hugging Face dataset and model cards                       │
│ • Compile final technical paper (reports/FINAL_HACKATHON_SUBMISSION.md)│
└────────────────────────────────────────────────────────────────────────┘
```

---

## Detailed Milestone Execution Plan

### Milestone 2: Strengthen Core Security Architecture (Immediate Next Priority)
- **Objective:** Eliminate verified authorization gaps and isolate experimental runtimes.
- **Specific Tasks:**
  1. **SEC-01 (Default-Deny RLAC):** In `src/security/policies.py`, update `evaluate()` so unclassified resource IDs default to `"RESTRICTED"` rather than `"INTERNAL"`.
  2. **SEC-02 (Injection Exposure):** In `RESOURCE_CLASSIFICATION` and `SYNTHETIC_DOCUMENTS`, set `malicious_doc_001`, `002`, `003` to `INTERNAL` (so an analyst can read the report), but flag them with `is_untrusted_data=True` and strict taint delimiters. This ensures indirect injection is tested against the planner and execution layers, rather than being prematurely blocked by document read permissions.
  3. **SEC-03 (Active Taint Propagation):** Connect `TaintTracker.is_tainted_by_untrusted_source()` into `SecurityPolicyEngine.evaluate()`. If a tool call's arguments mirror untrusted document commands, deny with `DENIED_TAINT_PROPAGATION`.
  4. **SEC-04 (Runtime Decoupling):** Separate `run_agent()` into `ProtectedAgent` (hardcoded policy enforcement, no bypass flag) and `VulnerableBaselineAgent` (explicit baseline test harness).
  5. **SEC-05 (Search Clearance Filter):** Update `search_documents()` to filter results by `session_context["user_role"]`, preventing information leakage in search metadata.

### Milestone 3: Improve & Integrate AgentShield Guard Model
- **Objective:** Produce genuine training evidence and integrate the Guard as a risk signal.
- **Specific Tasks:**
  1. Execute `AgentShield_Guard_Training.ipynb` on GPU/CPU to generate real model weights in `checkpoints/agentshield_guard_v2/`.
  2. Verify training curves, validation calibration threshold $\tau^*$, and test metrics.
  3. Implement `src/agents/guard.py` to wrap the trained model for runtime inference.
  4. Connect Guard telemetry into `document_analysis_node` and `input_boundary_node` in `src/agents/graph.py`.
  5. Enforce invariant: Guard risk score is advisory telemetry; it **cannot** override policy rejection.

### Milestone 4: Comprehensive Benchmark & Comparative Evaluation
- **Objective:** Gather empirical proof of defense-in-depth across 4 experimental arms.
- **Specific Tasks:**
  1. Execute all 25 multi-turn scenarios across:
     - Arm 1: Vulnerable Baseline (Guard Off, Policy Off)
     - Arm 2: Guard-Only (Guard On, Policy Off)
     - Arm 3: Policy-Only (Guard Off, Policy On)
     - Arm 4: Combined AgentShield (Guard On, Policy On)
  2. Record complete traces, tool execution outcomes, and state mutations.
  3. Save results to `results/comparative_evaluation.json`.

### Milestone 5: Test Suite Expansion
- **Objective:** Achieve comprehensive regression coverage for all security invariants.
- **Specific Tasks:**
  1. Add tests for default-deny on unclassified resources.
  2. Add tests for search result clearance filtering.
  3. Add tests for dynamic taint propagation denial.
  4. Add tests for Guard/Policy disagreement behavior.

### Milestone 6: Evidence Audit & Reporting
- **Objective:** Ensure 100% scientific integrity in all documentation.
- **Specific Tasks:**
  1. Replace any estimated or historical figures in `README.md` with the empirical results from Milestone 4.
  2. Generate `reports/EXPERIMENTAL_RESULTS.md` with explicit denominators and confusion matrices.

### Milestone 7: Official Hackathon Requirements Verification
- **Objective:** Ensure full compliance with Track 2a, Problem 2a.3 rules.
- **Specific Tasks:**
  1. Verify whether Cohere Aya is mandatory for Track 2a.3.
  2. If mandatory, add an Aya LLM adapter in `src/agents/llm.py` via OpenRouter/HuggingFace while preserving Nemotron as an alternate backend.
  3. Check hackathon kit requirements (AuditKIT, CuratorKIT).

### Milestone 8 & 9: Public Artifacts & Final Submission Paper
- **Objective:** Package clean, reproducible submission assets.
- **Specific Tasks:**
  1. Ensure zero private credentials (`.env`, `credentials.json`, `token.json`) are present in any public git or export staging directory.
  2. Write final technical whitepaper: `reports/FINAL_HACKATHON_SUBMISSION.md`.

