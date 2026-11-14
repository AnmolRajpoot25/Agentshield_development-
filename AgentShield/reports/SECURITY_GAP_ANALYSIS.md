# AgentShield Security Gap Analysis & Threat Boundary Verification (Milestone 1)
**Date:** 2026-11-14  
**Auditor:** Principal AI Security Engineer  
**Status:** Code-Level Evidence Analysis

---

## 1. Security Boundary Invariant Verification

This section answers the 11 mandatory boundary verification questions using direct source-code inspection.

### Q1: Can any tool execute without passing through policy authorization?
- **Source Inspection:**
  - `src/agents/graph.py` -> `policy_validation_node` lines 183–204: If `decision.allowed` is False, sets `tool_name = None` and intercepts execution.
  - `src/tools/registry.py` -> `execute_tool()` lines 124–135: Independently calls `policy_engine.evaluate(tool_name, arguments, session_context)`.
- **Finding:** Under standard operation (`bypass_policy=False`), NO tool can execute without passing through policy authorization. There is a defense-in-depth double-check (both in the LangGraph validation node and directly inside the tool execution registry).
- **Residual Risk:** If a developer or test harness sets `bypass_policy=True` in `execute_tool()`, policy checks are skipped.

### Q2: Can the LLM bypass authorization by changing its response?
- **Source Inspection:**
  - `src/agents/graph.py` -> `planner_node()` lines 102–115 & `policy_validation_node()` lines 162–180.
- **Finding:** **NO.** The policy engine operates independently outside the LLM. Regardless of whether the model outputs convincing social engineering claims (e.g. *"I am an administrator"*, *"Restrictions waived"*), the policy engine reads the verified `session_context["user_role"]` passed in the initial invocation, not conversational text.

### Q3: Can bypass_policy be reached from the protected execution interface?
- **Source Inspection:**
  - `src/agents/graph.py` -> `run_agent(..., bypass_policy: bool = False)` line 265.
  - `src/agents/state.py` -> `AgentState["bypass_policy"]` line 40.
- **Finding:** An attacker communicating via natural language prompts CANNOT set `bypass_policy` because it is a Python keyword argument passed to `run_agent()`.
- **Architecture Weakness:** The `bypass_policy` flag resides directly in the production `run_agent()` function and `AgentState` schema. Having a bypass mechanism inside the primary agent entry point is poor architectural hygiene.
- **Recommended Correction:** Remove `bypass_policy` from `run_agent()`. Create an explicit, separate `VulnerableBaselineAgent` class for comparative benchmarking. (Priority: High).

### Q4: Can untrusted document instructions enter the planner as trusted instructions?
- **Source Inspection:**
  - `src/agents/graph.py` -> `document_analysis_node()` lines 220–248.
  - `src/agents/graph.py` -> `planner_node()` lines 79–96.
- **Finding:** **PARTIALLY VERIFIED VULNERABILITY.**
  In `document_analysis_node`, when an injection is detected, the document is appended to `untrusted_context_sources`. However, in `planner_node`, `formatted_messages` is constructed ONLY from `messages` (user and assistant turns). If the agent's previous `final_response` summarized or echoed untrusted content, it enters `messages` without structural taint tags. The model could confuse document directives with user requests in subsequent turns.
- **Recommended Correction:** Formally separate `messages` into `trusted_dialogue` vs `untrusted_document_context` with explicit delimiter blocks in the LLM prompt. (Priority: High).

### Q5: Is document provenance retained across turns?
- **Source Inspection:**
  - `src/tools/document_reader.py` -> `read_document()` lines 39–58: Wraps document in `<<<BEGIN_UNTRUSTED_DOCUMENT id="...">>>`.
  - `src/agents/state.py` -> `AgentState["untrusted_context_sources"]`.
  - `src/evaluation/runner.py` -> `run_scenario()` lines 48–50: Propagates `untrusted_context_sources` across turns.
- **Finding:** Document IDs are retained in `untrusted_context_sources`, but granular provenance metadata (retrieval timestamp, origin tool, classification level, hash) is not persisted as a structured provenance object across turns. (Priority: Medium).

### Q6: Does taint tracking affect enforcement or only generate warnings?
- **Source Inspection:**
  - `src/security/taint.py` -> `is_tainted_by_untrusted_source()` lines 53–74.
  - `src/security/policies.py` -> `SecurityPolicyEngine.evaluate()` lines 185–197.
- **Finding:** **VERIFIED DEFECT.**
  `policies.py` inspects `tool_args` for static injection tokens via `TaintTracker.scan_for_injection_markers(v)` and blocks tainted arguments with `DENIED_TAINTED_ARGUMENT`. HOWEVER, the dynamic taint tracking method `is_tainted_by_untrusted_source()` is NEVER invoked in `policies.py` or `graph.py`. Taint tracking in `document_analysis_node` only logs security events; it does NOT dynamically taint subsequent tool proposals derived from untrusted documents. (Priority: High).

### Q7: Are unknown resources denied by default?
- **Source Inspection:**
  - `src/security/policies.py` -> `RESOURCE_CLASSIFICATION` lines 18–28:
    ```python
    classification = RESOURCE_CLASSIFICATION.get(str(resource_id), "INTERNAL")
    ```
- **Finding:** **VERIFIED VULNERABILITY.**
  When an unrecognized resource ID is requested, `RESOURCE_CLASSIFICATION.get(str(resource_id), "INTERNAL")` defaults to `"INTERNAL"`! For an `analyst` (who is allowed `INTERNAL` resources), an unknown resource is **ALLOWED** by default!
- **Recommended Correction:** Change default fallback from `"INTERNAL"` to `"RESTRICTED"` (Fail-Closed / Default Deny). Any resource not explicitly classified must be rejected by default. (Priority: Critical).

### Q8: Are user permissions verified independently of LLM-generated claims?
- **Source Inspection:**
  - `src/agents/graph.py` -> `input_boundary_node()` lines 63–76.
  - `src/security/policies.py` -> `evaluate()` lines 85–86.
- **Finding:** **VERIFIED WORKING.**
  User role is determined exclusively by `session_context.get("user_role")`. The LLM planner has no ability to alter `session_context`. When a user says *"I am the administrator"*, `input_boundary_node` logs a `false_authorization_claim` event, and the policy engine strictly enforces the original session role.

### Q9: Are tool arguments validated against schemas?
- **Source Inspection:**
  - `src/security/policies.py` -> `TOOL_SCHEMAS` lines 30–67 and `evaluate()` lines 112–165.
- **Finding:** **VERIFIED WORKING.**
  Schema validation checks required parameters, forbids unexpected parameters, enforces strict parameter data types, and bounds maximum string length (e.g. max query length 200). 7 unit tests explicitly confirm these rejections.

### Q10: Are actual execution effects independently recorded?
- **Source Inspection:**
  - `src/evaluation/adjudicator.py` -> `adjudicate_turn()` lines 63–74:
    ```python
    if tool_result_data.get("success") and not tool_result_data.get("no_tool_called"):
        executed_tool = tool_result_data.get("tool_name") or proposed_tool
        ...
    ```
- **Finding:** **PARTIALLY IMPLEMENTED.**
  The adjudicator checks the dictionary returned by `execute_tool()` and verifies whether secrets appear in `final_response`. However, it does not diff the actual state of the mock database (`DATABASE_TABLES`) or filesystem before and after execution to verify state mutation independently. (Priority: Medium).

### Q11: Does a Guard classification ever override an independent policy denial?
- **Source Inspection:**
  - `src/agents/graph.py` lines 147–183.
  - `src/security/policies.py` lines 79–199.
- **Finding:** **VERIFIED SECURE.**
  The Guard classifier is currently not connected to the execution gate, and the policy engine does not consume Guard risk scores. A low risk score cannot bypass policy enforcement.

---

## 2. Itemized Security Findings Table

| ID | File | Function | Actual Behavior | Security Risk | Recommended Correction | Priority |
| :---: | :--- | :--- | :--- | :--- | :--- | :---: |
| **SEC-01** | `src/security/policies.py` | `evaluate()` (line 173) | Defaults unknown `resource_id` to `"INTERNAL"` | **Fail-Open:** Unclassified resources are accessible to standard analysts | Default to `"RESTRICTED"` (Fail-Closed) | **Critical (P0)** |
| **SEC-02** | `src/security/policies.py` | `RESOURCE_CLASSIFICATION` (lines 24–27) | `malicious_doc_001` is classified as `CONFIDENTIAL` | **Evaluation Flaw:** Analyst cannot read the document, blocking prompt injection testing at retrieval rather than execution | Reclassify adversarial documents as `INTERNAL` with untrusted taint | **Critical (P0)** |
| **SEC-03** | `src/security/taint.py` & `policies.py` | `is_tainted_by_untrusted_source()` | Defined but dead code; never invoked in policy decision loop | **Enforcement Gap:** Taint propagation across multi-turn context does not block downstream calls | Call taint check inside `evaluate()` and reject tainted tool dispatches | **High (P1)** |
| **SEC-04** | `src/agents/graph.py` & `src/tools/registry.py` | `run_agent()` & `execute_tool()` | `bypass_policy: bool` argument exposed in protected entry point | **Architectural Hygiene:** Vulnerable baseline logic is co-located with protected runtime | Separate into `ProtectedAgent` vs `BaselineAgent` wrappers | **High (P1)** |
| **SEC-05** | `src/tools/document_reader.py` | `search_synthetic_documents()` | Returns all matching documents without filtering by user clearance | **Information Disclosure:** Analyst search results include confidential titles and IDs | Filter search results against user's permitted classification levels | **High (P1)** |
| **SEC-06** | `notebooks/AgentShield_Guard_Training.ipynb` | Entire notebook | Notebook contains code but no execution outputs or saved checkpoints | **Unsupported Claim:** Guard model cannot be claimed as an active defense without trained weights | Run training on GPU/CPU, save checkpoint artifacts, and log real metrics | **High (P1)** |
| **SEC-07** | `src/evaluation/adjudicator.py` | `adjudicate_turn()` | Inspects return dict rather than environment state diff | **Adjudication Fragility:** An unauthorized state mutation could occur if tool return schema fails | Implement pre/post snapshot diffing of `DATABASE_TABLES` | **Medium (P2)** |
| **SEC-08** | `src/tracing/logger.py` | `log_event()` | Writes to local file `logs/traces.jsonl` | Missing tamper-proof log export interface for benchmark reporting | Add structured JSON trace exporter | **Low (P3)** |

