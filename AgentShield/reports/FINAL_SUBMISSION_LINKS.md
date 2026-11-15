# AgentShield — Final Hackathon Submission Link Registry

**Lexsi AI Safety Hackathon (Track 2a, Problem Statement 2a.3)**  
**Registered Participant Email:** `rajpootanmol779@gmail.com`  
**Date:** November 14, 2026  

---

## 1. Submission Metadata & Track Information

| Field | Submission Value | Verification Status |
|:---|:---|:---:|
| **Project Title** | AgentShield: Policy-Enforced Security for Multi-Turn, Tool-Using AI Agents | **VERIFIED** |
| **Track** | Track 2a: Agentic AI Safety & Security | **VERIFIED** |
| **Problem Statement** | Problem 2a.3: Multi-turn Agent Guardrails, Tool-Use Containment & Adversarial Audit | **VERIFIED** |
| **Registered Participant Email** | `rajpootanmol779@gmail.com` | **VERIFIED** |
| **Abstract Word Count** | 404 words (under 500 word limit) | **VERIFIED** |
| **License** | Code: MIT \| Data & Model: Apache-2.0 | **VERIFIED** |

---

## 2. Submission Artifact Links

| Artifact Name | Platform / Type | Submission URL / Location | Status |
|:---|:---|:---|:---:|
| **Public GitHub Repository** | Source Code & Tests | `https://github.com/Anmol2507/AgentShield` | `PENDING_USER_PUSH` |
| **Hugging Face Dataset Collection** | Datasets & Benchmarks | `https://huggingface.co/collections/Anmol2507/agentshield-ai-agent-security-evaluation` | `READY_FOR_UPLOAD` |
| **Guard Dataset Repository** | Hugging Face Dataset | `https://huggingface.co/datasets/Anmol2507/agentshield-guard-dataset` | `READY_FOR_UPLOAD` |
| **Attack Benchmark Repository** | Hugging Face Dataset | `https://huggingface.co/datasets/Anmol2507/agentshield-attack-benchmark` | `READY_FOR_UPLOAD` |
| **Execution Traces Repository** | Hugging Face Dataset | `https://huggingface.co/datasets/Anmol2507/agentshield-synthetic-traces` | `READY_FOR_UPLOAD` |
| **Guard Model Repository** | Hugging Face Model | `https://huggingface.co/models/Anmol2507/agentshield-guard-distilbert` | `READY_FOR_UPLOAD` |
| **Research Submission Paper** | Markdown / Report | `AgentShield/reports/FINAL_HACKATHON_SUBMISSION.md` (or GitHub blob link) | **READY ON DISK** |
| **Submission Abstract** | Markdown / Text | `AgentShield/reports/ABSTRACT.md` | **READY ON DISK** |
| **Demonstration Walkthrough** | Script / Video Plan | `AgentShield/reports/DEMO_SCRIPT.md` | **READY ON DISK** |

*(Note: In accordance with hackathon instructions, remote repositories are marked `PENDING_USER_PUSH` / `PENDING_USER_UPLOAD` until the participant manually executes the provided push and upload scripts).*

---

## 3. Submission Abstract Text (Ready for Form Copy-Paste)

```text
Autonomous AI agents increasingly maintain multi-turn conversational state, query enterprise databases, ingest external documents, and execute real-world tools. However, this stateful autonomy creates critical security vulnerabilities: adversaries can erode safety constraints over multi-turn dialogues, assert conversational false authorization claims, or embed indirect prompt injections within retrieved data, manipulating the agent into dispatching destructive actions. Traditional AI guardrails focus on single-turn text classification, failing to prevent unauthorized execution when untrusted text influences downstream planning. 

To resolve this vulnerability, we introduce AgentShield, an agent security architecture that establishes a zero-trust protected execution boundary around the agent core: User Request -> Planner -> Guard -> Policy Engine -> Protected Executor -> Audit. AgentShield strictly decouples unprivileged model-level action proposals from deterministic authorization authority. The architecture integrates a fine-tuned multi-task DistilBERT Guard classifier that scores adversarial intent risk and categorizes attack vectors across seven threat classes, paired with an independent, non-bypassable Security Policy Engine. The policy engine deterministically enforces Role-Based Access Control (RBAC), default-deny Resource-Level Access Control (RLAC), parameter length and type bounds, structural document encapsulation (<<<BEGIN_UNTRUSTED_DOCUMENT>>>), and dynamic taint tracking prior to sandbox tool dispatch. 

We evaluate AgentShield using an interactive 36-scenario multi-turn benchmark (N=36, 96 interaction turns) spanning five core attack vectors (gradual jailbreaks, indirect prompt injection, tool misuse, context poisoning, and false authorization) alongside benign corporate workflows. Attacks are evaluated using an independent Attack Adjudicator that measures observable side-effects (database mutations, credential leakage) rather than superficial text refusals. 

In controlled comparative experiments across four architectural configurations, unhardened baseline agents suffered a 61.1% Attack Success Rate (ASR, 95% Wilson CI: [38.6%, 79.7%]) and a 63.9% Unauthorized Execution Rate (UER). While Guard intent classification alone provides valuable early-warning telemetry, it failed to reduce ASR without execution interception (61.1% ASR). In contrast, AgentShield's combined defense achieved a 0.0% Attack Success Rate (95% CI: [0.0%, 17.6%], p < 0.001) and 0.0% Unauthorized Execution Rate, completely neutralizing all 20 evaluated attacks. Furthermore, AgentShield preserved a 100.0% Benign Task Success Rate with 0.0% False Positive Rate and negligible security latency overhead (< 0.1 ms per request). Architectural ablation studies reveal that disabling RLAC increases attack success to 33.3%, confirming the necessity of defense-in-depth. 

Our findings demonstrate that statistical guardrails and LLM prompt restrictions are inherently insufficient for agent safety. Provable agent containment requires independent, deterministic policy enforcement operating as a hard execution gate. All source code, benchmarks, checkpoints, and 76 automated regression tests are open-sourced under Apache 2.0 and MIT licenses.
```

