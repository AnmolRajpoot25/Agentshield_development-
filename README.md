# 🛡️ AgentShield: Multi-Turn AI Agent Security Auditing & Enforcement Framework

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![LangGraph](https://img.shields.io/badge/Orchestration-LangGraph-orange.svg)](https://github.com/langchain-ai/langgraph)
[![Tests Passing](https://img.shields.io/badge/tests-76%2F76%20passing-brightgreen.svg)](AgentShield/tests/)
[![Security Benchmark](https://img.shields.io/badge/Benchmark-36%20Scenarios-red.svg)](AgentShield/datasets/adversarial/)
[![HF Models](https://img.shields.io/badge/%F0%9F%A4%97%20Hugging%20Face-Models%20Collection-yellow)](https://huggingface.co/collections/Anmol2507/agentshield-models-collection-6af98018b216382e742d42ba)
[![HF Datasets](https://img.shields.io/badge/%F0%9F%A4%97%20Hugging%20Face-Datasets%20Collection-blue)](https://huggingface.co/collections/Anmol2507/agentshield-datasets-collection-6af9800a7256661d479b5372)
[![License: MIT](https://img.shields.io/badge/License-MIT-purple.svg)](AgentShield/LICENSE)

> **Lexsi AI Safety Hackathon (Track 2a, Problem Statement 2a.3)**  
> **Primary Objective:** Build an AI agent security auditing and enforcement framework that prevents unauthorized actions under realistic multi-turn agent attacks while preserving legitimate task completion.  
> **Full Research Write-Up:** [**FINAL_HACKATHON_SUBMISSION.md**](AgentShield/reports/FINAL_HACKATHON_SUBMISSION.md) | **Submission Abstract:** [**ABSTRACT.md**](AgentShield/reports/ABSTRACT.md)

---

## ⚡ Quickstart

```bash
# 1. Clone repository
git clone https://github.com/AnmolRajpoot25/Agentshield_development-.git
cd Agentshield_development-

# 2. Create virtual environment & install dependencies
python -m venv venv
# On Windows: .\venv\Scripts\Activate.ps1 | On Linux/macOS: source venv/bin/activate
pip install -r AgentShield/requirements.txt

# 3. Run full automated test suite (76 tests, ~23s)
python AgentShield/run_tests.py

# 4. Run benchmark evaluation (36 scenarios)
python -m AgentShield.src.evaluation.runner --mode agentshield
```

---

## 📑 Core Documentation & Guides

| Guide | Description | Path |
|:---|:---|:---|
| **Research Paper & Write-Up** | Comprehensive hackathon research paper, methodology, and findings | [AgentShield/reports/FINAL_HACKATHON_SUBMISSION.md](AgentShield/reports/FINAL_HACKATHON_SUBMISSION.md) |
| **Submission Abstract** | 404-word official hackathon submission abstract | [AgentShield/reports/ABSTRACT.md](AgentShield/reports/ABSTRACT.md) |
| **Submission Links Registry** | Verified repository, collection, and dataset links | [AgentShield/reports/FINAL_SUBMISSION_LINKS.md](AgentShield/reports/FINAL_SUBMISSION_LINKS.md) |
| **System Architecture** | Protected execution boundary, node specifications, Mermaid flow | [AgentShield/docs/ARCHITECTURE.md](AgentShield/docs/ARCHITECTURE.md) |
| **Installation Guide** | Clean OS setup, CPU vs. GPU, offline vs. online mode | [AgentShield/docs/INSTALLATION.md](AgentShield/docs/INSTALLATION.md) |
| **Training & Calibration** | DistilBERT Guard classifier training, threshold calibration, inference | [AgentShield/docs/TRAINING.md](AgentShield/docs/TRAINING.md) |
| **Benchmark & Evaluation** | 36-scenario benchmark, 4 configurations, 6 ablations, metrics | [AgentShield/docs/EVALUATION.md](AgentShield/docs/EVALUATION.md) |
| **Artifact Traceability Index** | Mapping reported results to source JSONs, checkpoints, and figures | [AgentShield/reports/ARTIFACT_INDEX.md](AgentShield/reports/ARTIFACT_INDEX.md) |
| **Full Project README** | Detailed architectural, empirical, and mathematical documentation | [AgentShield/README.md](AgentShield/README.md) |

---

## 🔬 Key Empirical Results (Milestone 5)

| Metric | 1. Vulnerable Baseline | 2. Guard-Only | 3. Policy-Only | 4. AgentShield Combined | Defense Benefit |
|:---|:---:|:---:|:---:|:---:|:---:|
| **Attack Success Rate (ASR)** | **61.1%** | **61.1%** | **0.0%** | **0.0%** | **-61.1% reduction** |
| 95% Wilson Score CI | [38.6%, 79.7%] | [38.6%, 79.7%] | [0.0%, 17.6%] | [0.0%, 17.6%] | $p < 0.001$ |
| **Unauthorized Execution Rate (UER)**| **63.9%** | **63.9%** | **0.0%** | **0.0%** | **-63.9% reduction** |
| 95% Wilson Score CI | [47.6%, 77.5%] | [47.6%, 77.5%] | [0.0%, 11.3%] | [0.0%, 11.3%] | $p < 0.001$ |
| **Policy Rejection Rate (PRR)** | 0.0% | 0.0% | **100.0%** | **100.0%** | Complete interception |
| **Benign Task Success Rate (BTSR)** | **100.0%** | **100.0%** | **100.0%** | **100.0%** | Zero utility penalty |
| **False Positive Rate (FPR)** | **0.0%** | **0.0%** | **0.0%** | **0.0%** | Zero false alarms |
| **Security Overhead Latency** | 0.0 ms | 0.05 ms | 0.04 ms | **0.09 ms** | Negligible (< 0.1 ms) |

---

## 🔒 Security Invariants Verified Across 76 Tests

AgentShield enforces 5 core invariants verified with **100% pass rate** in `AgentShield/run_tests.py`:
1. **Proposal Separation:** Unprivileged LLM Planner has zero authorization authority.
2. **Default-Deny RLAC:** Unregistered resources and confidential documents fail closed.
3. **Privilege Exclusivity:** Non-admin roles can never execute destructive operations (`delete_records`).
4. **Data Encapsulation:** Retrieved external content is structurally isolated as passive data.
5. **Fail-Closed Resilience:** Exceptions, schema mismatches, and outages fail safely.

---

## 📁 Repository Structure

```
.
├── .github/workflows/ci.yml       # Continuous integration pipeline
├── .env.example                   # Environment configuration template
├── README.md                      # Root documentation & quickstart
└── AgentShield/
    ├── configs/                   # Runtime & policy configurations
    ├── datasets/                  # Benchmark & Guard datasets
    │   ├── adversarial/           # Canonical benchmark_v4.jsonl (36 scenarios)
    │   └── processed/             # Guard training dataset (68 dialogues)
    ├── checkpoints/               # Trained Guard model weights (DistilBERT)
    ├── docs/                      # Architectural & evaluation guides
    ├── reports/                   # Technical audit & research reports
    ├── results/                   # Machine-readable experiment JSONs
    ├── src/                       # Core implementation
    │   ├── agents/                # LangGraph protected agent runtime
    │   ├── guard/                 # DistilBERT Guard classifier & inference
    │   ├── security/              # Security Policy Engine, RBAC, Taint Tracking
    │   ├── tools/                 # In-memory sandbox execution & document store
    │   └── evaluation/            # Adjudicator, metrics, and experiment engine
    ├── tests/                     # 76 automated pytest cases
    └── run_tests.py               # Standalone test runner harness
```

---

## 📄 License
Licensed under the [MIT License](AgentShield/LICENSE).

