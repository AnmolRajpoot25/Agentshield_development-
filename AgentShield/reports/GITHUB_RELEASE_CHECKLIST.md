# AgentShield — Milestone 10: GitHub Release Readiness Manifest

**Lexsi AI Safety Hackathon (Track 2a, Problem Statement 2a.3)**  
**Audit Target:** Public GitHub Repository Cleanliness & Secret Prevention  
**Date:** November 14, 2026  
**Status:** **READY FOR GITHUB PUBLICATION (Zero Secrets, Clean Tree)**  

---

## 1. Executive Summary

This manifest verifies that the AgentShield repository is clean, complete, and free of sensitive private credentials. All files required for full academic and technical reproduction are staged and committed, while private development files are permanently excluded via `.gitignore`.

---

## 2. Sensitive Credentials & Privacy Audit

The local development directory contains intentionally present testing credentials that must never be pushed to a public remote:

| Sensitive File | Purpose in Private Dev | `.gitignore` Status | Git Tracking Status | Public Exposure Risk |
|:---|:---|:---:|:---:|:---:|
| `.env` | Local OpenRouter API testing key | **EXCLUDED** (`.env`) | **UNTRACKED** | **ZERO RISK (Preserved locally, not in git)** |
| `credentials.json` | Google Drive OAuth Client ID | **EXCLUDED** (`credentials.json`) | **UNTRACKED** | **ZERO RISK (Preserved locally, not in git)** |
| `token.json` | Google Drive Refresh Token | **EXCLUDED** (`token.json`) | **UNTRACKED** | **ZERO RISK (Preserved locally, not in git)** |
| `*.bin` / `pytorch_model.bin` | Large model weights (>100MB limit) | **EXCLUDED** (`*.bin`) | **UNTRACKED** | **ZERO RISK (Ignored by git, uploaded to HF)** |
| `.coverage` / `.pytest_cache` | Binary test coverage caches | **EXCLUDED** (`.coverage`) | **UNTRACKED** | **ZERO RISK (Ignored by git)** |

```bash
# Verification command: Ensure no sensitive files are tracked
git ls-files | grep -E "(\.env$|credentials\.json|token\.json|\.bin$)"
# Output: (Empty - zero sensitive files tracked)
```

---

## 3. Public Repository File Manifest

The public repository contains 100% of the files necessary for independent evaluator reproduction:

```
AgentShield-Auth/
├── .github/
│   └── workflows/
│       └── ci.yml                     # Automated GitHub Actions CI workflow (Py 3.11, 3.12)
├── .env.example                       # Non-secret environment template
├── .gitignore                         # Security-hardened exclusion patterns
├── README.md                          # Root entry point & quickstart guide
└── AgentShield/
    ├── README.md                      # Comprehensive module documentation
    ├── requirements.txt               # Pinned Python production dependencies
    ├── run_tests.py                   # Standalone automated test runner harness
    ├── configs/
    │   └── config.yaml                # Policy, RBAC, and LLM configuration
    ├── datasets/
    │   ├── adversarial/
    │   │   ├── benchmark_v4.jsonl     # Canonical 46-scenario multi-turn benchmark
    │   │   ├── full_benchmark.jsonl   # 25-scenario evaluation suite
    │   │   └── seed_scenarios.jsonl   # 10 initial seed scenarios
    │   └── processed/
    │       └── guard_dataset_v3.jsonl # 398 leak-free multi-turn training dialogues
    ├── docs/
    │   ├── ARCHITECTURE.md            # Execution boundary & Mermaid flowcharts
    │   ├── INSTALLATION.md            # Cross-platform environment setup guide
    │   ├── TRAINING.md                # DistilBERT Guard classifier training & calibration
    │   └── EVALUATION.md              # Benchmark evaluation & ablation reproduction
    ├── notebooks/
    │   └── AgentShield_Guard_Training.ipynb # Kaggle/Colab GPU fine-tuning notebook
    ├── reports/
    │   ├── ABSTRACT.md                # 404-word submission abstract
    │   ├── FINAL_HACKATHON_SUBMISSION.md # Master 15-section research write-up
    │   ├── RESEARCH_CLAIMS_AND_EVIDENCE.md # Quantitative mapping of all claims
    │   ├── REFERENCES.md              # Peer-reviewed academic bibliography
    │   ├── SUBMISSION_GAP_ANALYSIS.md # External evaluator scorecard (84/90)
    │   ├── TEST_RESULTS.md            # 76-test execution verification
    │   ├── SECURITY_REGRESSION.md     # Adversarial regression matrix
    │   ├── ARTIFACT_INDEX.md          # Master research traceability index
    │   └── figures/                   # High-res research visualizations
    │       ├── asr_comparison.png
    │       ├── uer_comparison.png
    │       ├── ablation_study.png
    │       ├── guard_recall_by_category.png
    │       ├── benign_utility_comparison.png
    │       ├── latency_distribution.png
    │       └── test_coverage.png
    ├── results/                       # Machine-readable JSON evaluation outputs
    │   ├── comparative_evaluation.json
    │   ├── ablation_results.json
    │   ├── latency_cost_results.json
    │   ├── guard_metrics.json
    │   └── coverage.json
    ├── src/                           # Core implementation
    │   ├── agents/                    # LangGraph agent runtime & baseline
    │   ├── guard/                     # DistilBERT sequence classifier & dataset builder
    │   ├── security/                  # SecurityPolicyEngine, RBAC matrix, TaintTracker
    │   ├── tools/                     # In-memory sandbox execution & document store
    │   ├── evaluation/                # Adjudicator, metrics calculator, experiment engine
    │   └── tracing/                   # Tamper-evident logger with SHA-256 state hashing
    └── tests/                         # 76 automated pytest cases across 11 test files
```

---

## 4. Git History & Commit Integrity

The commit history on `master` reflects continuous, structured progress:
- `bb7431c`: `feat(testing): complete milestone 6 automated testing, security regression and reliability`
- `36776b3`: `docs(reproducibility): complete milestone 7 documentation, reproduction guides, and artifact index`
- `d9ea76b`: `feat(huggingface): complete milestone 8 local dataset packaging, model repository, and publication verification`
- `ac64390`: `docs(research): complete milestone 9 final hackathon research write-up, abstract, claims evidence, and gap analysis`

**Author Identity:** Strictly preserved across all commits as:  
`Anmol Rajpoot <rajpootanmol779@gmail.com>`.

---

## 5. Instructions for Manual GitHub Publication

When the participant is ready to push this repository to GitHub:
```bash
# 1. Add your public GitHub remote
git remote add origin https://github.com/<your-username>/AgentShield.git

# 2. Push to master/main
git push -u origin master
```
*(No remote pushes are executed automatically by the agent).*
