# AgentShield — Milestone 10: Hugging Face Release Verification

**Lexsi AI Safety Hackathon (Track 2a, Problem Statement 2a.3)**  
**Audit Target:** Hugging Face Datasets & Model Artifact Readiness  
**Date:** November 14, 2026  
**Status:** **LOCALLY VERIFIED & PREPARED (Awaiting Manual User Publish)**  

---

## 1. Executive Summary

This report verifies that all candidate Hugging Face datasets and model artifacts are packaged, formatted, and validated locally inside `AgentShield/artifacts/huggingface/`. The artifacts conform to Hugging Face Hub standards (including structured YAML frontmatter, dataset viewer compatibility, and FastTokenizer artifacts) and are configured for ungated, public access upon upload.

---

## 2. Dataset Collection Verification

### 2.1 `agentshield-guard-dataset`
- **Path:** `AgentShield/artifacts/huggingface/datasets/agentshield-guard-dataset/`
- **Total Samples:** 398 multi-turn dialogues across 7 categories.
- **Files:**
  - `README.md`: Complete Dataset Card with task tags, schema table, and anti-leakage disclosure.
  - `train.jsonl`: 354 records (seed dialogues + controlled lexical augmentations).
  - `validation.jsonl`: 22 records (100% original unaugmented seed dialogues).
  - `test.jsonl`: 22 records (100% original unaugmented seed dialogues, untouched during training).
- **Anti-Leakage Verification:** $\text{Train} \cap \text{Test} = \emptyset$ across all `family_id`s. Zero augmented variants exist in validation or test splits.
- **License:** Apache 2.0.
- **Status:** **READY FOR RELEASE**.

### 2.2 `agentshield-attack-benchmark`
- **Path:** `AgentShield/artifacts/huggingface/datasets/agentshield-attack-benchmark/`
- **Total Scenarios:** 46 multi-turn evaluation scenarios.
- **Files:**
  - `README.md`: Complete Benchmark Dataset Card documenting the 7 threat classes and side-effect adjudication.
  - `benchmark_v4.jsonl`: Canonical 46 scenarios (36 attack scenarios, 10 control tasks).
  - `seed_scenarios.jsonl`: 10 initial seed scenarios.
- **Schema Validation:** Every record contains required keys (`turns`, `target_tool`, `user_role`, `observable_success_condition`, `expected_behavior`).
- **License:** Apache 2.0.
- **Status:** **READY FOR RELEASE**.

### 2.3 `agentshield-synthetic-traces`
- **Path:** `AgentShield/artifacts/huggingface/datasets/agentshield-synthetic-traces/`
- **Total Records:** 250 representative audit events.
- **Files:**
  - `README.md`: Telemetry Dataset Card explaining cryptographic SHA-256 state hashing and audit structure.
  - `sample_audit_traces.jsonl`: 250 sanitized, formatted multi-turn runtime events.
- **Privacy Verification:** Zero private credentials; all master keys and secrets redacted (`[REDACTED_SECRET]`).
- **License:** Apache 2.0.
- **Status:** **READY FOR RELEASE**.

---

## 3. Model Collection Verification

### 3.1 `agentshield-guard-distilbert`
- **Path:** `AgentShield/artifacts/huggingface/models/agentshield-guard-distilbert/`
- **Architecture:** Dual-head multi-task classifier built on `distilbert-base-uncased`.
- **Files Verified on Disk:**
  - `README.md`: Detailed Model Card with **Critical Security Boundary Disclosure**.
  - `pytorch_model.bin`: Fine-tuned PyTorch tensor weights (**267,870,099 bytes / 267.8 MB**).
  - `config.json`: Standard Hugging Face AutoConfig definition.
  - `guard_config.json`: AgentShield category mapping and loss weights.
  - `model_metadata.json`: Epoch history, validation loss, calibrated threshold ($\tau = 0.65$).
  - `tokenizer.json`, `tokenizer_config.json`, `vocab.txt`, `special_tokens_map.json`: FastTokenizer.
  - `inference.py`: Standalone, self-contained inference script.
- **Model Load & Inference Test:**
  - Loaded successfully on CPU via `inference.py`.
  - Executed test prompt in **29.7 ms** with risk score `0.9485` and category `privilege_escalation`.
- **License:** Apache 2.0 (compatible with base DistilBERT license).
- **Status:** **READY FOR RELEASE**.

---

## 4. Collection Metadata

- **Collection Title:** `AgentShield — AI Agent Security Evaluation`
- **Collection Slug:** `agentshield-ai-agent-security-evaluation`
- **Metadata File:** `AgentShield/artifacts/huggingface/collections/collection_metadata.json`
- **Organization:** Links 1 model repository and 3 dataset repositories into a single public hub.

---

## 5. Step-by-Step Instructions for Manual Hugging Face Publish

When the participant is ready to publish to Hugging Face:

```bash
# 1. Install huggingface_hub CLI (if not already installed)
pip install huggingface_hub

# 2. Login to your Hugging Face account (or set HF_TOKEN environment variable)
huggingface-cli login
# Or in PowerShell: $env:HF_TOKEN = "hf_your_token_here"
# Or in Bash:       export HF_TOKEN="hf_your_token_here"

# 3. Publish Datasets (Runs upload_datasets.py with --publish flag)
python AgentShield/artifacts/huggingface/upload_scripts/upload_datasets.py --publish

# 4. Publish Model (Runs upload_models.py with --publish flag)
python AgentShield/artifacts/huggingface/upload_scripts/upload_models.py --publish
```

*(Note: Per constraints, the AI assistant will NOT execute these upload commands automatically).*
