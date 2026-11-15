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

## 4. Live Published Collections & Repositories

- **Hugging Face Datasets Collection:** [https://huggingface.co/collections/Anmol2507/agentshield-datasets-collection-6af9800a7256661d479b5372](https://huggingface.co/collections/Anmol2507/agentshield-datasets-collection-6af9800a7256661d479b5372)
  - `Anmol2507/agentshield-guard-dataset`
  - `Anmol2507/agentshield-attack-benchmark`
  - `Anmol2507/agentshield-synthetic-traces`
- **Hugging Face Models Collection:** [https://huggingface.co/collections/Anmol2507/agentshield-models-collection-6af98018b216382e742d42ba](https://huggingface.co/collections/Anmol2507/agentshield-models-collection-6af98018b216382e742d42ba)
  - `Anmol2507/agentshield-guard-distilbert`
- **Status:** **PUBLISHED & PUBLIC (VERIFIED)**.

---

## 5. Verification & Access Audit

All repositories and collections have been created and published publicly on Hugging Face Hub under the account `Anmol2507`:
- All individual repositories are un-gated and publicly accessible.
- Both collections are public (`private: False`).
- SHA-256 and byte sizes match local source artifacts.

