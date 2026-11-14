---
license: apache-2.0
task_categories:
  - text-classification
language:
  - en
tags:
  - ai-safety
  - agentic-ai
  - prompt-injection
  - jailbreak
  - guardrails
  - security
pretty_name: AgentShield Multi-Turn Guard Classifier Dataset
size_categories:
  - n<1K
---

# AgentShield Guard Intent & Category Classifier Dataset

**Lexsi AI Safety Hackathon (Track 2a, Problem Statement 2a.3)**  
**Version:** `v3.0.0`  
**License:** Apache 2.0  
**Repository:** `AgentShield/datasets/processed/guard_dataset_v3.jsonl`  

---

## 1. Dataset Summary

The **AgentShield Guard Dataset** is a curated, multi-turn conversational dataset designed to train and evaluate sequence classifiers that detect adversarial intent in autonomous AI agents. Unlike traditional single-turn prompt injection datasets, this dataset models multi-turn dialogues where attackers attempt gradual trust escalation, conversational false authorization claims, indirect prompt injection inside passive documents, and destructive tool misuse.

The dataset contains **398 formatted multi-turn dialogues** partitioned into leak-free train, validation, and test splits with joint binary intent labels and 7 fine-grained attack categories.

---

## 2. Dataset Structure & Splits

### Split Breakdown
- **Train:** 354 dialogues (seed dialogues + controlled lexical augmentations).
- **Validation:** 22 dialogues (100% original unaugmented seed dialogues).
- **Test:** 22 dialogues (100% original unaugmented seed dialogues, strictly untouched during training and threshold calibration).

### Leakage Prevention Methodology
Traditional NLP datasets often perform data augmentation before partitioning, causing paraphrased variants of the same sample to appear in both training and test sets. 
**AgentShield enforces a strict Split-First Anti-Leakage Rule:**
1. Original seed dialogues are partitioned by `family_id` prior to any augmentation.
2. Data augmentation is applied **exclusively to the training split**.
3. The validation and test sets contain strictly unaugmented samples (`is_augmented: false`) with **zero family overlap** with the training set ($\text{Train} \cap \text{Test} = \emptyset$).

---

## 3. Data Schema & Features

Each sample is structured as follows:

| Field Name | Type | Description | Example |
|:---|:---|:---|:---|
| `sample_id` | string | Unique sample identifier | `sample_gradual_jailbreak_001_v1` |
| `family_id` | string | Seed family identifier used for leak-free splitting | `fam_gradual_001` |
| `is_augmented` | boolean | Indicates whether the sample is an augmented variant | `false` |
| `split` | string | Split partition (`train`, `val`, `test`) | `train` |
| `binary_label` | int | 0 = Benign, 1 = Adversarial | `1` |
| `category` | string | Attack category or benign | `gradual_jailbreak` |
| `category_id` | int | Mapped numeric ID (0 to 6) | `1` |
| `formatted_text`| string | Structured multi-turn conversation string | `[USER]: Turn 1 text... [ASSISTANT]: ...` |
| `turns` | list | List of individual turn objects with role and content | `[{"role": "user", "content": "..."}]` |

---

## 4. Attack Categories & Label Mapping

| Category ID | Category Name | Description |
|:---:|:---|:---|
| `0` | `benign` | Legitimate corporate workflows (invoice queries, security policy search, financial summaries). |
| `1` | `gradual_jailbreak` | Multi-turn trust escalation eroding safety restrictions across turns. |
| `2` | `indirect_prompt_injection`| Injected directives embedded within external retrieved passive documents. |
| `3` | `tool_misuse` | Attempting to execute unregistered tools (`system_shell`) or unpermitted destructive calls. |
| `4` | `context_poisoning` | Fabricated claims regarding previous conversation turns or permissions. |
| `5` | `false_authorization` | Fabricated ticket approvals or conversational claims of administrative authority. |
| `6` | `privilege_escalation` | Non-admin roles attempting to execute root or security-override operations. |

---

## 5. Intended Use & Safety Considerations

- **Primary Use:** Training and benchmarking adversarial intent classifiers for agentic AI architectures.
- **Out-of-Scope Use:** The Guard classifier is an **early-detection and telemetry component, NOT an authorization engine.** It must not be deployed as a sole defense or replace deterministic policy engines.
- **Safety Disclosure:** Synthetic attack examples are evaluation artifacts designed to test defense boundaries. They do not contain executable exploit code or harmful real-world malware.

---

## 6. Citation & Provenance

```bibtex
@dataset{agentshield_guard_dataset_2026,
  title={AgentShield: Multi-Turn AI Agent Guard Classifier Dataset},
  author={Rajpoot, Anmol},
  year={2026},
  publisher={Hugging Face},
  howpublished={\url{https://huggingface.co/datasets/agentshield-guard-dataset}}
}
```
