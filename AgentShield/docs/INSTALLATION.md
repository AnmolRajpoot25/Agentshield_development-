# AgentShield — Installation & Environment Setup Guide

**Lexsi AI Safety Hackathon (Track 2a, Problem Statement 2a.3)**  
**Target Environment:** Cross-platform (Linux, macOS, Windows)  
**Document Version:** 2.0 (Milestone 7 Production Baseline)

---

## 1. System Requirements & Tested Environments

AgentShield has been tested and verified in the following environments:

| Environment | OS Version | Python Version | Hardware | Status |
|:---|:---|:---:|:---:|:---:|
| **Local Host (Primary)** | Windows 11 (x86_64) | 3.13.2 | AMD / Intel Multi-Core CPU | **Verified (76/76 Tests Pass)** |
| **CI Runner (Matrix 1)** | Ubuntu 22.04 LTS | 3.11 | GitHub Actions Hosted Runner (CPU) | **Verified in CI Pipeline** |
| **CI Runner (Matrix 2)** | Ubuntu 22.04 LTS | 3.12 | GitHub Actions Hosted Runner (CPU) | **Verified in CI Pipeline** |
| **Kaggle Cloud (Optional)**| Ubuntu 20.04 LTS | 3.10 | NVIDIA Tesla T4 / P100 (16GB VRAM) | **Verified for GPU Training** |

### Hardware Requirements
- **Memory (RAM):** 8 GB minimum (16 GB recommended).
- **Disk Storage:** ~2 GB free disk space (includes PyTorch, Transformers, and Guard model weights).
- **CPU:** Standard x86_64 or ARM64 processor (at least 2 physical cores).
- **GPU (Optional):** NVIDIA GPU with CUDA 11.8+ or 12.1+ support for fast Guard model fine-tuning. CPU execution is automatically used if no GPU is detected.

---

## 2. Step-by-Step Installation

### Step 2.1: Clone the Repository
```bash
git clone https://github.com/your-org/AgentShield.git
cd AgentShield
```

### Step 2.2: Create and Activate a Virtual Environment
We strongly recommend using a dedicated Python virtual environment:

#### On Linux / macOS:
```bash
python3 -m venv venv
source venv/bin/activate
```

#### On Windows (PowerShell):
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

#### On Windows (Command Prompt):
```cmd
python -m venv venv
.\venv\Scripts\activate.bat
```

### Step 2.3: Upgrade Package Management Tools
```bash
python -m pip install --upgrade pip setuptools wheel
```

### Step 2.4: Install Production & Research Dependencies
```bash
pip install -r AgentShield/requirements.txt
```

*Note: If running directly inside the `AgentShield/` directory:*
```bash
pip install -r requirements.txt
```

---

## 3. Dependency Verification

Verify that core packages load cleanly:

```bash
python -c "
import torch
import transformers
import langgraph
import pytest
import matplotlib
print(f'PyTorch Version: {torch.__version__}')
print(f'CUDA Available: {torch.cuda.is_available()}')
print(f'Transformers Version: {transformers.__version__}')
print(f'LangGraph Version: {langgraph.__version__}')
print('[+] Environment verified successfully.')
"
```

Expected output:
```
PyTorch Version: 2.2.0+ (or higher)
CUDA Available: True (if GPU installed) or False (if CPU-only)
Transformers Version: 4.40.0+ (or higher)
LangGraph Version: 0.2.0+ (or higher)
[+] Environment verified successfully.
```

---

## 4. Hardware Configuration & Fallback Options

### 4.1 CPU-Only Execution (Default Fallback)
If you do not have an NVIDIA GPU, AgentShield automatically configures PyTorch and DistilBERT to run on CPU. No manual code changes are required:
- Full automated test suite (76 tests) completes in **~23 seconds** on CPU.
- Guard inference overhead on CPU is **< 0.1 ms** per request.
- Benchmark evaluations on CPU complete in **< 15 seconds**.

### 4.2 NVIDIA GPU Acceleration (Optional)
If you have an NVIDIA GPU, verify that PyTorch is built with CUDA support:
```bash
python -c "import torch; print('Device:', torch.cuda.get_device_name(0) if torch.cuda.is_available() else 'CPU')"
```
To install CUDA-enabled PyTorch for your specific CUDA version, consult [PyTorch Get Started](https://pytorch.org/get-started/locally/).

---

## 5. Offline vs. Live API Execution Modes

AgentShield supports two execution modes:

### Mode A: Completely Offline Mode (No API Key Required)
- **What runs:** 100% of the 76 automated tests, the Security Policy Engine, RBAC matrix, RLAC clearance rules, Taint Tracker, Document Reader, Guard model inference (via local checkpoint or heuristic fallback), and Benchmark runs.
- **How it works:** When `OPENROUTER_API_KEY` is not present, AgentShield activates the deterministic `MockLLMClient`, generating predictable plans offline.
- **Setup:** No `.env` configuration is needed.

### Mode B: Live LLM Mode (OpenRouter API Key Required)
- **What runs:** Live multi-turn planning via cloud models (e.g., `nvidia/nemotron-4-340b-instruct` or `nvidia/nemotron-3.5-lightning-free`).
- **Setup:** Copy `.env.example` to `.env` and insert your key:
  ```bash
  cp .env.example .env
  # Edit .env and set OPENROUTER_API_KEY=your_key_here
  ```

---

## 6. Smoke Test: Verifying the Installation

Run the automated isolation test suite to confirm installation success:

```bash
python AgentShield/run_tests.py --suite isolation
```

Expected terminal output:
```
================================================================================
                    AgentShield — Automated Test Harness
================================================================================
[*] Running command: ... -m pytest .../test_isolation.py -v
============================== 3 passed in 9.23s ==============================
[+] SUITE VERDICT: PASSED (100% of test invariants satisfied)
================================================================================
```

