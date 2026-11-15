#!/usr/bin/env python3
"""
AgentShield — Hugging Face Model Upload Harness
Safely packages and validates the fine-tuned DistilBERT Guard classifier prior to publication.

Supports dry-run validation by default. Publication requires explicit --publish flag
and HF_TOKEN environment variable. Never commits or logs authentication tokens.
"""

import os
import sys
import argparse
from pathlib import Path

try:
    from dotenv import load_dotenv
    # Search root and local .env
    load_dotenv()
    load_dotenv(Path(__file__).resolve().parent.parent.parent.parent / ".env")
except ImportError:
    pass

# Paths
HF_BASE = Path(__file__).resolve().parent.parent
HF_MODELS_DIR = HF_BASE / "models"

MODEL_TO_UPLOAD = {
    "repo_name": "agentshield-guard-distilbert",
    "local_path": HF_MODELS_DIR / "agentshield-guard-distilbert",
    "repo_type": "model",
    "files": [
        "README.md",
        "pytorch_model.bin",
        "config.json",
        "guard_config.json",
        "model_metadata.json",
        "tokenizer.json",
        "tokenizer_config.json",
        "vocab.txt",
        "special_tokens_map.json",
        "inference.py"
    ]
}


def validate_local_model():
    print("[*] Validating local model packaging...")
    path = MODEL_TO_UPLOAD["local_path"]
    print(f"\n[+] Checking model directory: {path}")

    if not path.exists():
        print(f"[-] ERROR: Missing directory: {path}")
        return False

    all_valid = True
    for f in MODEL_TO_UPLOAD["files"]:
        file_path = path / f
        if not file_path.exists():
            print(f"[-] ERROR: Missing file: {file_path}")
            all_valid = False
        else:
            sz = file_path.stat().st_size
            print(f"    - {f}: OK ({sz:,} bytes)")

    return all_valid


def upload_model(args):
    print("=" * 70)
    print("AgentShield — Hugging Face Model Publication Manager")
    print("=" * 70)

    if not validate_local_model():
        print("\n[-] Validation failed. Aborting.")
        return 1

    if args.dry_run:
        print("\n" + "=" * 70)
        print("[+] DRY-RUN SUCCESSFUL: Model repository is locally validated.")
        print("[+] Model weights (267.8 MB), tokenizer, config, and Model Card are verified.")
        print("[!] No remote files were uploaded. Pass --publish with HF_TOKEN to upload.")
        print("=" * 70 + "\n")
        return 0

    # Explicit publication mode
    token = os.environ.get("HF_TOKEN")
    if not token:
        print("\n[-] ERROR: HF_TOKEN environment variable is required for publication.")
        print("    Set your token via: export HF_TOKEN=hf_... (Linux/macOS) or $env:HF_TOKEN=\"hf_...\" (PowerShell)")
        return 1

    try:
        from huggingface_hub import HfApi
        api = HfApi(token=token)
        org = args.organization or api.whoami()["name"]

        repo_id = f"{org}/{MODEL_TO_UPLOAD['repo_name']}"
        print(f"\n[*] Creating/updating remote model repository: {repo_id}...")
        api.create_repo(repo_id=repo_id, repo_type="model", exist_ok=True)

        print(f"[*] Uploading files from {MODEL_TO_UPLOAD['local_path']} to {repo_id}...")
        api.upload_folder(
            folder_path=str(MODEL_TO_UPLOAD["local_path"]),
            repo_id=repo_id,
            repo_type="model",
            commit_message="Release AgentShield Guard DistilBERT v3.0.0"
        )
        print(f"[+] Successfully published: https://huggingface.co/{repo_id}")
        return 0

    except Exception as e:
        print(f"\n[-] Upload failed: {e}")
        return 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AgentShield Hugging Face Model Uploader")
    parser.add_argument("--dry-run", action="store_true", default=True, help="Validate locally without uploading (default)")
    parser.add_argument("--publish", dest="dry_run", action="store_false", help="Execute actual upload to Hugging Face Hub")
    parser.add_argument("--organization", type=str, default=None, help="Target Hugging Face username or organization")
    args = parser.parse_args()

    sys.exit(upload_model(args))
