import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

# Resolve base directory dynamically (supports local dev, CI, and Kaggle)
def get_base_dir() -> Path:
    kaggle_dir = Path("/kaggle/working/AgentShield")
    if kaggle_dir.exists():
        return kaggle_dir
    # Fallback to local project directory relative to this file
    return Path(__file__).resolve().parent.parent.parent


BASE_DIR = get_base_dir()
LOG_DIR = BASE_DIR / "logs"
TRACE_FILE = LOG_DIR / "traces.jsonl"


def compute_state_hash(state_dict: Dict[str, Any]) -> str:
    """
    Computes a deterministic SHA-256 signature of the state payload
    to provide tamper-evident cryptographic traceability for security audits.
    """
    try:
        serialized = json.dumps(state_dict, sort_keys=True, default=str)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    except Exception:
        return "hash_unavailable"


def log_event(
    episode_id: str,
    event_type: str,
    payload: Dict[str, Any],
    trace_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Records a structured security event in the centralized audit trace log.
    Includes trace_id, episode_id, UTC timestamp, event_type, payload,
    and a tamper-evident state hash.
    """
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    trace = {
        "trace_id": trace_id or str(uuid.uuid4()),
        "episode_id": episode_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "payload": payload,
        "state_hash": compute_state_hash(payload)
    }

    try:
        with TRACE_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(trace, ensure_ascii=False, default=str) + "\n")
    except Exception as e:
        # Failsafe logging to stderr without halting agent execution
        import sys
        sys.stderr.write(f"[AgentShield Audit Warning] Trace logging error: {e}\n")

    return trace


def get_episode_traces(episode_id: str) -> list:
    """
    Retrieves all trace events associated with a specific episode ID.
    """
    traces = []
    if not TRACE_FILE.exists():
        return traces

    with TRACE_FILE.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                if event.get("episode_id") == episode_id:
                    traces.append(event)
            except Exception:
                continue
    return traces
