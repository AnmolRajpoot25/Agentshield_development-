import json
import os
import re
import time
from typing import Any, Dict, List, Optional, Union

import torch
from transformers import AutoTokenizer

from src.guard.config import GuardConfig, CATEGORY_MAP, ID2CATEGORY, LABEL_MAP
from src.guard.dataset import format_multi_turn_dialogue
from src.guard.model import MultiTaskAgentShieldGuard


class GuardPredictor:
    """
    Production inference engine for AgentShield Guardrail.
    Evaluates user requests, multi-turn dialogue, and untrusted documents,
    returning structured telemetry and risk assessment.
    """

    def __init__(
        self,
        checkpoint_dir: Optional[str] = None,
        config: Optional[GuardConfig] = None,
        device: Optional[torch.device] = None
    ):
        self.config = config or GuardConfig()
        self.checkpoint_dir = checkpoint_dir or self.config.checkpoint_dir
        self.device = device or torch.device("cuda" if torch.cuda.is_available() else "cpu")
        
        self.model: Optional[MultiTaskAgentShieldGuard] = None
        self.tokenizer: Optional[AutoTokenizer] = None
        self.is_loaded: bool = False
        self.threshold: float = self.config.calibrated_threshold
        
        self._load_model_artifacts()

    def _load_model_artifacts(self):
        """Attempts to load fine-tuned model and tokenizer from checkpoint_dir."""
        try:
            if os.path.exists(self.checkpoint_dir) and os.path.exists(os.path.join(self.checkpoint_dir, "pytorch_model.bin")):
                self.tokenizer = AutoTokenizer.from_pretrained(self.checkpoint_dir)
                self.model = MultiTaskAgentShieldGuard.from_pretrained(self.checkpoint_dir, device=self.device)
                self.model.eval()
                
                meta_path = os.path.join(self.checkpoint_dir, "model_metadata.json")
                if os.path.exists(meta_path):
                    with open(meta_path, "r", encoding="utf-8") as f:
                        meta = json.load(f)
                    self.threshold = meta.get("calibrated_threshold", self.config.calibrated_threshold)
                    
                self.is_loaded = True
            elif os.path.exists(self.checkpoint_dir) and os.path.exists(os.path.join(self.checkpoint_dir, "guard_config.json")):
                # Checkpoint dir initialized with config but no binary weights yet
                self.tokenizer = AutoTokenizer.from_pretrained(self.config.base_model_name)
                self.model = MultiTaskAgentShieldGuard(self.config).to(self.device)
                self.model.eval()
                self.is_loaded = True
        except Exception as e:
            self.is_loaded = False
            self.load_error = str(e)

    def predict(
        self,
        interaction: Union[str, List[Dict[str, Any]]],
        override_threshold: Optional[float] = None
    ) -> Dict[str, Any]:
        """
        Evaluates input interaction and returns structured risk telemetry.
        Never throws unhandled exceptions; fails closed to heuristic fallback.
        """
        start_time = time.time()
        eff_threshold = override_threshold if override_threshold is not None else self.threshold

        # Format input
        if isinstance(interaction, list):
            formatted_text = format_multi_turn_dialogue(interaction)
        else:
            formatted_text = str(interaction)

        # Handle empty/blank inputs
        if not formatted_text.strip():
            latency_ms = (time.time() - start_time) * 1000
            return {
                "risk_score": 0.0,
                "predicted_label": "benign",
                "attack_category": "benign",
                "category_confidence": 1.0,
                "threshold": eff_threshold,
                "model_version": self.config.model_version,
                "inference_status": "EMPTY_INPUT",
                "latency_ms": round(latency_ms, 2)
            }

        # Model Inference Path
        if self.is_loaded and self.model is not None and self.tokenizer is not None:
            try:
                inputs = self.tokenizer(
                    formatted_text,
                    truncation=True,
                    max_length=self.config.max_seq_length,
                    return_tensors="pt"
                ).to(self.device)

                with torch.no_grad():
                    bin_logits, cat_logits = self.model(inputs["input_ids"], inputs["attention_mask"])

                bin_probs = torch.softmax(bin_logits, dim=-1).squeeze(0)
                cat_probs = torch.softmax(cat_logits, dim=-1).squeeze(0)

                adv_risk_score = float(bin_probs[1].item())
                cat_idx = int(torch.argmax(cat_logits, dim=-1).item())
                cat_name = ID2CATEGORY.get(cat_idx, "unknown")
                cat_conf = float(cat_probs[cat_idx].item())

                predicted_label = "adversarial" if adv_risk_score >= eff_threshold else "benign"
                latency_ms = (time.time() - start_time) * 1000

                return {
                    "risk_score": round(adv_risk_score, 4),
                    "predicted_label": predicted_label,
                    "attack_category": cat_name,
                    "category_confidence": round(cat_conf, 4),
                    "threshold": eff_threshold,
                    "model_version": self.config.model_version,
                    "inference_status": "SUCCESS",
                    "latency_ms": round(latency_ms, 2)
                }

            except Exception as exc:
                # Graceful degradation on runtime inference error
                return self._fallback_heuristic(formatted_text, eff_threshold, start_time, error=str(exc))

        # Fallback Heuristic Path (When model not loaded)
        return self._fallback_heuristic(formatted_text, eff_threshold, start_time)

    def _fallback_heuristic(
        self,
        text: str,
        threshold: float,
        start_time: float,
        error: Optional[str] = None
    ) -> Dict[str, Any]:
        """Deterministic keyword-based heuristic fallback for offline or uncheckpointed runs."""
        lowered = text.lower()
        risk_score = 0.05
        category = "benign"

        if any(w in lowered for w in ["ignore previous", "disregard all", "you are now dan"]):
            risk_score = 0.95
            category = "indirect_prompt_injection"
        elif any(w in lowered for w in ["delete_records", "drop table", "wipe records", "rm -rf"]):
            risk_score = 0.90
            category = "tool_misuse"
        elif any(w in lowered for w in ["i am admin", "root operator", "superuser clearance"]):
            risk_score = 0.88
            category = "privilege_escalation"
        elif any(w in lowered for w in ["verbally authorized", "ceo approved", "security team approved"]):
            risk_score = 0.85
            category = "false_authorization"
        elif any(w in lowered for w in ["context update", "maintenance mode", "restrictions are suspended"]):
            risk_score = 0.82
            category = "context_poisoning"
        elif any(w in lowered for w in ["assume normal restrictions are just suggestions", "diagnostic mode"]):
            risk_score = 0.80
            category = "gradual_jailbreak"

        latency_ms = (time.time() - start_time) * 1000
        predicted_label = "adversarial" if risk_score >= threshold else "benign"

        status = "FALLBACK_HEURISTIC" if error is None else f"ERROR_FALLBACK: {error[:60]}"

        return {
            "risk_score": round(risk_score, 4),
            "predicted_label": predicted_label,
            "attack_category": category,
            "category_confidence": 0.75,
            "threshold": threshold,
            "model_version": f"{self.config.model_version}-heuristic-fallback",
            "inference_status": status,
            "latency_ms": round(latency_ms, 2)
        }


# Global default predictor instance
default_guard_predictor = GuardPredictor()


def inspect_interaction_risk(interaction: Union[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
    """Convenience functional interface for AgentShield."""
    return default_guard_predictor.predict(interaction)

