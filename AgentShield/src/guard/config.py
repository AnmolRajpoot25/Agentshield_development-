from dataclasses import dataclass, field
import os
from typing import Dict, Any


CATEGORY_MAP: Dict[str, int] = {
    "benign": 0,
    "gradual_jailbreak": 1,
    "indirect_prompt_injection": 2,
    "tool_misuse": 3,
    "context_poisoning": 4,
    "false_authorization": 5,
    "privilege_escalation": 6
}

ID2CATEGORY: Dict[int, str] = {v: k for k, v in CATEGORY_MAP.items()}

LABEL_MAP: Dict[str, int] = {
    "benign": 0,
    "adversarial": 1
}

ID2LABEL: Dict[int, str] = {v: k for k, v in LABEL_MAP.items()}


@dataclass
class GuardConfig:
    """Configuration parameters for the AgentShield Guard model, training, and inference."""
    
    # Model Architecture
    base_model_name: str = "distilbert-base-uncased"
    num_categories: int = len(CATEGORY_MAP)
    num_binary_classes: int = 2
    max_seq_length: int = 256
    dropout_prob: float = 0.2
    hidden_dim: int = 768

    # Training Hyperparameters
    learning_rate: float = 3e-5
    batch_size: int = 8
    epochs: int = 3
    weight_decay: float = 0.01
    warmup_ratio: float = 0.1
    seed: int = 42
    early_stopping_patience: int = 2
    binary_loss_weight: float = 1.0
    category_loss_weight: float = 0.8

    # Calibration & Inference
    calibrated_threshold: float = 0.5
    model_version: str = "v3.0.0-distilbert-multitask"
    
    # File Paths (relative to AgentShield root)
    dataset_path: str = "datasets/processed/guard_dataset_v3.jsonl"
    checkpoint_dir: str = "checkpoints/agentshield_guard"
    results_dir: str = "results"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "base_model_name": self.base_model_name,
            "num_categories": self.num_categories,
            "num_binary_classes": self.num_binary_classes,
            "max_seq_length": self.max_seq_length,
            "dropout_prob": self.dropout_prob,
            "learning_rate": self.learning_rate,
            "batch_size": self.batch_size,
            "epochs": self.epochs,
            "seed": self.seed,
            "calibrated_threshold": self.calibrated_threshold,
            "model_version": self.model_version,
            "category_map": CATEGORY_MAP,
            "label_map": LABEL_MAP
        }

