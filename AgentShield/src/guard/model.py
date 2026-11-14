import json
import os
from typing import Dict, Optional, Tuple, Any

import torch
import torch.nn as nn
from transformers import AutoModel, AutoConfig

from src.guard.config import GuardConfig


class MultiTaskAgentShieldGuard(nn.Module):
    """
    Multi-Task Transformer Guardrail for AgentShield:
    - Shared Backbone: DistilBERT contextual representation
    - Head 1: Binary Classification (0 = Benign, 1 = Adversarial Intent)
    - Head 2: Multi-Class Classification (7 Attack Categories)
    """

    def __init__(self, config: Optional[GuardConfig] = None):
        super().__init__()
        self.config = config or GuardConfig()
        
        # Load backbone
        self.backbone = AutoModel.from_pretrained(self.config.base_model_name)
        hidden_dim = self.backbone.config.hidden_size
        
        self.dropout = nn.Dropout(self.config.dropout_prob)
        
        # Head 1: Binary classification (Benign vs Adversarial)
        self.binary_classifier = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(self.config.dropout_prob),
            nn.Linear(hidden_dim // 2, self.config.num_binary_classes)
        )
        
        # Head 2: Multi-class category classification (7 attack categories)
        self.category_classifier = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(self.config.dropout_prob),
            nn.Linear(hidden_dim // 2, self.config.num_categories)
        )

    def forward(
        self,
        input_ids: torch.Tensor,
        attention_mask: torch.Tensor
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Forward pass producing binary intent logits and category logits.
        Returns:
            binary_logits: (batch_size, 2)
            category_logits: (batch_size, num_categories)
        """
        outputs = self.backbone(input_ids=input_ids, attention_mask=attention_mask)
        # Extract representation from the [CLS] token (index 0)
        cls_rep = outputs.last_hidden_state[:, 0, :]
        cls_rep = self.dropout(cls_rep)
        
        binary_logits = self.binary_classifier(cls_rep)
        category_logits = self.category_classifier(cls_rep)
        
        return binary_logits, category_logits

    def save_pretrained(self, save_directory: str):
        """Saves model weights and configuration metadata to directory."""
        os.makedirs(save_directory, exist_ok=True)
        model_path = os.path.join(save_directory, "pytorch_model.bin")
        torch.save(self.state_dict(), model_path)
        
        config_path = os.path.join(save_directory, "guard_config.json")
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(self.config.to_dict(), f, indent=2)

    @classmethod
    def from_pretrained(cls, load_directory: str, device: Optional[torch.device] = None) -> "MultiTaskAgentShieldGuard":
        """Loads a saved checkpoint and configuration."""
        config_path = os.path.join(load_directory, "guard_config.json")
        if os.path.exists(config_path):
            with open(config_path, "r", encoding="utf-8") as f:
                cfg_dict = json.load(f)
            config = GuardConfig(
                base_model_name=cfg_dict.get("base_model_name", "distilbert-base-uncased"),
                num_categories=cfg_dict.get("num_categories", 7),
                num_binary_classes=cfg_dict.get("num_binary_classes", 2),
                max_seq_length=cfg_dict.get("max_seq_length", 256),
                dropout_prob=cfg_dict.get("dropout_prob", 0.2),
                calibrated_threshold=cfg_dict.get("calibrated_threshold", 0.5),
                model_version=cfg_dict.get("model_version", "v3.0.0-distilbert-multitask")
            )
        else:
            config = GuardConfig()
            
        model = cls(config=config)
        model_path = os.path.join(load_directory, "pytorch_model.bin")
        if os.path.exists(model_path):
            state_dict = torch.load(model_path, map_location=device or torch.device("cpu"), weights_only=True)
            model.load_state_dict(state_dict)
            
        if device:
            model.to(device)
            
        return model
