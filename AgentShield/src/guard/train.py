import copy
from datetime import datetime, timezone
import json
import os
import random
from typing import Dict, List, Optional, Tuple, Any

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from transformers import AutoTokenizer, get_linear_schedule_with_warmup

from src.guard.config import GuardConfig, CATEGORY_MAP, ID2CATEGORY, LABEL_MAP
from src.guard.dataset import GuardDatasetBuilder
from src.guard.model import MultiTaskAgentShieldGuard


class AgentShieldTorchDataset(Dataset):
    """PyTorch Dataset for multi-task AgentShield Guard training."""

    def __init__(self, records: List[Dict[str, Any]], tokenizer, max_length: int = 256):
        self.records = records
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __len__(self) -> int:
        return len(self.records)

    def __getitem__(self, idx: int) -> Dict[str, torch.Tensor]:
        rec = self.records[idx]
        text = rec["formatted_text"]
        
        encoding = self.tokenizer(
            text,
            truncation=True,
            max_length=self.max_length,
            padding="max_length",
            return_tensors="pt"
        )
        
        return {
            "input_ids": encoding["input_ids"].squeeze(0),
            "attention_mask": encoding["attention_mask"].squeeze(0),
            "binary_label": torch.tensor(rec["binary_label"], dtype=torch.long),
            "category_id": torch.tensor(rec["category_id"], dtype=torch.long),
            "sample_id": rec.get("sample_id", f"sample_{idx}")
        }


def calibrate_optimal_threshold(
    val_probs: np.ndarray,
    val_labels: np.ndarray,
    target_recall: float = 0.95
) -> Tuple[float, Dict[str, float]]:
    """
    Calibrates decision threshold on validation data to maximize F1 score
    while prioritizing adversarial detection recall.
    """
    best_f1 = -1.0
    best_thresh = 0.50
    best_stats = {}

    for thresh in np.arange(0.10, 0.90, 0.05):
        preds = (val_probs >= thresh).astype(int)
        
        tp = np.sum((preds == 1) & (val_labels == 1))
        fp = np.sum((preds == 1) & (val_labels == 0))
        fn = np.sum((preds == 0) & (val_labels == 1))
        tn = np.sum((preds == 0) & (val_labels == 0))
        
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        # Optimize for best F1 subject to high recall
        if f1 > best_f1:
            best_f1 = f1
            best_thresh = float(round(thresh, 2))
            best_stats = {
                "threshold": best_thresh,
                "precision": float(round(prec, 4)),
                "recall": float(round(rec, 4)),
                "f1": float(round(f1, 4)),
                "fpr": float(round(fpr, 4))
            }

    return best_thresh, best_stats


def train_guard_model(
    config: Optional[GuardConfig] = None,
    dataset: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    device: Optional[torch.device] = None
) -> Tuple[MultiTaskAgentShieldGuard, Dict[str, Any]]:
    """
    Executes full multi-task training pipeline with early stopping and threshold calibration.
    """
    cfg = config or GuardConfig()
    
    # 1. Deterministic Seeding
    random.seed(cfg.seed)
    np.random.seed(cfg.seed)
    torch.manual_seed(cfg.seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(cfg.seed)

    # 2. Device Selection
    if device is None:
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"[AgentShield Guard Training] Executing on device: {device}")

    # 3. Load or Build Dataset
    if dataset is None:
        print("[AgentShield Guard Training] Building dataset with grouped stratification...")
        dataset = GuardDatasetBuilder.build_dataset(seed=cfg.seed, augment_train=True)

    # 4. Initialize Tokenizer & Model
    print(f"[AgentShield Guard Training] Initializing tokenizer & backbone: {cfg.base_model_name}")
    tokenizer = AutoTokenizer.from_pretrained(cfg.base_model_name)
    model = MultiTaskAgentShieldGuard(config=cfg)
    model.to(device)

    # 5. DataLoaders
    train_dataset = AgentShieldTorchDataset(dataset["train"], tokenizer, cfg.max_seq_length)
    val_dataset = AgentShieldTorchDataset(dataset["val"], tokenizer, cfg.max_seq_length)

    train_loader = DataLoader(train_dataset, batch_size=cfg.batch_size, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=cfg.batch_size, shuffle=False)

    # 6. Optimizer & Loss Functions
    optimizer = torch.optim.AdamW(
        model.parameters(),
        lr=cfg.learning_rate,
        weight_decay=cfg.weight_decay
    )
    total_steps = len(train_loader) * cfg.epochs
    warmup_steps = int(total_steps * cfg.warmup_ratio)
    scheduler = get_linear_schedule_with_warmup(
        optimizer,
        num_warmup_steps=warmup_steps,
        num_training_steps=total_steps
    )

    criterion_bin = nn.CrossEntropyLoss()
    criterion_cat = nn.CrossEntropyLoss()

    best_val_loss = float("inf")
    patience_counter = 0
    training_history = []
    best_model_state = None

    print(f"[AgentShield Guard Training] Starting training: {cfg.epochs} epochs, {len(train_dataset)} train samples, {len(val_dataset)} val samples")

    for epoch in range(1, cfg.epochs + 1):
        # --- TRAINING PHASE ---
        model.train()
        total_train_loss = 0.0

        for batch in train_loader:
            optimizer.zero_grad()
            
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            bin_labels = batch["binary_label"].to(device)
            cat_labels = batch["category_id"].to(device)

            bin_logits, cat_logits = model(input_ids, attention_mask)

            loss_bin = criterion_bin(bin_logits, bin_labels)
            loss_cat = criterion_cat(cat_logits, cat_labels)
            total_loss = cfg.binary_loss_weight * loss_bin + cfg.category_loss_weight * loss_cat

            total_loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()
            scheduler.step()

            total_train_loss += total_loss.item()

        avg_train_loss = total_train_loss / max(1, len(train_loader))

        # --- VALIDATION PHASE ---
        model.eval()
        total_val_loss = 0.0
        val_bin_correct = 0
        val_cat_correct = 0
        val_bin_probs_list = []
        val_bin_labels_list = []

        with torch.no_grad():
            for batch in val_loader:
                input_ids = batch["input_ids"].to(device)
                attention_mask = batch["attention_mask"].to(device)
                bin_labels = batch["binary_label"].to(device)
                cat_labels = batch["category_id"].to(device)

                bin_logits, cat_logits = model(input_ids, attention_mask)
                
                loss_bin = criterion_bin(bin_logits, bin_labels)
                loss_cat = criterion_cat(cat_logits, cat_labels)
                val_loss = cfg.binary_loss_weight * loss_bin + cfg.category_loss_weight * loss_cat
                total_val_loss += val_loss.item()

                # Accuracy metrics
                probs = torch.softmax(bin_logits, dim=-1)
                bin_preds = torch.argmax(bin_logits, dim=-1)
                cat_preds = torch.argmax(cat_logits, dim=-1)

                val_bin_correct += (bin_preds == bin_labels).sum().item()
                val_cat_correct += (cat_preds == cat_labels).sum().item()

                val_bin_probs_list.extend(probs[:, 1].cpu().numpy())
                val_bin_labels_list.extend(bin_labels.cpu().numpy())

        avg_val_loss = total_val_loss / max(1, len(val_loader))
        val_bin_acc = val_bin_correct / max(1, len(val_dataset))
        val_cat_acc = val_cat_correct / max(1, len(val_dataset))

        print(f"Epoch {epoch}/{cfg.epochs} | Train Loss: {avg_train_loss:.4f} | Val Loss: {avg_val_loss:.4f} | Val Bin Acc: {val_bin_acc:.4f} | Val Cat Acc: {val_cat_acc:.4f}")

        training_history.append({
            "epoch": epoch,
            "train_loss": avg_train_loss,
            "val_loss": avg_val_loss,
            "val_bin_acc": val_bin_acc,
            "val_cat_acc": val_cat_acc
        })

        if avg_val_loss < best_val_loss:
            best_val_loss = avg_val_loss
            patience_counter = 0
            best_model_state = copy.deepcopy(model.state_dict())
        else:
            patience_counter += 1
            if patience_counter >= cfg.early_stopping_patience:
                print(f"[AgentShield Guard Training] Early stopping triggered at epoch {epoch}")
                break

    # Restore best checkpoint
    if best_model_state is not None:
        model.load_state_dict(best_model_state)

    # 7. Validation Threshold Calibration
    val_probs_arr = np.array(val_bin_probs_list)
    val_labels_arr = np.array(val_bin_labels_list)
    calibrated_tau, calib_stats = calibrate_optimal_threshold(val_probs_arr, val_labels_arr)
    cfg.calibrated_threshold = calibrated_tau
    print(f"[AgentShield Guard Calibration] Optimal threshold tau*: {calibrated_tau} (Val F1: {calib_stats.get('f1', 0):.4f})")

    # 8. Save Model & Artifacts
    save_dir = cfg.checkpoint_dir
    os.makedirs(save_dir, exist_ok=True)
    print(f"[AgentShield Guard Training] Saving checkpoint artifacts to: {save_dir}")
    model.save_pretrained(save_dir)
    tokenizer.save_pretrained(save_dir)

    metadata = {
        "model_version": cfg.model_version,
        "base_model": cfg.base_model_name,
        "trained_timestamp": datetime.now(timezone.utc).isoformat(),
        "device": str(device),
        "epochs_trained": len(training_history),
        "best_val_loss": float(round(best_val_loss, 4)),
        "calibrated_threshold": calibrated_tau,
        "calibration_stats": calib_stats,
        "training_history": training_history,
        "categories": ID2CATEGORY,
        "labels": LABEL_MAP
    }
    with open(os.path.join(save_dir, "model_metadata.json"), "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    return model, metadata


if __name__ == "__main__":
    train_guard_model()
