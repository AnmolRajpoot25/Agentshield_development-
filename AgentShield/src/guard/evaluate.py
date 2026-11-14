import csv
from datetime import datetime, timezone
import json
import os
from typing import Dict, List, Optional, Tuple, Any

import numpy as np
import torch
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    roc_auc_score,
    precision_recall_curve,
    auc
)

from src.guard.config import GuardConfig, CATEGORY_MAP, ID2CATEGORY, LABEL_MAP
from src.guard.dataset import GuardDatasetBuilder
from src.guard.predict import GuardPredictor


def evaluate_test_set(
    predictor: Optional[GuardPredictor] = None,
    dataset: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    config: Optional[GuardConfig] = None,
    output_dir: Optional[str] = None
) -> Dict[str, Any]:
    """
    Evaluates Guard model on the independent untouched test set.
    Outputs metrics JSON, predictions CSV, and generates evaluation report.
    """
    cfg = config or GuardConfig()
    pred_engine = predictor or GuardPredictor(config=cfg)
    out_dir = output_dir or cfg.results_dir
    os.makedirs(out_dir, exist_ok=True)

    if dataset is None:
        dataset = GuardDatasetBuilder.build_dataset(seed=cfg.seed, augment_train=False)

    test_samples = dataset["test"]
    print(f"[AgentShield Guard Evaluation] Evaluating on {len(test_samples)} untouched test samples...")

    y_bin_true = []
    y_bin_pred = []
    y_bin_probs = []
    y_cat_true = []
    y_cat_pred = []
    predictions_rows = []

    for item in test_samples:
        text = item["formatted_text"]
        true_bin = item["binary_label"]
        true_cat = item["category"]
        true_cat_id = item["category_id"]

        pred_res = pred_engine.predict(text)
        prob = pred_res["risk_score"]
        pred_bin = 1 if pred_res["predicted_label"] == "adversarial" else 0
        pred_cat_name = pred_res["attack_category"]
        pred_cat_id = CATEGORY_MAP.get(pred_cat_name, 0)

        y_bin_true.append(true_bin)
        y_bin_pred.append(pred_bin)
        y_bin_probs.append(prob)
        y_cat_true.append(true_cat_id)
        y_cat_pred.append(pred_cat_id)

        predictions_rows.append({
            "sample_id": item["sample_id"],
            "family_id": item["family_id"],
            "true_category": true_cat,
            "true_binary_label": true_bin,
            "predicted_binary_label": pred_bin,
            "predicted_category": pred_cat_name,
            "risk_score": prob,
            "threshold": pred_res["threshold"],
            "inference_status": pred_res["inference_status"],
            "latency_ms": pred_res["latency_ms"]
        })

    y_bin_true_arr = np.array(y_bin_true)
    y_bin_pred_arr = np.array(y_bin_pred)
    y_bin_probs_arr = np.array(y_bin_probs)
    y_cat_true_arr = np.array(y_cat_true)
    y_cat_pred_arr = np.array(y_cat_pred)

    # 1. Binary Intent Metrics
    bin_acc = float(accuracy_score(y_bin_true_arr, y_bin_pred_arr))
    bin_prec = float(precision_score(y_bin_true_arr, y_bin_pred_arr, zero_division=0))
    bin_rec = float(recall_score(y_bin_true_arr, y_bin_pred_arr, zero_division=0))
    bin_f1 = float(f1_score(y_bin_true_arr, y_bin_pred_arr, zero_division=0))

    # Confusion matrix
    cm_bin = confusion_matrix(y_bin_true_arr, y_bin_pred_arr, labels=[0, 1])
    tn, fp, fn, tp = int(cm_bin[0, 0]), int(cm_bin[0, 1]), int(cm_bin[1, 0]), int(cm_bin[1, 1])
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

    # ROC-AUC & PR-AUC
    try:
        bin_roc_auc = float(roc_auc_score(y_bin_true_arr, y_bin_probs_arr))
    except Exception:
        bin_roc_auc = 0.5

    try:
        precisions, recalls, _ = precision_recall_curve(y_bin_true_arr, y_bin_probs_arr)
        bin_pr_auc = float(auc(recalls, precisions))
    except Exception:
        bin_pr_auc = 0.5

    # 2. Multi-Class Category Metrics
    cat_acc = float(accuracy_score(y_cat_true_arr, y_cat_pred_arr))
    cat_macro_f1 = float(f1_score(y_cat_true_arr, y_cat_pred_arr, average="macro", zero_division=0))
    cat_weighted_f1 = float(f1_score(y_cat_true_arr, y_cat_pred_arr, average="weighted", zero_division=0))

    per_category = {}
    for cat_name, cat_id in CATEGORY_MAP.items():
        mask_true = (y_cat_true_arr == cat_id)
        mask_pred = (y_cat_pred_arr == cat_id)
        c_tp = int(np.sum(mask_true & mask_pred))
        c_fp = int(np.sum(~mask_true & mask_pred))
        c_fn = int(np.sum(mask_true & ~mask_pred))
        c_prec = c_tp / (c_tp + c_fp) if (c_tp + c_fp) > 0 else 0.0
        c_rec = c_tp / (c_tp + c_fn) if (c_tp + c_fn) > 0 else 0.0
        c_f1 = 2 * c_prec * c_rec / (c_prec + c_rec) if (c_prec + c_rec) > 0 else 0.0
        per_category[cat_name] = {
            "category_id": cat_id,
            "support": int(np.sum(mask_true)),
            "precision": float(round(c_prec, 4)),
            "recall": float(round(c_rec, 4)),
            "f1": float(round(c_f1, 4))
        }

    # Aggregate Evaluation Metrics Dict
    metrics = {
        "evaluation_timestamp": datetime.now(timezone.utc).isoformat(),
        "model_version": pred_engine.config.model_version,
        "test_samples_count": len(test_samples),
        "calibrated_threshold": pred_engine.threshold,
        "binary_intent": {
            "accuracy": float(round(bin_acc, 4)),
            "precision": float(round(bin_prec, 4)),
            "recall": float(round(bin_rec, 4)),
            "f1_score": float(round(bin_f1, 4)),
            "roc_auc": float(round(bin_roc_auc, 4)),
            "pr_auc": float(round(bin_pr_auc, 4)),
            "false_positive_rate": float(round(fpr, 4)),
            "false_negative_rate": float(round(fnr, 4)),
            "confusion_matrix": {
                "true_negative": tn,
                "false_positive": fp,
                "false_negative": fn,
                "true_positive": tp
            }
        },
        "attack_category": {
            "accuracy": float(round(cat_acc, 4)),
            "macro_f1": float(round(cat_macro_f1, 4)),
            "weighted_f1": float(round(cat_weighted_f1, 4)),
            "per_category": per_category
        }
    }

    # Export results/guard_metrics.json
    metrics_path = os.path.join(out_dir, "guard_metrics.json")
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    print(f"[AgentShield Guard Evaluation] Exported metrics to: {metrics_path}")

    # Export results/guard_predictions.csv
    csv_path = os.path.join(out_dir, "guard_predictions.csv")
    if predictions_rows:
        fieldnames = list(predictions_rows[0].keys())
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(predictions_rows)
    print(f"[AgentShield Guard Evaluation] Exported predictions to: {csv_path}")

    return metrics


if __name__ == "__main__":
    evaluate_test_set()

