import os
import sys
import pytest
import torch

# Ensure AgentShield root is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.guard.config import GuardConfig, CATEGORY_MAP, ID2CATEGORY, LABEL_MAP
from src.guard.dataset import GuardDatasetBuilder, format_multi_turn_dialogue
from src.guard.model import MultiTaskAgentShieldGuard
from src.guard.predict import GuardPredictor, inspect_interaction_risk
from src.guard.train import AgentShieldTorchDataset, calibrate_optimal_threshold
from src.agents.graph import run_agent
from src.security.policies import policy_engine


# -------------------------------------------------------------
# 1. Dataset Loading & Partitioning Integrity
# -------------------------------------------------------------
def test_dataset_loading_and_structure():
    """Verify dataset builder produces 7 categories with zero leakage across splits."""
    ds = GuardDatasetBuilder.build_dataset(seed=42, augment_train=True)
    assert "train" in ds and "val" in ds and "test" in ds
    assert len(ds["train"]) > 0
    assert len(ds["val"]) > 0
    assert len(ds["test"]) > 0

    train_fids = set(x["family_id"] for x in ds["train"])
    val_fids = set(x["family_id"] for x in ds["val"])
    test_fids = set(x["family_id"] for x in ds["test"])

    # Strict zero leakage assertion
    assert len(train_fids & val_fids) == 0
    assert len(train_fids & test_fids) == 0
    assert len(val_fids & test_fids) == 0


# -------------------------------------------------------------
# 2. Label & Category Mapping
# -------------------------------------------------------------
def test_label_and_category_mapping():
    """Verify bidirectional category and binary label consistency."""
    assert len(CATEGORY_MAP) == 7
    for cat_name, cat_id in CATEGORY_MAP.items():
        assert ID2CATEGORY[cat_id] == cat_name
    assert LABEL_MAP["benign"] == 0
    assert LABEL_MAP["adversarial"] == 1


# -------------------------------------------------------------
# 3. Tokenization & Dataset Tensor Shapes
# -------------------------------------------------------------
def test_tokenization_and_dataset_tensor_shapes():
    """Verify PyTorch dataset yields correct tensor shapes and types."""
    from transformers import AutoTokenizer
    tokenizer = AutoTokenizer.from_pretrained("distilbert-base-uncased")
    records = [
        {"formatted_text": "[TURN 1] [USER]: Hello assistant", "binary_label": 0, "category_id": 0, "sample_id": "s1"}
    ]
    ds = AgentShieldTorchDataset(records, tokenizer, max_length=128)
    item = ds[0]

    assert item["input_ids"].shape == (128,)
    assert item["attention_mask"].shape == (128,)
    assert item["binary_label"].item() == 0
    assert item["category_id"].item() == 0


# -------------------------------------------------------------
# 4. Multi-Task Model Forward Pass
# -------------------------------------------------------------
def test_model_architecture_and_forward_pass():
    """Verify model forward pass outputs dual logits of correct shape."""
    cfg = GuardConfig(num_categories=7, num_binary_classes=2)
    model = MultiTaskAgentShieldGuard(cfg)
    model.eval()

    dummy_input_ids = torch.randint(0, 1000, (2, 64))
    dummy_attention_mask = torch.ones((2, 64), dtype=torch.long)

    with torch.no_grad():
        bin_logits, cat_logits = model(dummy_input_ids, dummy_attention_mask)

    assert bin_logits.shape == (2, 2)
    assert cat_logits.shape == (2, 7)


# -------------------------------------------------------------
# 5. Threshold Calibration Behavior
# -------------------------------------------------------------
def test_calibrated_threshold_behavior():
    """Verify optimal threshold calibration selects boundary maximizing F1."""
    import numpy as np
    probs = np.array([0.1, 0.2, 0.6, 0.7, 0.8, 0.9])
    labels = np.array([0, 0, 1, 1, 1, 1])

    best_tau, stats = calibrate_optimal_threshold(probs, labels)
    assert 0.1 <= best_tau <= 0.9
    assert stats["f1"] > 0.8


# -------------------------------------------------------------
# 6. Empty Input Handling
# -------------------------------------------------------------
def test_empty_input_handling():
    """Verify blank input yields safe default risk score without crashing."""
    predictor = GuardPredictor()
    res = predictor.predict("")
    assert res["risk_score"] == 0.0
    assert res["predicted_label"] == "benign"
    assert res["inference_status"] == "EMPTY_INPUT"


# -------------------------------------------------------------
# 7. Malformed Inputs Handling
# -------------------------------------------------------------
def test_malformed_and_edge_case_inputs():
    """Verify unusual types and malformed dialogue sequences handle gracefully."""
    predictor = GuardPredictor()
    # List with non-standard dictionary
    res = predictor.predict([{"unexpected_key": 12345}])
    assert "risk_score" in res
    assert res["inference_status"] in ("SUCCESS", "FALLBACK_HEURISTIC")


# -------------------------------------------------------------
# 8. Long Input Truncation
# -------------------------------------------------------------
def test_long_input_truncation():
    """Verify input exceeding max length is truncated without raising exception."""
    predictor = GuardPredictor()
    long_text = "corporate policy " * 600
    res = predictor.predict(long_text)
    assert "risk_score" in res
    assert res["risk_score"] >= 0.0


# -------------------------------------------------------------
# 9. CPU Inference
# -------------------------------------------------------------
def test_cpu_inference():
    """Verify inference runs cleanly on CPU."""
    predictor = GuardPredictor(device=torch.device("cpu"))
    res = predictor.predict("Please search for invoice records.")
    assert "risk_score" in res
    assert res["predicted_label"] in ("benign", "adversarial")


# -------------------------------------------------------------
# 10. Guard Integration in Agent Graph
# -------------------------------------------------------------
def test_guard_integration_in_agent_graph():
    """Verify that run_agent executes the Guard node and records telemetry in state."""
    state = run_agent(
        user_request="Can you search our internal policy documents?",
        session_context={"user_role": "analyst", "user_id": "u1"},
        bypass_policy=False
    )
    assert "guard_output" in state
    assert state["guard_output"] is not None
    assert "risk_score" in state["guard_output"]
    assert "predicted_label" in state["guard_output"]


# -------------------------------------------------------------
# 11. Guard Failure Handling Graceful Degradation
# -------------------------------------------------------------
def test_guard_failure_handling_graceful_degradation():
    """Verify that if checkpoint dir is missing, predictor degrades to heuristic fallback."""
    predictor = GuardPredictor(checkpoint_dir="non_existent_directory_xyz_123")
    res = predictor.predict("Execute delete_records on users table.")
    assert res["risk_score"] > 0.5
    assert res["predicted_label"] == "adversarial"
    assert "FALLBACK_HEURISTIC" in res["inference_status"]


# -------------------------------------------------------------
# 12. Policy Enforcement Remains Independent of Guard
# -------------------------------------------------------------
def test_policy_enforcement_remains_independent_of_guard():
    """
    CRITICAL DEFENSE-IN-DEPTH INVARIANT:
    Even if the Guard assigns low risk score, the Policy Engine MUST independently deny unauthorized tools.
    """
    session = {"user_role": "analyst", "user_id": "u1"}
    decision = policy_engine.evaluate(
        tool_name="delete_records",
        tool_args={"record_id": "inv_001", "table": "invoices"},
        session_context=session
    )
    # Policy Engine denies based on RBAC regardless of any hypothetical Guard score
    assert decision.allowed is False
    assert decision.decision_code == "DENIED_RBAC_UNAUTHORIZED"
