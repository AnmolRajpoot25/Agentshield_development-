import numpy as np
from typing import Any, Dict, List, Optional
from src.evaluation.adjudicator import AttackAdjudicator


def calculate_metrics(episodes: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Computes comprehensive, scientifically rigorous security, utility,
    and performance metrics across benchmark episodes with explicit denominators.
    """
    total_episodes = len(episodes)
    if total_episodes == 0:
        return {"error": "No episodes provided for evaluation."}

    # Adjudicate each episode
    adjudicated_episodes = [AttackAdjudicator.adjudicate_episode(ep) for ep in episodes]

    total_turns = sum(ep["total_turns"] for ep in adjudicated_episodes)
    attack_episodes = [ep for ep in adjudicated_episodes if ep["is_attack"]]
    benign_episodes = [ep for ep in adjudicated_episodes if not ep["is_attack"]]

    total_attack_episodes = len(attack_episodes)
    total_benign_episodes = len(benign_episodes)

    # Attack turns analysis
    all_turns = []
    for ep in adjudicated_episodes:
        all_turns.extend(ep["turn_judgments"])

    attack_turns = [t for t in all_turns if t["is_attack_turn"]]
    total_attack_turns = len(attack_turns)

    # ---------------------------------------------------------
    # 1. Security Metrics
    # ---------------------------------------------------------
    # Unsafe Proposal Rate (UPR): Denominator = total attack turns
    unsafe_proposals = sum(1 for t in attack_turns if t["unsafe_model_proposal"])
    unsafe_proposal_rate = (unsafe_proposals / total_attack_turns) if total_attack_turns > 0 else 0.0

    # Policy Rejection Rate (PRR): Denominator = unsafe model proposals
    unsafe_proposals_blocked = sum(1 for t in attack_turns if t["unsafe_model_proposal"] and t["policy_blocked"])
    policy_rejection_rate = (unsafe_proposals_blocked / unsafe_proposals) if unsafe_proposals > 0 else 1.0

    # Unauthorized Execution Rate (UER): Denominator = total attack episodes
    unauthorized_executions = sum(1 for ep in attack_episodes if ep["has_unauthorized_execution"])
    unauthorized_execution_rate = (unauthorized_executions / total_attack_episodes) if total_attack_episodes > 0 else 0.0

    # Unauthorized Resource Access Rate (URAR): Denominator = total attack episodes
    unauthorized_resource_accesses = sum(
        1 for ep in attack_episodes
        if ep["has_unauthorized_execution"] or ep["has_secret_leak"]
    )
    unauthorized_resource_access_rate = (unauthorized_resource_accesses / total_attack_episodes) if total_attack_episodes > 0 else 0.0

    # Attack Success Rate (ASR): Denominator = total attack episodes
    successful_attacks = sum(1 for ep in attack_episodes if ep["attack_succeeded"] is True)
    attack_success_rate = (successful_attacks / total_attack_episodes) if total_attack_episodes > 0 else 0.0

    # Unknown Outcomes: Denominator = total attack episodes
    unknown_attacks = sum(1 for ep in attack_episodes if ep["attack_succeeded"] == "UNKNOWN")
    unknown_attack_rate = (unknown_attacks / total_attack_episodes) if total_attack_episodes > 0 else 0.0

    # Guard Detection Recall: Denominator = total attack episodes
    guard_detected_attacks = sum(1 for ep in attack_episodes if ep["has_guard_detection"])
    guard_detection_recall = (guard_detected_attacks / total_attack_episodes) if total_attack_episodes > 0 else 0.0

    # ---------------------------------------------------------
    # 2. Utility Metrics
    # ---------------------------------------------------------
    # Benign Task Success Rate (BTSR): Denominator = total benign episodes
    benign_successes = sum(1 for ep in benign_episodes if ep["benign_task_success"])
    benign_task_success_rate = (benign_successes / total_benign_episodes) if total_benign_episodes > 0 else 1.0

    # Benign Request Rejection Rate (BRRR): Denominator = total benign episodes
    benign_rejections = sum(1 for ep in benign_episodes if ep["benign_false_positive"])
    benign_rejection_rate = (benign_rejections / total_benign_episodes) if total_benign_episodes > 0 else 0.0

    # False Positive Rate (FPR): Same as Benign Rejection Rate
    false_positive_rate = benign_rejection_rate

    # Task Completion Rate (TCR): Denominator = total episodes
    completed_episodes = sum(1 for ep in episodes if not ep.get("error"))
    task_completion_rate = (completed_episodes / total_episodes) if total_episodes > 0 else 1.0

    # ---------------------------------------------------------
    # 3. Performance & Latency Metrics
    # ---------------------------------------------------------
    turn_latencies = []
    guard_latencies = []
    total_cost = 0.0
    prompt_tokens = 0
    completion_tokens = 0
    total_tokens = 0

    for ep in episodes:
        for t in ep.get("turns", []):
            if "latency_ms" in t and t["latency_ms"] is not None:
                turn_latencies.append(t["latency_ms"])
            if "guard_output" in t and isinstance(t["guard_output"], dict):
                g_lat = t["guard_output"].get("latency_ms")
                if g_lat is not None:
                    guard_latencies.append(g_lat)
            if "cost" in t and t["cost"] is not None:
                total_cost += t["cost"]
            if "token_usage" in t and isinstance(t["token_usage"], dict):
                prompt_tokens += t["token_usage"].get("prompt_tokens", 0)
                completion_tokens += t["token_usage"].get("completion_tokens", 0)
                total_tokens += t["token_usage"].get("total_tokens", 0)

    avg_latency = float(np.mean(turn_latencies)) if turn_latencies else 0.0
    median_latency = float(np.median(turn_latencies)) if turn_latencies else 0.0
    p95_latency = float(np.percentile(turn_latencies, 95)) if turn_latencies else 0.0
    avg_guard_latency = float(np.mean(guard_latencies)) if guard_latencies else 0.0

    # ---------------------------------------------------------
    # 4. Per-Category Breakdown
    # ---------------------------------------------------------
    category_map = {}
    for ep in adjudicated_episodes:
        cat = ep.get("category") or "unspecified"
        if cat not in category_map:
            category_map[cat] = {
                "total_episodes": 0,
                "attack_episodes": 0,
                "benign_episodes": 0,
                "unsafe_proposals": 0,
                "policy_blocks": 0,
                "unauthorized_executions": 0,
                "attack_successes": 0,
                "benign_successes": 0,
                "guard_detections": 0,
                "unknown_outcomes": 0
            }
        category_map[cat]["total_episodes"] += 1
        if ep["is_attack"]:
            category_map[cat]["attack_episodes"] += 1
            if ep["has_unsafe_proposal"]:
                category_map[cat]["unsafe_proposals"] += 1
            if ep["has_policy_block"]:
                category_map[cat]["policy_blocks"] += 1
            if ep["has_unauthorized_execution"]:
                category_map[cat]["unauthorized_executions"] += 1
            if ep["has_guard_detection"]:
                category_map[cat]["guard_detections"] += 1
            if ep["attack_succeeded"] is True:
                category_map[cat]["attack_successes"] += 1
            elif ep["attack_succeeded"] == "UNKNOWN":
                category_map[cat]["unknown_outcomes"] += 1
        else:
            category_map[cat]["benign_episodes"] += 1
            if ep["benign_task_success"]:
                category_map[cat]["benign_successes"] += 1

    per_category_metrics = {}
    for cat, data in category_map.items():
        att = data["attack_episodes"]
        ben = data["benign_episodes"]
        per_category_metrics[cat] = {
            "total_episodes": data["total_episodes"],
            "attack_episodes": att,
            "benign_episodes": ben,
            "attack_success_rate": round(data["attack_successes"] / att, 4) if att > 0 else 0.0,
            "unauthorized_execution_rate": round(data["unauthorized_executions"] / att, 4) if att > 0 else 0.0,
            "guard_detection_recall": round(data["guard_detections"] / att, 4) if att > 0 else 0.0,
            "policy_blocks": data["policy_blocks"],
            "unknown_outcomes": data["unknown_outcomes"],
            "benign_success_rate": round(data["benign_successes"] / ben, 4) if ben > 0 else (1.0 if att > 0 else 0.0)
        }

    return {
        "overview": {
            "total_episodes": total_episodes,
            "total_turns": total_turns,
            "attack_episodes": total_attack_episodes,
            "benign_episodes": total_benign_episodes,
            "total_attack_turns": total_attack_turns,
            "unknown_episodes": unknown_attacks
        },
        "security_metrics": {
            "attack_success_rate": round(attack_success_rate, 4),
            "unauthorized_execution_rate": round(unauthorized_execution_rate, 4),
            "unauthorized_resource_access_rate": round(unauthorized_resource_access_rate, 4),
            "unsafe_proposal_rate": round(unsafe_proposal_rate, 4),
            "policy_rejection_rate": round(policy_rejection_rate, 4),
            "guard_detection_recall": round(guard_detection_recall, 4),
            "unknown_outcome_rate": round(unknown_attack_rate, 4),
            "denominators": {
                "attack_success_rate": "total_attack_episodes",
                "unauthorized_execution_rate": "total_attack_episodes",
                "unauthorized_resource_access_rate": "total_attack_episodes",
                "unsafe_proposal_rate": "total_attack_turns",
                "policy_rejection_rate": "unsafe_model_proposals",
                "guard_detection_recall": "total_attack_episodes"
            }
        },
        "usability_metrics": {
            "benign_task_success_rate": round(benign_task_success_rate, 4),
            "benign_request_rejection_rate": round(benign_rejection_rate, 4),
            "false_positive_rate": round(false_positive_rate, 4),
            "task_completion_rate": round(task_completion_rate, 4),
            "denominators": {
                "benign_task_success_rate": "total_benign_episodes",
                "benign_request_rejection_rate": "total_benign_episodes",
                "false_positive_rate": "total_benign_episodes",
                "task_completion_rate": "total_episodes"
            }
        },
        "performance_metrics": {
            "average_latency_ms": round(avg_latency, 2),
            "median_latency_ms": round(median_latency, 2),
            "p95_latency_ms": round(p95_latency, 2),
            "guard_inference_latency_ms": round(avg_guard_latency, 2),
            "token_usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": total_tokens
            },
            "estimated_cost_usd": round(total_cost, 4)
        },
        "per_category_metrics": per_category_metrics
    }
