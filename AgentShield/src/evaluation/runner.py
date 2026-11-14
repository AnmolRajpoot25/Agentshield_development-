import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import random
import sys
from typing import Any, Dict, List, Optional
import uuid

# Ensure AgentShield package root is in sys.path
_AGENTSHIELD_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_AGENTSHIELD_ROOT) not in sys.path:
    sys.path.insert(0, str(_AGENTSHIELD_ROOT))

from src.agents.graph import run_agent
from src.agents.baseline import VulnerableBaselineAgent
from src.guard.predict import inspect_interaction_risk
from src.evaluation.metrics import calculate_metrics
from src.tracing.logger import log_event, get_base_dir
from src.tools.registry import reset_database

BASE = get_base_dir()
DATASET_FILE = BASE / "datasets/adversarial/seed_scenarios.jsonl"
FULL_BENCHMARK_FILE = BASE / "datasets/adversarial/benchmark_v4.jsonl"
LEGACY_BENCHMARK_FILE = BASE / "datasets/adversarial/full_benchmark.jsonl"
RESULTS_DIR = BASE / "results"

RESULTS_DIR.mkdir(parents=True, exist_ok=True)


def load_scenarios(benchmark_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Loads benchmark scenarios from JSONL file."""
    if benchmark_path:
        target_path = Path(benchmark_path)
    elif FULL_BENCHMARK_FILE.exists():
        target_path = FULL_BENCHMARK_FILE
    elif LEGACY_BENCHMARK_FILE.exists():
        target_path = LEGACY_BENCHMARK_FILE
    else:
        target_path = DATASET_FILE

    with target_path.open("r", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def run_scenario(
    scenario: Dict[str, Any],
    config_mode: str = "combined_agentshield",
    user_role: Optional[str] = None
) -> Dict[str, Any]:
    """
    Executes a multi-turn scenario under one of four rigorous configurations:
    1. 'vulnerable_baseline': Guard disabled, Policy disabled (Bypass policy)
    2. 'policy_only': Guard disabled, Policy enabled (Protected runtime without Guard)
    3. 'guard_only': Guard enabled, Policy disabled (Bypass policy with Guard telemetry)
    4. 'combined_agentshield': Guard enabled, Policy enabled (Full defense-in-depth)
    """
    # Normalize mode names
    mode = config_mode.lower().strip()
    if mode in ("baseline_unprotected", "baseline"):
        mode = "vulnerable_baseline"
    elif mode in ("agentshield", "protected"):
        mode = "combined_agentshield"

    # Reset database to pristine state for independent, reproducible evaluation
    reset_database()

    episode_id = str(uuid.uuid4())
    messages = []
    turn_results = []
    untrusted_context_sources = []

    session_context = {
        "user_id": scenario.get("user_id", "user_analyst_01"),
        "user_role": user_role or scenario.get("user_role", "analyst")
    }

    turns = scenario.get("conversation_turns") or scenario.get("turns", [])

    for turn_number, user_message in enumerate(turns, start=1):
        guard_output = None

        if mode == "vulnerable_baseline":
            # Config 1: Vulnerable baseline, no policy, no guard
            result = VulnerableBaselineAgent.invoke(
                user_request=user_message,
                episode_id=episode_id,
                messages=messages,
                turn_number=turn_number,
                session_context=session_context
            )
        elif mode == "guard_only":
            # Config 2: Guard telemetry active, but policy engine disabled
            # Evaluate Guard
            turns_for_guard = list(messages) + [{"role": "user", "text": user_message}]
            guard_output = inspect_interaction_risk(turns_for_guard)
            
            # Execute on vulnerable baseline
            result = VulnerableBaselineAgent.invoke(
                user_request=user_message,
                episode_id=episode_id,
                messages=messages,
                turn_number=turn_number,
                session_context=session_context
            )
            result["guard_output"] = guard_output
        elif mode == "policy_only":
            # Config 3: Policy active, but Guard telemetry disabled
            result = run_agent(
                user_request=user_message,
                episode_id=episode_id,
                scenario_id=scenario.get("scenario_id"),
                messages=messages,
                turn_number=turn_number,
                session_context=session_context,
                bypass_policy=False,
                untrusted_context_sources=untrusted_context_sources
            )
            # Suppress guard output
            result["guard_output"] = None
        else:
            # Config 4: Combined AgentShield (Full Defense-in-Depth)
            result = run_agent(
                user_request=user_message,
                episode_id=episode_id,
                scenario_id=scenario.get("scenario_id"),
                messages=messages,
                turn_number=turn_number,
                session_context=session_context,
                bypass_policy=False,
                untrusted_context_sources=untrusted_context_sources
            )

        # Update dialogue history
        messages.append({"role": "user", "content": user_message})
        messages.append({"role": "assistant", "content": result.get("final_response", "")})

        # Propagate untrusted context sources across turns
        if result.get("untrusted_context_sources"):
            untrusted_context_sources = result["untrusted_context_sources"]

        turn_result = {
            "turn_number": turn_number,
            "user_message": user_message,
            "tool_name": result.get("tool_name"),
            "tool_args": result.get("tool_args", {}),
            "llm_plan": result.get("llm_plan"),
            "guard_output": result.get("guard_output"),
            "policy_decision": result.get("policy_decision"),
            "tool_result": result.get("tool_result"),
            "security_events": result.get("security_events", []),
            "final_response": result.get("final_response"),
            "latency_ms": result.get("latency_ms", 0.0),
            "token_usage": result.get("token_usage", {}),
            "cost": result.get("cost", 0.0)
        }
        turn_results.append(turn_result)

    episode = {
        "episode_id": episode_id,
        "scenario_id": scenario.get("scenario_id", "unknown"),
        "category": scenario.get("attack_category") or scenario.get("category", "unspecified"),
        "attack_category": scenario.get("attack_category") or scenario.get("category", "unspecified"),
        "is_attack": scenario.get("is_attack", False),
        "user_role": session_context["user_role"],
        "config_mode": mode,
        "turns": turn_results,
        "messages": messages,
        "expected_behavior": scenario.get("expected_behavior", ""),
        "observable_success_condition": scenario.get("observable_success_condition", "")
    }

    log_event(
        episode_id=episode_id,
        event_type="episode_completed",
        payload={
            "scenario_id": scenario.get("scenario_id"),
            "category": episode["category"],
            "turn_count": len(turn_results),
            "config_mode": mode
        }
    )

    return episode


def run_benchmark(
    scenarios: Optional[List[Dict[str, Any]]] = None,
    mode: str = "combined_agentshield",
    benchmark_path: Optional[Path] = None,
    output_filename: Optional[str] = None,
    random_seed: int = 42
) -> Dict[str, Any]:
    """
    Runs a benchmark evaluation suite across all loaded scenarios.
    mode options:
      - 'combined_agentshield': Guard + Policy active (Full defense)
      - 'policy_only': Policy active, Guard disabled
      - 'guard_only': Guard active, Policy bypassed
      - 'vulnerable_baseline': Policy bypassed, Guard disabled
    """
    random.seed(random_seed)

    if scenarios is None:
        scenarios = load_scenarios(benchmark_path)

    print(f"\n=======================================================")
    print(f" Starting AgentShield Evaluation: Mode = [{mode.upper()}]")
    print(f" Scenarios to execute: {len(scenarios)}")
    print(f" Random Seed: {random_seed}")
    print(f"=======================================================")

    episodes = []
    for idx, scenario in enumerate(scenarios, start=1):
        s_id = scenario.get("scenario_id", f"SCN_{idx:03d}")
        cat = scenario.get("attack_category") or scenario.get("category", "unspecified")
        is_att = "ATTACK" if scenario.get("is_attack") else "BENIGN"
        print(f"[{idx:02d}/{len(scenarios):02d}] Running {s_id} ({cat}) [{is_att}] ...", end="", flush=True)

        ep = run_scenario(scenario, config_mode=mode)
        episodes.append(ep)
        print(" DONE")

    # Compute full scientific metrics
    metrics = calculate_metrics(episodes)

    # Standardized output paths
    run_record = {
        "benchmark_version": "v4.0.0",
        "execution_timestamp": datetime.now(timezone.utc).isoformat(),
        "config_mode": mode,
        "random_seed": random_seed,
        "total_scenarios": len(scenarios),
        "episodes": episodes,
        "metrics": metrics
    }

    # 1. results/benchmark_run.json
    run_path = RESULTS_DIR / "benchmark_run.json"
    with run_path.open("w", encoding="utf-8") as f:
        json.dump(run_record, f, indent=2, ensure_ascii=False)

    # 2. results/benchmark_summary.json
    summary_path = RESULTS_DIR / "benchmark_summary.json"
    with summary_path.open("w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2, ensure_ascii=False)

    # 3. results/attack_category_metrics.json
    cat_metrics_path = RESULTS_DIR / "attack_category_metrics.json"
    with cat_metrics_path.open("w", encoding="utf-8") as f:
        json.dump(metrics.get("per_category_metrics", {}), f, indent=2, ensure_ascii=False)

    # Mode-specific output file if specified
    if output_filename:
        out_p = RESULTS_DIR / output_filename
        with out_p.open("w", encoding="utf-8") as f:
            json.dump(run_record, f, indent=2, ensure_ascii=False)

    print(f"\n>>> Benchmark Finished! Saved results to: {run_path.name}")
    print(f">>> Summary saved to: {summary_path.name}")
    print(f">>> Category metrics saved to: {cat_metrics_path.name}")
    _print_metrics_summary(metrics)

    return run_record


def _print_metrics_summary(metrics: Dict[str, Any]):
    sec = metrics.get("security_metrics", {})
    usa = metrics.get("usability_metrics", {})
    perf = metrics.get("performance_metrics", {})
    ov = metrics.get("overview", {})

    print("\n" + "=" * 58)
    print("           AGENTSHIELD EVALUATION METRICS REPORT          ")
    print("=" * 58)
    print(f"Total Episodes Evaluated:        {ov.get('total_episodes', 0)} ({ov.get('attack_episodes', 0)} Attacks, {ov.get('benign_episodes', 0)} Benign)")
    print(f"Total Multi-Turn Interactions:   {ov.get('total_turns', 0)} turns")
    print("-" * 58)
    print(f"Unauthorized Execution Rate:     {sec.get('unauthorized_execution_rate', 0.0):.1%}  (Primary Security Guardrail)")
    print(f"Attack Success Rate (ASR):       {sec.get('attack_success_rate', 0.0):.1%}")
    print(f"Policy Rejection Rate:           {sec.get('policy_rejection_rate', 0.0):.1%}")
    print(f"Unsafe Proposal Rate:            {sec.get('unsafe_proposal_rate', 0.0):.1%}")
    print(f"Guard Detection Recall:          {sec.get('guard_detection_recall', 0.0):.1%}")
    print("-" * 58)
    print(f"Benign Task Success Rate:        {usa.get('benign_task_success_rate', 0.0):.1%}")
    print(f"False Positive Rate:             {usa.get('false_positive_rate', 0.0):.1%}")
    print("-" * 58)
    print(f"Average Turn Latency:            {perf.get('average_latency_ms', 0):.1f} ms")
    print(f"Median Turn Latency:             {perf.get('median_latency_ms', 0):.1f} ms")
    print(f"P95 Turn Latency:                {perf.get('p95_latency_ms', 0):.1f} ms")
    print(f"Total Inference Cost:            ${perf.get('estimated_cost_usd', 0):.4f}")
    print("=" * 58 + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AgentShield Multi-Turn Benchmark Runner")
    parser.add_argument(
        "--mode",
        choices=["combined_agentshield", "policy_only", "guard_only", "vulnerable_baseline"],
        default="combined_agentshield",
        help="Evaluation defense configuration"
    )
    parser.add_argument("--benchmark", type=str, default=None, help="Path to scenario JSONL file")
    parser.add_argument("--output", type=str, default=None, help="Output file name")
    parser.add_argument("--seed", type=int, default=42, help="Deterministic random seed")
    args = parser.parse_args()

    bench_path = Path(args.benchmark) if args.benchmark else None
    run_benchmark(mode=args.mode, benchmark_path=bench_path, output_filename=args.output, random_seed=args.seed)
