import argparse
import json
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.agents.graph import run_agent
from src.evaluation.metrics import calculate_metrics
from src.tracing.logger import log_event, get_base_dir

BASE = get_base_dir()
DATASET_FILE = BASE / "datasets/adversarial/seed_scenarios.jsonl"
FULL_BENCHMARK_FILE = BASE / "datasets/adversarial/full_benchmark.jsonl"
RESULTS_DIR = BASE / "results"

RESULTS_DIR.mkdir(parents=True, exist_ok=True)


def load_scenarios(benchmark_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Loads benchmark scenarios from JSONL file."""
    target_path = benchmark_path or (
        FULL_BENCHMARK_FILE if FULL_BENCHMARK_FILE.exists() else DATASET_FILE
    )
    with target_path.open("r", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def run_scenario(
    scenario: Dict[str, Any],
    bypass_policy: bool = False,
    user_role: str = "analyst"
) -> Dict[str, Any]:
    """
    Executes a multi-turn scenario while preserving conversation state,
    untrusted context taint, and recording telemetry at every turn.
    """
    episode_id = str(uuid.uuid4())
    messages = []
    turn_results = []
    untrusted_context_sources = []

    session_context = {
        "user_id": scenario.get("user_id", "user_analyst_01"),
        "user_role": scenario.get("user_role", user_role)
    }

    for turn_number, user_message in enumerate(scenario["turns"], start=1):
        result = run_agent(
            user_request=user_message,
            episode_id=episode_id,
            scenario_id=scenario.get("scenario_id"),
            messages=messages,
            turn_number=turn_number,
            session_context=session_context,
            bypass_policy=bypass_policy,
            untrusted_context_sources=untrusted_context_sources
        )

        # Update conversational state
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
        "category": scenario.get("category", "unspecified"),
        "is_attack": scenario.get("is_attack", False),
        "user_role": session_context["user_role"],
        "bypass_policy": bypass_policy,
        "turns": turn_results,
        "messages": messages,
        "expected_behavior": scenario.get("expected_behavior", "")
    }

    log_event(
        episode_id=episode_id,
        event_type="episode_completed",
        payload={
            "scenario_id": scenario.get("scenario_id"),
            "category": scenario.get("category"),
            "turn_count": len(turn_results),
            "bypass_policy": bypass_policy
        }
    )

    return episode


def run_benchmark(
    scenarios: Optional[List[Dict[str, Any]]] = None,
    mode: str = "agentshield",
    output_filename: Optional[str] = None
) -> Dict[str, Any]:
    """
    Runs a benchmark evaluation suite across all loaded scenarios.
    mode:
      - 'agentshield': Independent Policy Engine active (Full defense)
      - 'baseline_unprotected': Policy Engine bypassed (Vulnerability baseline)
    """
    if scenarios is None:
        scenarios = load_scenarios()

    bypass_policy = (mode == "baseline_unprotected")
    print(f"\n=======================================================")
    print(f" Starting AgentShield Evaluation: Mode = [{mode.upper()}]")
    print(f" Scenarios to execute: {len(scenarios)}")
    print(f"=======================================================")

    episodes = []
    for idx, scenario in enumerate(scenarios, start=1):
        s_id = scenario.get("scenario_id", f"SCN_{idx:03d}")
        cat = scenario.get("category", "unspecified")
        is_att = "ATTACK" if scenario.get("is_attack") else "BENIGN"
        print(f"[{idx:02d}/{len(scenarios):02d}] Running {s_id} ({cat}) [{is_att}] ...", end="", flush=True)

        ep = run_scenario(scenario, bypass_policy=bypass_policy)
        episodes.append(ep)
        print(" DONE")

    # Compute full scientific metrics
    metrics = calculate_metrics(episodes)

    # Save results
    target_filename = output_filename or f"eval_{mode}_episodes.json"
    output_path = RESULTS_DIR / target_filename
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(episodes, f, indent=2, ensure_ascii=False)

    metrics_filename = output_filename.replace(".json", "_metrics.json") if output_filename else f"eval_{mode}_metrics.json"
    metrics_path = RESULTS_DIR / metrics_filename
    with metrics_path.open("w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2, ensure_ascii=False)

    print(f"\n>>> Benchmark Finished! Saved episodes to: {output_path.name}")
    print(f">>> Metrics saved to: {metrics_path.name}")
    _print_metrics_summary(metrics)

    return {"episodes": episodes, "metrics": metrics}


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
    print(f"Attack Detection Rate:           {sec.get('attack_detection_rate', 0.0):.1%}")
    print("-" * 58)
    print(f"Benign Task Success Rate:        {usa.get('benign_task_success_rate', 0.0):.1%}")
    print(f"False Positive Rate:             {usa.get('false_positive_rate', 0.0):.1%}")
    print("-" * 58)
    print(f"Average Turn Latency:            {perf.get('average_latency_ms', 0):.1f} ms")
    print(f"Total Inference Cost:            ${perf.get('total_inference_cost_usd', 0):.4f}")
    print("=" * 58 + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AgentShield Multi-Turn Benchmark Runner")
    parser.add_argument("--mode", choices=["agentshield", "baseline_unprotected"], default="agentshield", help="Evaluation defense mode")
    parser.add_argument("--benchmark", type=str, default=None, help="Path to scenario JSONL file")
    parser.add_argument("--output", type=str, default=None, help="Output file name")
    args = parser.parse_args()

    bench_path = Path(args.benchmark) if args.benchmark else None
    run_benchmark(mode=args.mode, benchmark_path=bench_path, output_filename=args.output)
