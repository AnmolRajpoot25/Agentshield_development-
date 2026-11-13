import argparse
import json
from pathlib import Path
from typing import Any, Dict, List

from src.evaluation.metrics import calculate_metrics
from src.evaluation.runner import load_scenarios, run_scenario
from src.tracing.logger import get_base_dir

BASE = get_base_dir()
RESULTS_DIR = BASE / "results"
REPORTS_DIR = BASE / "reports"


def run_comparative_study(
    scenario_subset: int = 10,
    benchmark_path: Path = None
) -> Dict[str, Any]:
    """
    Executes a head-to-head comparative study evaluating:
    1. Baseline Agent (No External Policy Engine - Tool Proposals Execute Directly)
    2. AgentShield Protected Agent (External Policy Engine + RBAC + RLAC + Taint Tracking)
    """
    scenarios = load_scenarios(benchmark_path)
    if scenario_subset and scenario_subset > 0:
        scenarios = scenarios[:scenario_subset]

    print("\n" + "=" * 65)
    print("      AGENTSHIELD COMPARATIVE SECURITY EXPERIMENT")
    print(f"      Scenarios in test suite: {len(scenarios)}")
    print("=" * 65)

    # ---------------------------------------------------------
    # Arm 1: AgentShield Protected Agent
    # ---------------------------------------------------------
    print("\n[Phase 1/2] Evaluating AgentShield Protected Agent...")
    protected_episodes = []
    for idx, scn in enumerate(scenarios, start=1):
        print(f"  [{idx:02d}/{len(scenarios):02d}] Protected: {scn.get('scenario_id')} ...", end="", flush=True)
        ep = run_scenario(scn, bypass_policy=False)
        protected_episodes.append(ep)
        print(" DONE")

    protected_metrics = calculate_metrics(protected_episodes)

    # ---------------------------------------------------------
    # Arm 2: Baseline Unprotected Agent (Policy Engine Bypassed)
    # ---------------------------------------------------------
    print("\n[Phase 2/2] Evaluating Baseline Vulnerable Agent (Policy Bypassed)...")
    baseline_episodes = []
    for idx, scn in enumerate(scenarios, start=1):
        print(f"  [{idx:02d}/{len(scenarios):02d}] Baseline: {scn.get('scenario_id')} ...", end="", flush=True)
        ep = run_scenario(scn, bypass_policy=True)
        baseline_episodes.append(ep)
        print(" DONE")

    baseline_metrics = calculate_metrics(baseline_episodes)

    # ---------------------------------------------------------
    # Generate Comparison Synthesis
    # ---------------------------------------------------------
    comparison = {
        "study_metadata": {
            "total_scenarios_evaluated": len(scenarios),
            "attack_scenarios": protected_metrics["overview"]["attack_episodes"],
            "benign_scenarios": protected_metrics["overview"]["benign_episodes"]
        },
        "baseline_unprotected": {
            "unauthorized_execution_rate": baseline_metrics["security_metrics"]["unauthorized_execution_rate"],
            "attack_success_rate": baseline_metrics["security_metrics"]["attack_success_rate"],
            "policy_rejection_rate": baseline_metrics["security_metrics"]["policy_rejection_rate"],
            "unsafe_proposal_rate": baseline_metrics["security_metrics"]["unsafe_proposal_rate"],
            "benign_task_success_rate": baseline_metrics["usability_metrics"]["benign_task_success_rate"],
            "false_positive_rate": baseline_metrics["usability_metrics"]["false_positive_rate"]
        },
        "agentshield_protected": {
            "unauthorized_execution_rate": protected_metrics["security_metrics"]["unauthorized_execution_rate"],
            "attack_success_rate": protected_metrics["security_metrics"]["attack_success_rate"],
            "policy_rejection_rate": protected_metrics["security_metrics"]["policy_rejection_rate"],
            "unsafe_proposal_rate": protected_metrics["security_metrics"]["unsafe_proposal_rate"],
            "benign_task_success_rate": protected_metrics["usability_metrics"]["benign_task_success_rate"],
            "false_positive_rate": protected_metrics["usability_metrics"]["false_positive_rate"]
        },
        "risk_reduction": {
            "absolute_uer_reduction": round(
                baseline_metrics["security_metrics"]["unauthorized_execution_rate"]
                - protected_metrics["security_metrics"]["unauthorized_execution_rate"],
                4
            ),
            "relative_risk_reduction_pct": round(
                ((baseline_metrics["security_metrics"]["unauthorized_execution_rate"]
                  - protected_metrics["security_metrics"]["unauthorized_execution_rate"])
                 / max(1e-6, baseline_metrics["security_metrics"]["unauthorized_execution_rate"])) * 100,
                2
            )
        }
    }

    # Save to disk
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out_file = RESULTS_DIR / "comparative_evaluation.json"
    with out_file.open("w", encoding="utf-8") as f:
        json.dump(comparison, f, indent=2)

    _print_comparison_table(comparison)
    return comparison


def _print_comparison_table(comp: Dict[str, Any]):
    b = comp["baseline_unprotected"]
    p = comp["agentshield_protected"]
    rr = comp["risk_reduction"]

    print("\n" + "=" * 76)
    print("             AGENTSHIELD COMPARATIVE BENCHMARK RESULTS")
    print("=" * 76)
    print(f"{'Security / Usability Metric':<35} | {'Baseline (No Policy)':<18} | {'AgentShield Protected':<18}")
    print("-" * 76)
    print(f"{'Unauthorized Execution Rate (UER)':<35} | {b['unauthorized_execution_rate']:<18.1%} | {p['unauthorized_execution_rate']:<18.1%}")
    print(f"{'Attack Success Rate (ASR)':<35} | {b['attack_success_rate']:<18.1%} | {p['attack_success_rate']:<18.1%}")
    print(f"{'Policy Rejection Rate (PRR)':<35} | {b['policy_rejection_rate']:<18.1%} | {p['policy_rejection_rate']:<18.1%}")
    print(f"{'Unsafe Model Proposal Rate':<35} | {b['unsafe_proposal_rate']:<18.1%} | {p['unsafe_proposal_rate']:<18.1%}")
    print(f"{'Benign Task Success Rate (BTSR)':<35} | {b['benign_task_success_rate']:<18.1%} | {p['benign_task_success_rate']:<18.1%}")
    print(f"{'False Positive Rate (FPR)':<35} | {b['false_positive_rate']:<18.1%} | {p['false_positive_rate']:<18.1%}")
    print("-" * 76)
    print(f"Absolute Risk Reduction:  {rr['absolute_uer_reduction']:.1%} reduction in unauthorized actions")
    print(f"Relative Protection Gain: {rr['relative_risk_reduction_pct']}% safer against multi-turn attacks")
    print("=" * 76 + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--subset", type=int, default=10, help="Number of scenarios to evaluate")
    args = parser.parse_args()
    run_comparative_study(scenario_subset=args.subset)

