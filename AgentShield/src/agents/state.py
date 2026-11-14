from typing import Any, Dict, List, Optional, TypedDict


class AgentState(TypedDict, total=False):
    # Core identifiers & session metadata
    episode_id: str
    scenario_id: Optional[str]
    turn_number: int
    user_request: str
    session_context: Dict[str, Any]

    # Conversation history
    messages: List[Dict[str, Any]]

    # Untrusted data & taint tracking
    untrusted_context_sources: List[str]
    untrusted_provenance: List[Dict[str, Any]]
    taint_detected: bool

    # Model planning & reasoning
    llm_plan: Optional[Dict[str, Any]]
    planner_raw_output: Optional[str]
    planner_error: Optional[str]

    # Tool invocation candidate
    tool_name: Optional[str]
    tool_args: Dict[str, Any]

    # External Security Policy decision
    policy_decision: Optional[Dict[str, Any]]

    # Execution outcome
    tool_result: Optional[Dict[str, Any]]

    # Security event telemetry
    security_events: List[Dict[str, Any]]
    guard_output: Optional[Dict[str, Any]]

    # Synthesized final output
    final_response: Optional[str]

    # Telemetry metrics
    latency_ms: float
    token_usage: Dict[str, int]
    cost: float

    # Benchmark evaluation controls
    bypass_policy: bool
