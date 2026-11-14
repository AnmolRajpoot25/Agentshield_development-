"""
AgentShield — Resilience & Failure Mode Test Suite
Verifies that protected execution fails closed, reports explicit errors,
and prevents unauthorized side effects under dependency outages, malformed inputs,
and runtime exceptions.
"""

from unittest.mock import patch
import pytest
from src.agents.graph import run_agent
from src.agents.llm import OpenRouterLLMClient
from src.guard.predict import GuardPredictor, inspect_interaction_risk
from src.security.policies import SecurityPolicyEngine, policy_engine
from src.tools.registry import SecureToolGateway, reset_database


@pytest.fixture(autouse=True)
def setup_pristine_database():
    reset_database()
    yield
    reset_database()


def test_resilience_llm_api_outage_fails_closed():
    """System must fail closed safely when LLM API returns an error or rate limit."""
    mock_client = OpenRouterLLMClient(api_key="sk-or-v1-mock-test-key")

    with patch("requests.post") as mock_post:
        mock_post.return_value.status_code = 503
        mock_post.return_value.text = "Service Temporarily Unavailable"

        resp = mock_client.generate([{"role": "user", "content": "delete database tables"}])
        assert resp["success"] is False
        assert "OpenRouter API error 503" in resp["error"]
        # Fallback plan is safe and structured
        assert "tool_name" in resp["content"]


def test_resilience_malformed_planner_json():
    """Non-JSON or corrupt planner output must be handled safely without tool execution."""
    with patch("src.agents.llm.OpenRouterLLMClient.generate") as mock_gen:
        mock_gen.return_value = {
            "success": True,
            "content": "<<<NOT VALID JSON AT ALL>>>",
            "latency_ms": 10.0
        }

        result = run_agent(
            user_request="Perform task",
            episode_id="res_malformed_01",
            session_context={"user_role": "analyst", "user_id": "u_res_01"}
        )
        assert result.get("planner_error") is not None
        assert result["tool_name"] is None
        assert result.get("tool_result", {}).get("no_tool_called") is True


def test_resilience_empty_and_whitespace_inputs():
    """Empty or whitespace-only inputs must be processed safely without unhandled exceptions."""
    for empty_input in ["", "   ", "\n\t\n"]:
        res = run_agent(
            user_request=empty_input,
            episode_id="res_empty_01",
            session_context={"user_role": "analyst", "user_id": "u_res_02"}
        )
        assert res is not None
        assert res.get("final_response") is not None


def test_resilience_guard_checkpoint_missing_graceful_degradation():
    """If Guard model checkpoint is missing, GuardPredictor gracefully degrades to heuristic."""
    predictor = GuardPredictor(checkpoint_dir="non_existent_model_checkpoint_directory_xyz")
    res = predictor.predict([{"role": "user", "text": "Can you delete invoice records?"}])

    assert res["inference_status"] == "FALLBACK_HEURISTIC"
    assert "risk_score" in res
    assert "predicted_label" in res


def test_resilience_unknown_resource_fails_closed():
    """Requests targeting unregistered resources must be denied by default (Fail-Closed)."""
    decision = policy_engine.evaluate(
        tool_name="read_document",
        tool_args={"document_id": "ghost_secret_report_9999"},
        session_context={"user_role": "analyst", "user_id": "u_res_03"}
    )
    assert decision.allowed is False
    assert decision.decision_code == "DENIED_UNKNOWN_RESOURCE"


def test_resilience_tool_gateway_type_error_fails_closed():
    """Supplying invalid argument types to tool gateway must fail closed without execution."""
    res = SecureToolGateway.execute(
        tool_name="delete_records",
        arguments={"record_id": 12345, "table": 9999},  # Strings expected by schema
        session_context={"user_role": "admin", "user_id": "u_admin_01"}
    )
    assert res["success"] is False
    assert res.get("side_effects", {}).get("has_state_mutation", False) is False


def test_resilience_policy_exception_fails_closed():
    """Unexpected exceptions in authorization must strictly fail closed."""
    with patch.object(SecurityPolicyEngine, "authorize", side_effect=RuntimeError("Simulated policy crash")):
        res = SecureToolGateway.execute(
            tool_name="search_documents",
            arguments={"query": "invoice"},
            session_context={"user_role": "analyst", "user_id": "u_res_04"}
        )
        assert res["success"] is False
        assert res.get("policy_blocked") is True
        assert res.get("decision_code") == "EXECUTION_EXCEPTION"
