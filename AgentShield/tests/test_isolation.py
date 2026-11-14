"""
AgentShield — Multi-Tenant State Isolation & Concurrency Test Suite
Verifies that session state, authorization roles, taint metadata, and audit records
remain strictly isolated across distinct users, episodes, and synthetic sessions.
"""

import uuid
import pytest
from src.agents.graph import run_agent
from src.security.policies import policy_engine
from src.tools.registry import SecureToolGateway, reset_database, DATABASE_TABLES


@pytest.fixture(autouse=True)
def setup_pristine_database():
    reset_database()
    yield
    reset_database()


def test_isolation_user_roles_do_not_leak():
    """User A (analyst) and User B (viewer) maintain strict role isolation."""
    session_a = {"user_role": "analyst", "user_id": "user_alice"}
    session_b = {"user_role": "viewer", "user_id": "user_bob"}

    # Alice (analyst) can query database
    dec_a = policy_engine.evaluate(
        tool_name="query_database",
        tool_args={"table": "invoices"},
        session_context=session_a
    )
    assert dec_a.allowed is True

    # Bob (viewer) cannot query database
    dec_b = policy_engine.evaluate(
        tool_name="query_database",
        tool_args={"table": "invoices"},
        session_context=session_b
    )
    assert dec_b.allowed is False
    assert dec_b.decision_code == "DENIED_RBAC_UNAUTHORIZED"

    # Verify Bob's attempt did not alter Alice's subsequent query
    dec_a2 = policy_engine.evaluate(
        tool_name="query_database",
        tool_args={"table": "invoices"},
        session_context=session_a
    )
    assert dec_a2.allowed is True


def test_isolation_taint_metadata_quarantined_per_episode():
    """Taint metadata from one episode must not bleed into subsequent episodes."""
    ep1_id = f"ep_{uuid.uuid4().hex[:6]}"
    ep2_id = f"ep_{uuid.uuid4().hex[:6]}"

    # Episode 1 retrieves malicious document
    res_ep1 = run_agent(
        user_request="Read malicious_doc_001.",
        episode_id=ep1_id,
        session_context={"user_role": "analyst", "user_id": "user_alice"}
    )
    assert res_ep1.get("untrusted_context_sources") is not None
    assert len(res_ep1["untrusted_context_sources"]) > 0

    # Episode 2 starts with fresh context
    res_ep2 = run_agent(
        user_request="Search for company security policies.",
        episode_id=ep2_id,
        session_context={"user_role": "analyst", "user_id": "user_bob"},
        untrusted_context_sources=[]
    )
    assert res_ep2.get("untrusted_context_sources") == []
    assert res_ep2["policy_blocked"] is False


def test_isolation_database_state_reproducibility():
    """Database mutations by admin do not corrupt baseline state after reset."""
    session_admin = {"user_role": "admin", "user_id": "admin_root"}

    # Admin deletes an invoice
    res = SecureToolGateway.execute(
        tool_name="delete_records",
        arguments={"record_id": "inv_001", "table": "invoices"},
        session_context=session_admin
    )
    assert res["success"] is True
    assert res["side_effects"]["records_deleted"] == 1

    # Reset database
    reset_database()

    # Invoices table restored to original count (2 invoices)
    assert len(DATABASE_TABLES["invoices"]) == 2
    invoice_ids = [inv["invoice_id"] for inv in DATABASE_TABLES["invoices"]]
    assert "inv_001" in invoice_ids
    assert "inv_002" in invoice_ids

