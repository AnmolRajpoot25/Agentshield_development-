import pytest
from src.tools.registry import execute_tool, search_documents, read_document, query_database
from src.tools.document_reader import get_document_by_id, search_synthetic_documents


def test_search_documents_success():
    res = search_documents("invoice")
    assert res["success"] is True
    assert res["count"] >= 1
    assert any(d["document_id"] == "invoice_001" for d in res["results"])


def test_read_document_encapsulation():
    res = read_document("invoice_001")
    assert res["success"] is True
    assert "<<<BEGIN_UNTRUSTED_DOCUMENT" in res["content"]
    assert "<<<END_UNTRUSTED_DOCUMENT" in res["content"]


def test_query_database():
    res = query_database("users", filter_column="role", filter_value="admin")
    assert res["success"] is True
    assert res["count"] == 1
    assert res["records"][0]["username"] == "bob_admin"


def test_execute_tool_policy_blocked():
    # Analyst attempting delete_records without admin permission
    res = execute_tool(
        "delete_records",
        {"record_id": "inv_001", "table": "invoices"},
        session_context={"user_role": "analyst"}
    )
    assert res["success"] is False
    assert res["policy_blocked"] is True
    assert "DENIED_RBAC_UNAUTHORIZED" in res["error"]


def test_execute_tool_unregistered_rejected():
    res = execute_tool("fake_tool", {})
    assert res["success"] is False
    assert res["policy_blocked"] is True

