from typing import Any, Dict, List, Optional
from src.security.policies import policy_engine
from src.security.taint import TaintTracker
from src.tools.document_reader import SYNTHETIC_DOCUMENTS, search_synthetic_documents

# In-memory mock database tables
DATABASE_TABLES: Dict[str, List[Dict[str, Any]]] = {
    "users": [
        {"user_id": "u1", "username": "alice_analyst", "role": "analyst"},
        {"user_id": "u2", "username": "bob_admin", "role": "admin"},
        {"user_id": "u3", "username": "eve_external", "role": "viewer"}
    ],
    "invoices": [
        {"invoice_id": "inv_001", "amount": 5000, "status": "pending", "vendor": "ABC Technologies"},
        {"invoice_id": "inv_002", "amount": 12000, "status": "paid", "vendor": "CloudCorp"}
    ],
    "audit_logs": [
        {"log_id": "l_101", "action": "login", "user": "alice_analyst", "status": "success"},
        {"log_id": "l_102", "action": "doc_access", "user": "alice_analyst", "status": "success"}
    ]
}


def search_documents(query: str, max_results: int = 5) -> Dict[str, Any]:
    """Search synthetic corporate documents via keyword matching."""
    if not isinstance(query, str) or not query.strip():
        return {"success": False, "error": "Search query must be a non-empty string."}
    
    matches = search_synthetic_documents(query, max_results=max_results)
    return {
        "success": True,
        "results": matches,
        "count": len(matches)
    }


def read_document(document_id: str) -> Dict[str, Any]:
    """Retrieve full document text, encapsulating untrusted content within taint delimiters."""
    if not isinstance(document_id, str) or not document_id.strip():
        return {"success": False, "error": "Invalid document ID."}

    doc = SYNTHETIC_DOCUMENTS.get(document_id)
    if not doc:
        return {"success": False, "error": f"Document '{document_id}' not found."}

    raw_content = doc.get("content", "")
    # Apply explicit untrusted data encapsulation
    encapsulated_content = TaintTracker.encapsulate_untrusted_data(document_id, raw_content)

    return {
        "success": True,
        "document_id": doc["document_id"],
        "title": doc["title"],
        "classification": doc["classification"],
        "content": encapsulated_content,
        "is_untrusted_data": True
    }


def summarize_document(document_id: str) -> Dict[str, Any]:
    """Retrieve document metadata and content preview for summarization."""
    res = read_document(document_id)
    if not res.get("success"):
        return res

    return {
        "success": True,
        "document_id": res["document_id"],
        "title": res["title"],
        "classification": res["classification"],
        "content": res["content"]
    }


def query_database(
    table: str,
    filter_column: Optional[str] = None,
    filter_value: Optional[Any] = None
) -> Dict[str, Any]:
    """Query synthetic database tables with column filtering."""
    if not isinstance(table, str) or not table.strip():
        return {"success": False, "error": "Table name must be a valid string."}

    table_key = table.lower().strip()
    if table_key not in DATABASE_TABLES:
        return {"success": False, "error": f"Table '{table}' does not exist."}

    records = DATABASE_TABLES[table_key]
    if filter_column and filter_value is not None:
        records = [r for r in records if str(r.get(filter_column)) == str(filter_value)]

    return {
        "success": True,
        "table": table_key,
        "count": len(records),
        "records": records
    }


def send_email(recipient: str, subject: str, body: str) -> Dict[str, Any]:
    """Simulated external email notification tool."""
    return {
        "success": True,
        "message": f"Email dispatched to {recipient} with subject '{subject}'.",
        "recipient": recipient
    }


def delete_records(record_id: str, table: str) -> Dict[str, Any]:
    """Destructive operation: removes records from a database table."""
    table_key = table.lower().strip()
    if table_key not in DATABASE_TABLES:
        return {"success": False, "error": f"Table '{table}' does not exist."}

    original_count = len(DATABASE_TABLES[table_key])
    DATABASE_TABLES[table_key] = [
        r for r in DATABASE_TABLES[table_key]
        if str(r.get("user_id")) != record_id
        and str(r.get("invoice_id")) != record_id
        and str(r.get("log_id")) != record_id
    ]

    deleted_count = original_count - len(DATABASE_TABLES[table_key])
    return {
        "success": True,
        "message": f"Deleted {deleted_count} record(s) matching '{record_id}' from '{table}'.",
        "deleted_count": deleted_count
    }


# Tool lookup map
TOOL_REGISTRY = {
    "search_documents": search_documents,
    "read_document": read_document,
    "summarize_document": summarize_document,
    "query_database": query_database,
    "send_email": send_email,
    "delete_records": delete_records
}


def execute_tool(
    tool_name: str,
    arguments: Dict[str, Any],
    session_context: Optional[Dict[str, Any]] = None,
    bypass_policy: bool = False
) -> Dict[str, Any]:
    """
    Centralized execution gateway.
    Unless bypass_policy is explicitly enabled (for baseline vulnerability measurement),
    all executions MUST be verified and authorized by the Security Policy Engine.
    """
    if not bypass_policy:
        decision = policy_engine.evaluate(tool_name, arguments, session_context)
        if not decision.allowed:
            return {
                "success": False,
                "error": f"Policy rejection [{decision.decision_code}]: {decision.reason}",
                "decision_code": decision.decision_code,
                "policy_blocked": True
            }

    tool_func = TOOL_REGISTRY.get(tool_name)
    if tool_func is None:
        return {
            "success": False,
            "error": f"Unknown tool: '{tool_name}'",
            "decision_code": "UNKNOWN_TOOL",
            "policy_blocked": False
        }

    try:
        res = tool_func(**arguments)
        return {
            "success": res.get("success", True),
            "tool_name": tool_name,
            "result": res,
            "policy_blocked": False
        }
    except TypeError as te:
        return {
            "success": False,
            "error": f"Invalid arguments supplied to tool: {str(te)}",
            "decision_code": "INVALID_ARGUMENT_ERROR",
            "policy_blocked": False
        }
    except Exception as exc:
        return {
            "success": False,
            "error": f"Execution error: {str(exc)}",
            "decision_code": "EXECUTION_EXCEPTION",
            "policy_blocked": False
        }
