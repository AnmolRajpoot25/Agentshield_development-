import copy
from typing import Any, Dict, List, Optional, Tuple
from src.security.policies import policy_engine, PolicyDecision
from src.security.taint import TaintTracker
from src.tools.document_reader import (
    SYNTHETIC_DOCUMENTS,
    search_synthetic_documents,
    get_document_by_id
)

# In-memory mock database tables representing corporate resources
INITIAL_DATABASE_TABLES: Dict[str, List[Dict[str, Any]]] = {
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

DATABASE_TABLES: Dict[str, List[Dict[str, Any]]] = copy.deepcopy(INITIAL_DATABASE_TABLES)


def reset_database() -> None:
    """Resets mock database tables to pristine initial state for reproducible benchmarking."""
    global DATABASE_TABLES
    DATABASE_TABLES.clear()
    DATABASE_TABLES.update(copy.deepcopy(INITIAL_DATABASE_TABLES))


def _snapshot_database() -> Dict[str, List[Dict[str, Any]]]:
    """Captures a deepcopy snapshot of database state for side-effect auditing."""
    return copy.deepcopy(DATABASE_TABLES)


def _compute_database_diff(
    before: Dict[str, List[Dict[str, Any]]],
    after: Dict[str, List[Dict[str, Any]]]
) -> Dict[str, Any]:
    """Computes observable state mutations and record deletions across tables."""
    modified_tables = []
    deleted_count = 0

    for table, records in before.items():
        after_records = after.get(table, [])
        if len(after_records) < len(records):
            modified_tables.append(table)
            deleted_count += (len(records) - len(after_records))
        elif after_records != records:
            modified_tables.append(table)

    return {
        "has_state_mutation": len(modified_tables) > 0,
        "tables_modified": modified_tables,
        "records_deleted": deleted_count
    }


# --------------------------------------------------------------------------
# Tool Implementations
# --------------------------------------------------------------------------

def search_documents(
    query: str,
    max_results: int = 5,
    user_role: str = "analyst"
) -> Dict[str, Any]:
    """
    Search synthetic corporate documents via keyword matching.
    Enforces search clearance filtering: analyst does not see restricted titles.
    """
    if not isinstance(query, str) or not query.strip():
        return {"success": False, "error": "Search query must be a non-empty string."}
    
    matches = search_synthetic_documents(query, max_results=max_results, user_role=user_role)
    return {
        "success": True,
        "results": matches,
        "count": len(matches)
    }


def read_document(document_id: str) -> Dict[str, Any]:
    """Retrieve full document text, encapsulating untrusted content within taint delimiters."""
    if not isinstance(document_id, str) or not document_id.strip():
        return {"success": False, "error": "Invalid document ID."}

    doc = get_document_by_id(document_id)
    if not doc:
        return {"success": False, "error": f"Document '{document_id}' not found."}

    raw_content = doc.get("content", "")
    classification = doc.get("classification", "INTERNAL")
    vendor = doc.get("vendor", "internal")

    # Apply explicit untrusted data encapsulation
    encapsulated_content = TaintTracker.encapsulate_untrusted_data(
        document_id=document_id,
        raw_content=raw_content,
        classification=classification,
        source=vendor
    )

    return {
        "success": True,
        "document_id": doc["document_id"],
        "title": doc["title"],
        "classification": classification,
        "content": encapsulated_content,
        "raw_content": raw_content,
        "is_untrusted_data": doc.get("is_malicious", False)
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
        and record_id.lower() != "all"
        and record_id != "*"
    ]

    deleted_count = original_count - len(DATABASE_TABLES[table_key])
    return {
        "success": True,
        "message": f"Deleted {deleted_count} record(s) matching '{record_id}' from '{table}'.",
        "deleted_count": deleted_count
    }


# Complete Registered Tools Map
TOOL_REGISTRY = {
    "search_documents": search_documents,
    "read_document": read_document,
    "summarize_document": summarize_document,
    "query_database": query_database,
    "send_email": send_email,
    "delete_records": delete_records
}


# --------------------------------------------------------------------------
# Secure Tool Execution Gateway
# --------------------------------------------------------------------------

class SecureToolGateway:
    """
    Centralized protected execution gateway enforcing the 8-step authorization pipeline:
    1. Tool existence validation
    2. Argument schema validation
    3. User identity validation
    4. Role permission validation (RBAC)
    5. Resource permission validation (RLAC Default-Deny)
    6. Operation authorization & dynamic taint check
    7. Sandbox execution
    8. Result and side-effect auditing
    """

    @classmethod
    def execute(
        cls,
        tool_name: str,
        arguments: Dict[str, Any],
        session_context: Optional[Dict[str, Any]] = None,
        untrusted_sources: Optional[List[str]] = None,
        bypass_policy: bool = False
    ) -> Dict[str, Any]:
        # Protected gateway strictly rejects bypass_policy attempts
        session_context = session_context or {"user_role": "analyst", "user_id": "u1"}
        untrusted_sources = untrusted_sources or []

        # 1-6. Independent Policy Engine Authorization Gate
        decision = policy_engine.evaluate(
            tool_name=tool_name,
            tool_args=arguments,
            session_context=session_context,
            untrusted_sources=untrusted_sources
        )

        if not decision.allowed:
            return {
                "success": False,
                "error": f"Authorization Denied [{decision.decision_code}]: {decision.reason}",
                "decision_code": decision.decision_code,
                "policy_id": decision.policy_id,
                "policy_blocked": True,
                "side_effects": {"has_state_mutation": False, "records_deleted": 0}
            }

        # Step 7: Tool Existence Verification in registry
        tool_func = TOOL_REGISTRY.get(tool_name)
        if tool_func is None:
            return {
                "success": False,
                "error": f"Unknown tool: '{tool_name}'",
                "decision_code": "DENIED_UNREGISTERED_TOOL",
                "policy_blocked": True,
                "side_effects": {"has_state_mutation": False, "records_deleted": 0}
            }

        # Step 8: Execution with Snapshot Side-Effect Auditing
        before_state = _snapshot_database()

        try:
            # Special case: pass user_role to search_documents for clearance filtering
            if tool_name == "search_documents":
                exec_args = dict(arguments)
                exec_args["user_role"] = session_context.get("user_role", "analyst")
                res = tool_func(**exec_args)
            else:
                res = tool_func(**arguments)

            after_state = _snapshot_database()
            side_effects = _compute_database_diff(before_state, after_state)

            return {
                "success": res.get("success", True),
                "tool_name": tool_name,
                "result": res,
                "policy_blocked": False,
                "decision_code": decision.decision_code,
                "policy_id": decision.policy_id,
                "side_effects": side_effects
            }

        except TypeError as te:
            return {
                "success": False,
                "error": f"Invalid arguments supplied to tool: {str(te)}",
                "decision_code": "INVALID_ARGUMENT_ERROR",
                "policy_blocked": False,
                "side_effects": {"has_state_mutation": False, "records_deleted": 0}
            }
        except Exception as exc:
            return {
                "success": False,
                "error": f"Execution error: {str(exc)}",
                "decision_code": "EXECUTION_EXCEPTION",
                "policy_blocked": False,
                "side_effects": {"has_state_mutation": False, "records_deleted": 0}
            }

    execute_tool = execute


def execute_tool(
    tool_name: str,
    arguments: Dict[str, Any],
    session_context: Optional[Dict[str, Any]] = None,
    untrusted_sources: Optional[List[str]] = None,
    bypass_policy: bool = False
) -> Dict[str, Any]:
    """
    Central execution dispatcher.
    All protected runtime calls MUST route through SecureToolGateway.
    bypass_policy is restricted exclusively for controlled baseline benchmarks.
    """
    if bypass_policy:
        # Isolated vulnerable baseline path for comparative research only
        tool_func = TOOL_REGISTRY.get(tool_name)
        if not tool_func:
            return {"success": False, "error": f"Unknown tool: '{tool_name}'", "policy_blocked": False}
        before = _snapshot_database()
        try:
            res = tool_func(**arguments)
            after = _snapshot_database()
            diff = _compute_database_diff(before, after)
            return {"success": res.get("success", True), "tool_name": tool_name, "result": res, "policy_blocked": False, "side_effects": diff}
        except Exception as e:
            return {"success": False, "error": str(e), "policy_blocked": False}

    return SecureToolGateway.execute(
        tool_name=tool_name,
        arguments=arguments,
        session_context=session_context,
        untrusted_sources=untrusted_sources
    )
