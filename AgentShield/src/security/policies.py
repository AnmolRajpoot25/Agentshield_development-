from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
from src.security.rbac import RolePermissionMatrix
from src.security.taint import TaintTracker

# Allowed registered tools
ALLOWED_TOOLS: Set[str] = {
    "search_documents",
    "summarize_document",
    "read_document",
    "query_database",
    "send_email",
    "delete_records"
}

# Resource Sensitivity Metadata Catalog (RLAC)
RESOURCE_CLASSIFICATION: Dict[str, str] = {
    "invoice_001": "INTERNAL",
    "policy_001": "PUBLIC",
    "quarterly_report_002": "INTERNAL",
    "confidential_payroll_002": "CONFIDENTIAL",
    "employee_records_confidential": "CONFIDENTIAL",
    "admin_credentials_004": "RESTRICTED",
    "vendor_security_report_malicious_003": "CONFIDENTIAL",
    "malicious_doc_001": "CONFIDENTIAL",
    "malicious_doc_002": "CONFIDENTIAL",
    "malicious_doc_003": "CONFIDENTIAL"
}

TOOL_SCHEMAS: Dict[str, Dict[str, Any]] = {
    "search_documents": {
        "required": ["query"],
        "optional": ["max_results"],
        "types": {"query": str, "max_results": int},
        "max_len": {"query": 200}
    },
    "summarize_document": {
        "required": ["document_id"],
        "optional": [],
        "types": {"document_id": str},
        "max_len": {"document_id": 100}
    },
    "read_document": {
        "required": ["document_id"],
        "optional": [],
        "types": {"document_id": str},
        "max_len": {"document_id": 100}
    },
    "query_database": {
        "required": ["table"],
        "optional": ["filter_column", "filter_value"],
        "types": {"table": str, "filter_column": str, "filter_value": (str, int, float)},
        "max_len": {"table": 100, "filter_column": 100, "filter_value": 200}
    },
    "send_email": {
        "required": ["recipient", "subject", "body"],
        "optional": [],
        "types": {"recipient": str, "subject": str, "body": str},
        "max_len": {"recipient": 150, "subject": 200, "body": 2000}
    },
    "delete_records": {
        "required": ["record_id", "table"],
        "optional": [],
        "types": {"record_id": str, "table": str},
        "max_len": {"record_id": 100, "table": 100}
    }
}


@dataclass
class PolicyDecision:
    allowed: bool
    decision_code: str
    reason: str
    tool_name: Optional[str]
    user_role: str
    timestamp: str
    details: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SecurityPolicyEngine:
    """
    Independent External Security Policy Engine for AgentShield.
    Enforces Tool Allowlisting, Strict Schema Validation, RBAC,
    Resource-Level Access Control (RLAC), Taint Boundaries, and
    Context-Poisoning Invariants.
    """

    def __init__(self, default_role: str = "analyst"):
        self.default_role = default_role

    def evaluate(
        self,
        tool_name: Optional[str],
        tool_args: Dict[str, Any],
        session_context: Optional[Dict[str, Any]] = None,
        state_history: Optional[List[Dict[str, Any]]] = None
    ) -> PolicyDecision:
        timestamp = datetime.now(timezone.utc).isoformat()
        session_context = session_context or {}
        user_role = session_context.get("user_role", self.default_role)

        # 1. Null / None tool handling
        if not tool_name or tool_name.lower() in ("none", "null"):
            return PolicyDecision(
                allowed=True,
                decision_code="NO_TOOL_PROPOSED",
                reason="No tool operation requested.",
                tool_name=None,
                user_role=user_role,
                timestamp=timestamp,
                details={}
            )

        # 2. Tool Allowlisting Check
        if tool_name not in ALLOWED_TOOLS:
            return PolicyDecision(
                allowed=False,
                decision_code="DENIED_UNREGISTERED_TOOL",
                reason=f"Tool '{tool_name}' is not in the authorized tool allowlist.",
                tool_name=tool_name,
                user_role=user_role,
                timestamp=timestamp,
                details={"attempted_tool": tool_name}
            )

        # 3. Arguments dictionary validation
        if not isinstance(tool_args, dict):
            return PolicyDecision(
                allowed=False,
                decision_code="DENIED_INVALID_ARGUMENT_STRUCTURE",
                reason="Tool arguments must be supplied as a valid JSON dictionary.",
                tool_name=tool_name,
                user_role=user_role,
                timestamp=timestamp,
                details={"arguments_type": type(tool_args).__name__}
            )

        # 4. Schema & Parameter Validation
        schema = TOOL_SCHEMAS.get(tool_name)
        if schema:
            # Check required parameters
            for req in schema["required"]:
                if req not in tool_args:
                    return PolicyDecision(
                        allowed=False,
                        decision_code="DENIED_MISSING_REQUIRED_ARGUMENT",
                        reason=f"Missing required parameter '{req}' for tool '{tool_name}'.",
                        tool_name=tool_name,
                        user_role=user_role,
                        timestamp=timestamp,
                        details={"missing_param": req}
                    )
                val = tool_args[req]
                if isinstance(val, str) and not val.strip():
                    return PolicyDecision(
                        allowed=False,
                        decision_code="DENIED_EMPTY_PARAMETER",
                        reason=f"Parameter '{req}' cannot be empty.",
                        tool_name=tool_name,
                        user_role=user_role,
                        timestamp=timestamp,
                        details={"parameter": req}
                    )

            # Check for unexpected parameters
            all_allowed_params = set(schema["required"]) | set(schema.get("optional", []))
            for arg_k in tool_args.keys():
                if arg_k not in all_allowed_params:
                    return PolicyDecision(
                        allowed=False,
                        decision_code="DENIED_UNEXPECTED_ARGUMENT",
                        reason=f"Unexpected parameter '{arg_k}' rejected by schema policy.",
                        tool_name=tool_name,
                        user_role=user_role,
                        timestamp=timestamp,
                        details={"unexpected_param": arg_k}
                    )

            # Check parameter types and string lengths
            for param, expected_type in schema["types"].items():
                if param in tool_args:
                    val = tool_args[param]
                    if not isinstance(val, expected_type):
                        return PolicyDecision(
                            allowed=False,
                            decision_code="DENIED_TYPE_MISMATCH",
                            reason=f"Parameter '{param}' expected {expected_type}, received {type(val)}.",
                            tool_name=tool_name,
                            user_role=user_role,
                            timestamp=timestamp,
                            details={"param": param, "val": str(val)}
                        )
                    if isinstance(val, str):
                        max_len = schema.get("max_len", {}).get(param, 500)
                        if len(val) > max_len:
                            return PolicyDecision(
                                allowed=False,
                                decision_code="DENIED_PARAMETER_LENGTH_EXCEEDED",
                                reason=f"Parameter '{param}' exceeds maximum length of {max_len}.",
                                tool_name=tool_name,
                                user_role=user_role,
                                timestamp=timestamp,
                                details={"param": param, "length": len(val), "max": max_len}
                            )

        # 5. Role-Based Access Control (RBAC)
        if not RolePermissionMatrix.is_tool_permitted(user_role, tool_name):
            return PolicyDecision(
                allowed=False,
                decision_code="DENIED_RBAC_UNAUTHORIZED",
                reason=f"Role '{user_role}' is not authorized to execute '{tool_name}'.",
                tool_name=tool_name,
                user_role=user_role,
                timestamp=timestamp,
                details={"user_role": user_role, "required_tool": tool_name}
            )

        # 6. Resource-Level Access Control (RLAC)
        resource_id = tool_args.get("document_id") or tool_args.get("table") or tool_args.get("record_id")
        if resource_id:
            classification = RESOURCE_CLASSIFICATION.get(str(resource_id), "INTERNAL")
            # If query or doc contains sensitive keywords
            if any(k in str(resource_id).lower() for k in ["confidential", "credential", "payroll", "secret", "restricted"]):
                classification = "CONFIDENTIAL"

            if not RolePermissionMatrix.is_resource_permitted(user_role, classification):
                return PolicyDecision(
                    allowed=False,
                    decision_code="DENIED_RLAC_UNAUTHORIZED",
                    reason=f"Role '{user_role}' lacks clearance for resource '{resource_id}' ({classification}).",
                    tool_name=tool_name,
                    user_role=user_role,
                    timestamp=timestamp,
                    details={"resource_id": resource_id, "classification": classification}
                )

        # 7. Check for injection markers in arguments (Taint Analysis)
        for k, v in tool_args.items():
            if isinstance(v, str):
                injections = TaintTracker.scan_for_injection_markers(v)
                if injections:
                    return PolicyDecision(
                        allowed=False,
                        decision_code="DENIED_TAINTED_ARGUMENT",
                        reason=f"Adversarial injection tokens detected in parameter '{k}': {injections}",
                        tool_name=tool_name,
                        user_role=user_role,
                        timestamp=timestamp,
                        details={"param": k, "markers": injections}
                    )

        # 8. All security checks passed
        return PolicyDecision(
            allowed=True,
            decision_code="ALLOWED",
            reason=f"Operation '{tool_name}' verified against all security invariants.",
            tool_name=tool_name,
            user_role=user_role,
            timestamp=timestamp,
            details={"user_role": user_role, "tool_args": tool_args}
        )


# Global policy engine instance
policy_engine = SecurityPolicyEngine()


def authorize_tool(
    tool_name: str,
    arguments: Dict[str, Any],
    session_context: Optional[Dict[str, Any]] = None
) -> bool:
    """
    Standard interface for tool authorization returning boolean decision.
    Maintains backward compatibility with legacy calls.
    """
    decision = policy_engine.evaluate(tool_name, arguments, session_context)
    return decision.allowed
