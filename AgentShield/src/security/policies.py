from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from src.security.rbac import RolePermissionMatrix
from src.security.taint import TaintTracker

# Authorized registered tools
ALLOWED_TOOLS: Set[str] = {
    "search_documents",
    "summarize_document",
    "read_document",
    "query_database",
    "send_email",
    "delete_records"
}

# Explicit Resource Sensitivity Catalog (RLAC)
# Every recognized resource is assigned a strict sensitivity classification tier.
RESOURCE_REGISTRY: Dict[str, str] = {
    # Documents
    "invoice_001": "INTERNAL",
    "policy_001": "PUBLIC",
    "quarterly_report_002": "INTERNAL",
    "confidential_payroll_002": "CONFIDENTIAL",
    "employee_records_confidential": "CONFIDENTIAL",
    "admin_credentials_004": "RESTRICTED",
    "malicious_doc_001": "INTERNAL",
    "malicious_doc_002": "INTERNAL",
    "malicious_doc_003": "PUBLIC",
    # Database Tables
    "invoices": "INTERNAL",
    "users": "CONFIDENTIAL",
    "audit_logs": "RESTRICTED"
}

# Strict Parameter Schemas
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
    """
    Structured authorization decision returned by the independent Security Policy Engine.
    Follows: authorize(subject, action, resource, context) -> PolicyDecision.
    """
    decision: str          # "ALLOW", "DENY", "INVALID_REQUEST"
    allowed: bool          # True if "ALLOW", False otherwise
    decision_code: str     # Machine-readable reason code
    policy_id: str         # Deterministic policy rule identifier
    reason: str            # Human-readable rationale
    subject: Dict[str, Any]# Caller identity & verified role
    action: Optional[str]  # Requested tool name
    resource: Optional[str]# Target resource identifier
    context: Dict[str, Any]# Environment / session context
    timestamp: str         # ISO 8601 UTC timestamp
    details: Dict[str, Any]# Telemetry diagnostic details

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SecurityPolicyEngine:
    """
    Independent External Security Policy Engine for AgentShield.
    Enforces Tool Allowlisting, Strict Parameter Schemas, Role-Based Access Control (RBAC),
    Resource-Level Access Control (RLAC Default-Deny), and Dynamic Taint Invariants.
    """

    def __init__(
        self,
        default_role: str = "analyst",
        enable_rbac: bool = True,
        enable_rlac: bool = True,
        enable_taint: bool = True
    ):
        self.default_role = default_role
        self.enable_rbac = enable_rbac
        self.enable_rlac = enable_rlac
        self.enable_taint = enable_taint

    def authorize(
        self,
        subject: Dict[str, Any],
        action: Optional[str],
        resource: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        arguments: Optional[Dict[str, Any]] = None,
        untrusted_sources: Optional[List[str]] = None
    ) -> PolicyDecision:
        """
        Centralized enterprise authorization decision interface:
        authorize(subject, action, resource, context) -> PolicyDecision
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        context = context or {}
        arguments = arguments if arguments is not None else {}
        untrusted_sources = untrusted_sources or []

        user_role = str(subject.get("user_role", self.default_role)).lower()
        user_id = str(subject.get("user_id", "unknown_user"))
        subject_record = {"user_id": user_id, "user_role": user_role}

        # ---------------------------------------------------------
        # Check 1: Null / None tool proposal handling
        # ---------------------------------------------------------
        if not action or action.lower() in ("none", "null"):
            return PolicyDecision(
                decision="ALLOW",
                allowed=True,
                decision_code="NO_TOOL_PROPOSED",
                policy_id="POL-NO-OP",
                reason="No active tool operation requested.",
                subject=subject_record,
                action=None,
                resource=None,
                context=context,
                timestamp=timestamp,
                details={}
            )

        # ---------------------------------------------------------
        # Check 2: Tool Allowlisting Check
        # ---------------------------------------------------------
        if action not in ALLOWED_TOOLS:
            return PolicyDecision(
                decision="DENY",
                allowed=False,
                decision_code="DENIED_UNREGISTERED_TOOL",
                policy_id="POL-TOOL-ALLOWLIST",
                reason=f"Tool '{action}' is not in the authorized tool allowlist.",
                subject=subject_record,
                action=action,
                resource=resource,
                context=context,
                timestamp=timestamp,
                details={"attempted_tool": action}
            )

        # ---------------------------------------------------------
        # Check 3: Arguments structure validation
        # ---------------------------------------------------------
        if not isinstance(arguments, dict):
            return PolicyDecision(
                decision="INVALID_REQUEST",
                allowed=False,
                decision_code="DENIED_INVALID_ARGUMENT_STRUCTURE",
                policy_id="POL-SCHEMA-FORMAT",
                reason="Tool arguments must be supplied as a valid JSON dictionary.",
                subject=subject_record,
                action=action,
                resource=resource,
                context=context,
                timestamp=timestamp,
                details={"arguments_type": type(arguments).__name__}
            )

        # ---------------------------------------------------------
        # Check 4: Schema & Parameter Validation
        # ---------------------------------------------------------
        schema = TOOL_SCHEMAS.get(action)
        if schema:
            # Check required parameters
            for req in schema["required"]:
                if req not in arguments:
                    return PolicyDecision(
                        decision="INVALID_REQUEST",
                        allowed=False,
                        decision_code="DENIED_MISSING_REQUIRED_ARGUMENT",
                        policy_id="POL-SCHEMA-REQUIRED",
                        reason=f"Missing required parameter '{req}' for tool '{action}'.",
                        subject=subject_record,
                        action=action,
                        resource=resource,
                        context=context,
                        timestamp=timestamp,
                        details={"missing_param": req}
                    )
                val = arguments[req]
                if isinstance(val, str) and not val.strip():
                    return PolicyDecision(
                        decision="INVALID_REQUEST",
                        allowed=False,
                        decision_code="DENIED_EMPTY_PARAMETER",
                        policy_id="POL-SCHEMA-NONEMPTY",
                        reason=f"Parameter '{req}' cannot be empty.",
                        subject=subject_record,
                        action=action,
                        resource=resource,
                        context=context,
                        timestamp=timestamp,
                        details={"parameter": req}
                    )

            # Check for unexpected parameters
            all_allowed_params = set(schema["required"]) | set(schema.get("optional", []))
            for arg_k in arguments.keys():
                if arg_k not in all_allowed_params:
                    return PolicyDecision(
                        decision="INVALID_REQUEST",
                        allowed=False,
                        decision_code="DENIED_UNEXPECTED_ARGUMENT",
                        policy_id="POL-SCHEMA-EXTRA-KEYS",
                        reason=f"Unexpected parameter '{arg_k}' rejected by schema policy.",
                        subject=subject_record,
                        action=action,
                        resource=resource,
                        context=context,
                        timestamp=timestamp,
                        details={"unexpected_param": arg_k}
                    )

            # Check parameter types and length bounds
            for param, expected_type in schema["types"].items():
                if param in arguments:
                    val = arguments[param]
                    if not isinstance(val, expected_type):
                        return PolicyDecision(
                            decision="INVALID_REQUEST",
                            allowed=False,
                            decision_code="DENIED_TYPE_MISMATCH",
                            policy_id="POL-SCHEMA-TYPE",
                            reason=f"Parameter '{param}' expected {expected_type}, received {type(val)}.",
                            subject=subject_record,
                            action=action,
                            resource=resource,
                            context=context,
                            timestamp=timestamp,
                            details={"param": param, "val": str(val)}
                        )
                    if isinstance(val, str):
                        max_len = schema.get("max_len", {}).get(param, 500)
                        if len(val) > max_len:
                            return PolicyDecision(
                                decision="INVALID_REQUEST",
                                allowed=False,
                                decision_code="DENIED_PARAMETER_LENGTH_EXCEEDED",
                                policy_id="POL-SCHEMA-MAXLEN",
                                reason=f"Parameter '{param}' exceeds maximum length of {max_len}.",
                                subject=subject_record,
                                action=action,
                                resource=resource,
                                context=context,
                                timestamp=timestamp,
                                details={"param": param, "length": len(val), "max": max_len}
                            )

        # ---------------------------------------------------------
        # Check 5: Role-Based Access Control (RBAC)
        # ---------------------------------------------------------
        if self.enable_rbac and not RolePermissionMatrix.is_tool_permitted(user_role, action):
            return PolicyDecision(
                decision="DENY",
                allowed=False,
                decision_code="DENIED_RBAC_UNAUTHORIZED",
                policy_id="POL-RBAC-001",
                reason=f"Role '{user_role}' is not authorized to execute operation '{action}'.",
                subject=subject_record,
                action=action,
                resource=resource,
                context=context,
                timestamp=timestamp,
                details={"user_role": user_role, "required_tool": action}
            )

        # ---------------------------------------------------------
        # Check 6: Resource-Level Access Control (RLAC Default-Deny)
        # ---------------------------------------------------------
        resolved_resource = resource or arguments.get("document_id") or arguments.get("table") or arguments.get("record_id")
        
        if self.enable_rlac and resolved_resource:
            res_str = str(resolved_resource).strip()
            
            # Fail-Closed Rule (SEC-01): Unknown resources MUST be denied by default!
            if res_str not in RESOURCE_REGISTRY:
                return PolicyDecision(
                    decision="DENY",
                    allowed=False,
                    decision_code="DENIED_UNKNOWN_RESOURCE",
                    policy_id="POL-RLAC-DEFAULT-DENY",
                    reason=f"Resource '{res_str}' is not registered in the resource catalog and is denied by default (Fail-Closed).",
                    subject=subject_record,
                    action=action,
                    resource=res_str,
                    context=context,
                    timestamp=timestamp,
                    details={"resource": res_str, "status": "unregistered"}
                )

            classification = RESOURCE_REGISTRY[res_str]

            if not RolePermissionMatrix.is_resource_permitted(user_role, classification):
                return PolicyDecision(
                    decision="DENY",
                    allowed=False,
                    decision_code="DENIED_RLAC_UNAUTHORIZED",
                    policy_id="POL-RLAC-CLEARANCE",
                    reason=f"Role '{user_role}' lacks clearance for resource '{res_str}' ({classification}).",
                    subject=subject_record,
                    action=action,
                    resource=res_str,
                    context=context,
                    timestamp=timestamp,
                    details={"resource_id": res_str, "classification": classification, "user_role": user_role}
                )

        # ---------------------------------------------------------
        # Check 7: Dynamic Taint Propagation Check (SEC-03)
        # ---------------------------------------------------------
        if self.enable_taint:
            is_tainted, taint_reason = TaintTracker.is_tainted_by_untrusted_source(action, arguments, untrusted_sources)
            if is_tainted:
                return PolicyDecision(
                    decision="DENY",
                    allowed=False,
                    decision_code="DENIED_TAINT_PROPAGATION",
                    policy_id="POL-TAINT-001",
                    reason=f"Adversarial taint propagation detected: {taint_reason}",
                    subject=subject_record,
                    action=action,
                    resource=resolved_resource,
                    context=context,
                    timestamp=timestamp,
                    details={"taint_reason": taint_reason}
                )

            # Static argument marker check
            for k, v in arguments.items():
                if isinstance(v, str):
                    injections = TaintTracker.scan_for_injection_markers(v)
                    if injections:
                        return PolicyDecision(
                            decision="DENY",
                            allowed=False,
                            decision_code="DENIED_TAINTED_ARGUMENT",
                            policy_id="POL-TAINT-002",
                            reason=f"Adversarial injection tokens detected in parameter '{k}': {injections}",
                            subject=subject_record,
                            action=action,
                            resource=resolved_resource,
                            context=context,
                            timestamp=timestamp,
                            details={"param": k, "markers": injections}
                        )

        # ---------------------------------------------------------
        # All Invariants Satisfied: ALLOW
        # ---------------------------------------------------------
        return PolicyDecision(
            decision="ALLOW",
            allowed=True,
            decision_code="ALLOWED",
            policy_id="POL-ALLOW-STANDARD",
            reason=f"Operation '{action}' verified against all security invariants.",
            subject=subject_record,
            action=action,
            resource=resolved_resource,
            context=context,
            timestamp=timestamp,
            details={"user_role": user_role, "arguments": arguments}
        )

    def evaluate(
        self,
        tool_name: Optional[str],
        tool_args: Dict[str, Any],
        session_context: Optional[Dict[str, Any]] = None,
        state_history: Optional[List[Dict[str, Any]]] = None,
        untrusted_sources: Optional[List[str]] = None
    ) -> PolicyDecision:
        """Evaluates tool invocation candidate, maintaining compatibility with LangGraph node."""
        session_context = session_context or {}
        subject = {
            "user_role": session_context.get("user_role", self.default_role),
            "user_id": session_context.get("user_id", "session_user_01")
        }
        resource = tool_args.get("document_id") or tool_args.get("table") or tool_args.get("record_id")
        return self.authorize(
            subject=subject,
            action=tool_name,
            resource=resource,
            context=session_context,
            arguments=tool_args,
            untrusted_sources=untrusted_sources
        )


# Global policy engine singleton
policy_engine = SecurityPolicyEngine()


def authorize_tool(
    tool_name: str,
    arguments: Dict[str, Any],
    session_context: Optional[Dict[str, Any]] = None
) -> bool:
    """
    Standard backward-compatible boolean authorization check.
    """
    decision = policy_engine.evaluate(tool_name, arguments, session_context)
    return decision.allowed
