from typing import Any, Dict, List, Optional, Set


class RolePermissionMatrix:
    """
    Role-Based Access Control (RBAC) matrix defining permissions,
    allowed operations, and permitted resource classification levels per role.
    """

    # Operation-level tool permissions per role
    ROLE_PERMISSIONS: Dict[str, Set[str]] = {
        "anonymous": set(),
        "viewer": {
            "search_documents",
            "summarize_document"
        },
        "analyst": {
            "search_documents",
            "summarize_document",
            "read_document",
            "query_database"
        },
        "admin": {
            "search_documents",
            "summarize_document",
            "read_document",
            "query_database",
            "send_email",
            "delete_records"
        },
        "system_auditor": {
            "search_documents",
            "summarize_document",
            "read_document",
            "query_database",
            "audit_logs"
        }
    }

    # Resource classification clearances per role
    ROLE_RESOURCE_CLEARANCE: Dict[str, Set[str]] = {
        "anonymous": {"PUBLIC"},
        "viewer": {"PUBLIC"},
        "analyst": {"PUBLIC", "INTERNAL"},
        "admin": {"PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"},
        "system_auditor": {"PUBLIC", "INTERNAL", "CONFIDENTIAL"}
    }

    # Destructive operations requiring explicit administrative privilege
    DESTRUCTIVE_TOOLS: Set[str] = {
        "delete_records",
        "drop_table",
        "system_shell",
        "execute_command"
    }

    @classmethod
    def is_tool_permitted(cls, role: str, tool_name: str) -> bool:
        """Checks if a user role is permitted to call the given tool."""
        permitted = cls.ROLE_PERMISSIONS.get(role.lower(), set())
        return tool_name in permitted

    @classmethod
    def is_resource_permitted(cls, role: str, classification_level: str) -> bool:
        """Checks if a user role has clearance to read the given resource classification."""
        clearances = cls.ROLE_RESOURCE_CLEARANCE.get(role.lower(), set())
        return classification_level.upper() in clearances

    @classmethod
    def is_destructive(cls, tool_name: str) -> bool:
        """Checks if a tool is categorized as a destructive or irreversible operation."""
        return tool_name in cls.DESTRUCTIVE_TOOLS

    @classmethod
    def get_allowed_clearances(cls, role: str) -> Set[str]:
        """Returns the set of classification levels permitted for a role."""
        return cls.ROLE_RESOURCE_CLEARANCE.get(role.lower(), {"PUBLIC"})
