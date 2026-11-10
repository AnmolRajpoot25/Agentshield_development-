from typing import Dict, List, Set

class RolePermissionMatrix:
    """
    Role-Based Access Control (RBAC) matrix defining permissions
    and permitted resource classification levels per role.
    """

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

    ROLE_RESOURCE_CLEARANCE: Dict[str, Set[str]] = {
        "anonymous": {"PUBLIC"},
        "viewer": {"PUBLIC"},
        "analyst": {"PUBLIC", "INTERNAL"},
        "admin": {"PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"},
        "system_auditor": {"PUBLIC", "INTERNAL", "CONFIDENTIAL"}
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

