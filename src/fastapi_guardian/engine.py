from collections import defaultdict

from fastapi_guardian import exceptions
from fastapi_guardian.dto import AuthContext, PermissionDefinition, PermissionGrant
from fastapi_guardian.resource import Resource


class BaseAuthEngine:
    _permissions: list[PermissionDefinition]
    # resource -> action -> PermissionDefinition
    _permission_tree: dict[str, dict[str, PermissionDefinition]]

    def __init__(self) -> None:
        self._permissions = []
        self._permission_tree = defaultdict(dict)

    def has_permission(self, *, context: AuthContext) -> bool:
        """Check if the principal has ANY permission for the given resource and action."""
        decision = bool(self.matching_grants(context=context))
        self.log_decision(context=context, decision=decision)
        return decision

    def matching_grants(self, *, context: AuthContext) -> list[PermissionGrant]:
        """Get all permission grants that match the given principal, resource and action."""
        return [
            grant
            for grant in context.principal.permissions
            if grant.resource == context.current_permission.resource.__resource_code__
            and grant.action == context.current_permission.action
        ]

    def log_decision(self, *, context: AuthContext, decision: bool) -> None:
        """Implement in subclass to log access decision."""
        return None

    def register_permission(self, permission: PermissionDefinition) -> None:
        """
        Register new permission into catalog of this engine.
        Can be used later for introspection and administration (e.g., show list of supported permissions in UI, modify OpenAPI schema, etc.)
        """
        resource_code = permission.resource.__resource_code__
        if (
            self._permission_tree.get(resource_code, {}).get(permission.action)
            is not None
        ):
            raise exceptions.ImproperlyConfigured(
                f"Permission {permission.action} already registered for resource {resource_code}."
                "To avoid confusion, it's currently impossible to re-register the same permission."
            )

        self._permissions.append(permission)
        self._permission_tree[resource_code][permission.action] = permission

    def permissions_for(self, resource: type[Resource]) -> list[PermissionDefinition]:
        """Retuns all registered permissions for the given resource."""
        return list(self._permission_tree[resource.__resource_code__].values())

    @property
    def permissions_by_resource(self) -> dict[str, list[PermissionDefinition]]:
        """Returns all registered permissions grouped by resource."""
        return {k: list(v.values()) for k, v in self._permission_tree.items()}

    @property
    def permissions(self) -> list[PermissionDefinition]:
        """Returns all registered permissions."""
        return self._permissions
