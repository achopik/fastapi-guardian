import abc
import typing

from fastapi.exceptions import HTTPException

from fastapi_guardian import exceptions
from fastapi_guardian.dto import (
    AuthContext,
    AuthPredicatePayload,
    AuthScope,
    Identifier,
    PermissionDefinition,
    Principal,
)
from fastapi_guardian.engine import BaseAuthEngine
from fastapi_guardian.resource import Resource


class BasePermission[T: type[Resource], ID: Identifier](abc.ABC):
    __slots__ = ("permission", "auth_engine")

    auth_engine: BaseAuthEngine

    def __init__(
        self,
        resource: T,
        action: str,
        scopes: list[AuthScope] | None = None,
        predicates: list[AuthPredicatePayload[T, ID]] | None = None,
        auth_engine: BaseAuthEngine | None = None,
    ) -> None:
        if auth_engine is not None:
            self.auth_engine = auth_engine

        if self.auth_engine is None:
            raise exceptions.ImproperlyConfigured(
                "auth_engine is required either as argument or as class attribute"
            )

        self.permission = PermissionDefinition[T, ID](
            resource=resource,
            action=action,
            scopes=scopes or ["global"],
            predicates=predicates or [],
        )
        self.auth_engine.register_permission(permission=self.permission)

    @abc.abstractmethod
    async def __call__(self, *args: typing.Any, **kwargs: typing.Any) -> AuthContext:
        pass

    async def authorize(self, principal: Principal[ID] | None = None) -> AuthContext:
        if principal is None:
            raise HTTPException(status_code=401, detail="Unauthorized")

        context = AuthContext[T, ID](
            principal=principal, current_permission=self.permission
        )
        access_granted = self.auth_engine.has_permission(context=context)
        if access_granted:
            return context

        raise HTTPException(status_code=403, detail="Forbidden")
