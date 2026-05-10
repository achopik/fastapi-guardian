import typing

from pydantic import (
    BaseModel,
    Field,
    SerializerFunctionWrapHandler,
    ValidationError,
    model_serializer,
    model_validator,
)

from fastapi_guardian.resource import Resource

Identifier = str | int
AuthScope = typing.Literal["global", "conditional", "resource"]


class BasePermissionGrant(BaseModel):
    resource: str
    action: str
    scope: AuthScope

    @model_serializer(mode="wrap")
    def to_json(self, handler: SerializerFunctionWrapHandler) -> dict:
        serialized = handler(self)
        resource = serialized.pop("resource")
        action = serialized.pop("action")
        scope = serialized.pop("scope")
        return {
            "resource": resource,
            "action": action,
            "scope": scope,
            "extra": serialized,
        }

    @model_validator(mode="before")
    @classmethod
    def from_json(cls, data: typing.Any) -> typing.Any:
        if isinstance(data, dict):
            extra = data.pop("extra", {})
            return {**data, **extra}
        return data


class GlobalPermissionGrant(BasePermissionGrant):
    scope: typing.Literal["global"] = "global"


class ConditionalPermissionGrant(BasePermissionGrant):
    scope: typing.Literal["conditional"] = "conditional"
    condition: str


class ResourcePermissionGrant(BasePermissionGrant):
    scope: typing.Literal["resource"] = "resource"
    resource_id: str


PermissionGrant = (
    GlobalPermissionGrant | ConditionalPermissionGrant | ResourcePermissionGrant
)


class PermissionContext(BaseModel):
    permissions: list[typing.Annotated[PermissionGrant, Field(discriminator="scope")]]


class Principal[ID: Identifier](PermissionContext):
    id: ID
    email: str
    username: str
    roles: list[str] = Field(default_factory=list)


class PredicateContext[T: type[Resource], ID: Identifier](BaseModel):
    principal: Principal[ID]
    resource: T


class AuthPredicate[T: type[Resource], ID: Identifier](BaseModel):
    fn: typing.Callable[[PredicateContext[T, ID]], typing.Any]
    name: str
    description: str = Field(default="", min_length=0)


class AuthPredicatePayload[T: type[Resource], ID: Identifier](typing.TypedDict):
    fn: typing.Callable[[PredicateContext[T, ID]], typing.Any]
    name: str
    description: typing.NotRequired[str]


class PermissionDefinition[T: type[Resource], ID: Identifier](BaseModel):
    """Defines permission required for a given API resource along with all auth metadata."""

    resource: T
    action: str
    scopes: typing.Annotated[list[AuthScope], Field(default_factory=lambda: ["global"])]
    predicates: typing.Annotated[
        list[AuthPredicate[T, ID]], Field(default_factory=list)
    ]

    @model_validator(mode="after")
    def validate_predicates(self) -> typing.Any:
        if "conditional" in self.scopes and not self.predicates:
            raise ValidationError(
                "Conditional permissions must have at least one predicate"
            )
        return self


class AuthContext[T: type[Resource], ID: Identifier](BaseModel):
    """Defines all related info to make authorization decision."""

    principal: Principal
    current_permission: PermissionDefinition[T, ID]
