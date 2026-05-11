import typing

import pytest
import pytest_asyncio
from fastapi import Depends
from pydantic import ValidationError
from tortoise import Tortoise, fields, models
from tortoise.expressions import Q

from fastapi_guardian import exceptions
from fastapi_guardian.dependencies import BasePermission
from fastapi_guardian.dto import (
    AuthContext,
    AuthPredicate,
    ConditionalPermissionGrant,
    GlobalPermissionGrant,
    PermissionDefinition,
    Principal,
    ResourcePermissionGrant,
)
from fastapi_guardian.ext.tortoise import (
    TortoiseAuthEngine,
    TortoisePermissionExpression,
    TortoiseResource,
)


class Base(TortoiseResource, models.Model):
    __resource_app_name__ = "auth"
    id = fields.IntField(primary_key=True)

    class Meta:
        abstract = True


class User(Base):
    __resource_name__ = "user"

    username = fields.CharField(max_length=255)
    email = fields.CharField(max_length=255)


@pytest_asyncio.fixture()
async def tortoise_test_app():
    await Tortoise.close_connections()
    await Tortoise.init(
        db_url="sqlite://:memory:",
        modules={"auth": [__name__]},
    )
    await Tortoise.generate_schemas()
    await User.bulk_create(
        [
            User(id=1, username="admin", email="admin@example.com"),
            User(id=42, username="alice", email="alice@example.com"),
            User(id=43, username="bob", email="bob@example.com"),
            User(id=44, username="guest", email="guest@example.com"),
        ]
    )
    yield
    await Tortoise.close_connections()


predicates = [
    AuthPredicate[type[User], str](
        name="self", fn=lambda context: Q(id=context.principal.id)
    ),
    AuthPredicate[type[User], str](
        name="only_admin_email",
        fn=lambda context: Q(email="admin@example.com"),
    ),
    AuthPredicate[type[User], str](
        name="only_admin_username",
        fn=lambda context: Q(username="admin"),
    ),
]

admin_principal = Principal[str](
    id="1",
    email="admin@example.com",
    username="admin",
    permissions=[
        ConditionalPermissionGrant(
            resource="user",
            action="read",
            condition="self",
        )
    ],
)


@pytest.mark.parametrize(
    ("expression_str", "expected_string"),
    [
        (
            "self and (only_admin_email or only_admin_username)",
            "self and (only_admin_email or only_admin_username)",
        ),
        (
            "self or only_admin_email and only_admin_username",
            "self or only_admin_email and only_admin_username",
        ),
        (
            "self and only_admin_email and only_admin_username",
            "self and only_admin_email and only_admin_username",
        ),
        (
            "self or only_admin_email or only_admin_username",
            "self or only_admin_email or only_admin_username",
        ),
        ("self", "self"),
        ("not self", "not self"),
        ("not (self and only_admin_email)", "not (self and only_admin_email)"),
    ],
)
def test__permission_expression_parsing__positive(expression_str, expected_string):
    expression = TortoisePermissionExpression(
        expression=expression_str, predicates=predicates
    )
    assert str(expression) == expected_string


def test_resource_subclass_negative():
    with pytest.raises(exceptions.ImproperlyConfigured):

        class InvalidResource(TortoiseResource):
            pass

        InvalidResource.__resource_code__

    with pytest.raises(exceptions.ImproperlyConfigured):

        class InvalidResourceWithoutAppName(TortoiseResource):
            __resource_name__ = "invalid_resource"

        InvalidResourceWithoutAppName.__resource_code__

    with pytest.raises(exceptions.ImproperlyConfigured):

        class InvalidResourceWithoutTableName(TortoiseResource):
            __resource_app_name__ = "invalid_app"

        InvalidResourceWithoutTableName.__resource_code__


def test_permission_initialization_positive():
    tortoise_auth_engine = TortoiseAuthEngine()

    class Permission(BasePermission[type[Base], str]):
        auth_engine = tortoise_auth_engine

        async def __call__(
            self, principal: Principal | None = Depends(lambda: None)
        ) -> AuthContext:
            return await self.authorize(principal=principal)

    permission = Permission(resource=User, action="read")
    assert permission.permission.resource == User
    assert permission.permission.action == "read"
    assert permission.permission.scopes == ["global"]
    assert permission.permission.predicates == []
    assert permission.auth_engine is tortoise_auth_engine

    tortoise_auth_engine2 = TortoiseAuthEngine()
    permission2 = Permission(
        resource=User, action="read", auth_engine=tortoise_auth_engine2
    )
    assert permission2.auth_engine is tortoise_auth_engine2


def test_permission_initialization_negative():
    with pytest.raises(exceptions.ImproperlyConfigured):

        class Permission(BasePermission[type[Base], str]):
            async def __call__(
                self, principal: Principal | None = Depends(lambda: None)
            ) -> AuthContext:
                return await self.authorize(principal=principal)

        Permission(resource=User, action="read")

    class ValidPermission(BasePermission[type[Base], str]):
        auth_engine = TortoiseAuthEngine()

        async def __call__(
            self, principal: Principal | None = Depends(lambda: None)
        ) -> AuthContext:
            return await self.authorize(principal=principal)

    with pytest.raises(ValidationError):
        ValidPermission(resource=User, action="read", scopes=["global", "conditional"])

    with pytest.raises(exceptions.ImproperlyConfigured):
        ValidPermission(resource=User, action="read")
        ValidPermission(resource=User, action="read")


@pytest.mark.parametrize(
    ("expression_str", "expected_exception"),
    [
        (
            "#self and only_admin_email and only_admin_username",
            exceptions.ExpressionParsingError,
        ),
        (
            "self and only_admin_email and only_admin_username!!",
            exceptions.ExpressionParsingError,
        ),
        (
            "self and only_admin_email and nonexistent_predicate",
            exceptions.InvalidPredicateError,
        ),
    ],
)
def test__permission_expression_parsing__negative(expression_str, expected_exception):
    with pytest.raises(expected_exception):
        TortoisePermissionExpression(expression=expression_str, predicates=predicates)


@pytest.mark.parametrize(
    ("expression_str", "principal_id", "expected_ids"),
    [
        ("self", "42", [42]),
        ("not self", "42", [1, 43, 44]),
        (
            "self and only_admin_email",
            "42",
            [],
        ),
        (
            "self or only_admin_email",
            "42",
            [1, 42],
        ),
    ],
)
@pytest.mark.asyncio
async def test__permission_expression_evaluation__positive(
    tortoise_test_app,
    expression_str,
    principal_id,
    expected_ids,
):
    expression = TortoisePermissionExpression(
        expression=expression_str, predicates=predicates
    )
    query_filter = expression.evaluate(
        context=AuthContext[type[User], str](
            principal=Principal(
                id=principal_id,
                email="alice@example.com",
                username="alice",
                permissions=[],
            ),
            current_permission=PermissionDefinition[type[User], str](
                resource=User,
                action="read",
                predicates=predicates,
            ),
        )
    )

    actual_ids = (
        await User.filter(query_filter).order_by("id").values_list("id", flat=True)
    )

    assert actual_ids == expected_ids


def _raising_predicate_fn(_context):
    raise RuntimeError("predicate failed")


raising_predicates = [
    *predicates,
    AuthPredicate[type[User], str](name="raising", fn=_raising_predicate_fn),
]


@pytest.mark.parametrize(
    "expression_str",
    [
        "raising",
        "not raising",
        "raising and self",
        "self or raising",
        "not (raising and self)",
    ],
)
def test__permission_expression_evaluation__negative(expression_str):
    expression = TortoisePermissionExpression(
        expression=expression_str, predicates=raising_predicates
    )
    with pytest.raises(exceptions.ExpressionEvaluationError):
        expression.evaluate(
            context=AuthContext[type[User], str](
                principal=admin_principal,
                current_permission=PermissionDefinition[type[User], str](
                    resource=User,
                    action="read",
                    scopes=["global", "conditional"],
                    predicates=raising_predicates,
                ),
            )
        )


def _make_principal(*permissions) -> Principal:
    return Principal(
        id="1",
        email="admin@example.com",
        username="admin",
        permissions=list(permissions),
    )


def _make_context(principal: Principal, *, resource=User, action="read") -> AuthContext:
    return AuthContext(
        principal=principal,
        current_permission=PermissionDefinition(
            resource=resource,
            action=action,
            scopes=["global", "conditional", "resource"],
            predicates=[
                AuthPredicate[type[User], str](
                    name="self",
                    fn=lambda context: Q(id=context.principal.id),
                ),
                {
                    "name": "only_admin_email",
                    "fn": lambda context: Q(email="admin@example.com"),
                },
            ],
        ),
    )


async def _filtered_user_ids(context: AuthContext) -> list[int]:
    query = engine.filter_query(context=context, query=User.all())
    return await typing.cast(
        list[int], query.order_by("id").values_list("id", flat=True)
    )


engine = TortoiseAuthEngine()


class _NoIdResource(TortoiseResource):
    __resource_app_name__ = "auth"
    __resource_name__ = "no_id_resource"


@pytest.mark.parametrize(
    "grant",
    [
        GlobalPermissionGrant(resource="auth.user", action="read"),
        ConditionalPermissionGrant(
            resource="auth.user", action="read", condition="self"
        ),
        ResourcePermissionGrant(resource="auth.user", action="read", resource_id="42"),
    ],
)
def test__has_permission__positive(grant):
    context = _make_context(_make_principal(grant))
    assert engine.has_permission(context=context) is True


@pytest.mark.parametrize(
    "grants",
    [
        [],
        [GlobalPermissionGrant(resource="auth.role", action="read")],
        [GlobalPermissionGrant(resource="auth.user", action="update")],
        [GlobalPermissionGrant(resource="auth.role", action="update")],
    ],
)
def test__has_permission__negative(grants):
    context = _make_context(_make_principal(*grants))
    assert engine.has_permission(context=context) is False


def test__matching_grants__filters_by_resource_and_action():
    matching = ConditionalPermissionGrant(
        resource="auth.user", action="read", condition="self"
    )
    wrong_resource = GlobalPermissionGrant(resource="auth.role", action="read")
    wrong_action = GlobalPermissionGrant(resource="auth.user", action="update")
    context = _make_context(_make_principal(matching, wrong_resource, wrong_action))

    assert engine.matching_grants(context=context) == [matching]


def test__matching_grants__no_grants__returns_empty():
    context = _make_context(_make_principal())
    assert engine.matching_grants(context=context) == []


@pytest.mark.asyncio
async def test__filter_query__no_matching_grants__filters_out_all(tortoise_test_app):
    grant = GlobalPermissionGrant(resource="auth.role", action="read")
    context = _make_context(_make_principal(grant))
    assert await _filtered_user_ids(context) == []


@pytest.mark.asyncio
async def test__filter_query__global_scope__allows_all(tortoise_test_app):
    grant = GlobalPermissionGrant(resource="auth.user", action="read")
    context = _make_context(_make_principal(grant))
    assert await _filtered_user_ids(context) == [1, 42, 43, 44]


@pytest.mark.asyncio
async def test__filter_query__resource_scope__filters_by_id_in(tortoise_test_app):
    grants = [
        ResourcePermissionGrant(resource="auth.user", action="read", resource_id="42"),
        ResourcePermissionGrant(resource="auth.user", action="read", resource_id="43"),
    ]
    context = _make_context(_make_principal(*grants))
    assert await _filtered_user_ids(context) == [42, 43]


@pytest.mark.asyncio
async def test__filter_query__conditional_scope__filters_by_expression(
    tortoise_test_app,
):
    grant = ConditionalPermissionGrant(
        resource="auth.user", action="read", condition="self"
    )
    principal = _make_principal(grant)
    context = _make_context(principal)
    assert await _filtered_user_ids(context) == [int(principal.id)]


@pytest.mark.asyncio
async def test__filter_query__resource_and_conditional__combined_with_or(
    tortoise_test_app,
):
    grants = [
        ConditionalPermissionGrant(
            resource="auth.user", action="read", condition="self"
        ),
        ResourcePermissionGrant(resource="auth.user", action="read", resource_id="42"),
    ]
    principal = _make_principal(*grants)
    context = _make_context(principal)
    assert await _filtered_user_ids(context) == [1, 42]


@pytest.mark.asyncio
async def test__filter_query__global_short_circuits_other_scopes(tortoise_test_app):
    grants = [
        ConditionalPermissionGrant(
            resource="auth.user", action="read", condition="self"
        ),
        GlobalPermissionGrant(resource="auth.user", action="read"),
        ResourcePermissionGrant(resource="auth.user", action="read", resource_id="42"),
    ]
    context = _make_context(_make_principal(*grants))
    assert await _filtered_user_ids(context) == [1, 42, 43, 44]


@pytest.mark.asyncio
async def test__filter_query__resource_scope_without_id_column__raises(
    tortoise_test_app,
):
    grant = ResourcePermissionGrant(
        resource="auth.no_id_resource", action="read", resource_id="42"
    )
    context = _make_context(_make_principal(grant), resource=_NoIdResource)
    with pytest.raises(exceptions.ImproperlyConfigured):
        engine.filter_query(context=context, query=User.all())


@pytest.mark.asyncio
async def test__filter_query__conditional_scope_with_unparseable_condition__raises(
    tortoise_test_app,
):
    grant = ConditionalPermissionGrant(
        resource="auth.user", action="read", condition="!!invalid!!"
    )
    context = _make_context(_make_principal(grant))
    with pytest.raises(exceptions.ExpressionParsingError):
        engine.filter_query(context=context, query=User.all())


@pytest.mark.asyncio
async def test__filter_query__conditional_scope_with_unknown_predicate__raises(
    tortoise_test_app,
):
    grant = ConditionalPermissionGrant(
        resource="auth.user", action="read", condition="nonexistent_predicate"
    )
    context = _make_context(_make_principal(grant))
    with pytest.raises(exceptions.InvalidPredicateError):
        engine.filter_query(context=context, query=User.all())


@pytest.mark.parametrize(
    ("grant", "extra"),
    [
        (GlobalPermissionGrant(resource="auth.user", action="read"), {}),
        (
            ConditionalPermissionGrant(
                resource="auth.user", action="read", condition="self"
            ),
            {"condition": "self"},
        ),
        (
            ResourcePermissionGrant(
                resource="auth.user", action="read", resource_id="42"
            ),
            {"resource_id": "42"},
        ),
    ],
)
def test__grants__serialization_deserialization(grant, extra):
    serialized = grant.model_dump()
    assert serialized["scope"] == grant.scope
    assert serialized["resource"] == grant.resource
    assert serialized["action"] == grant.action
    assert serialized["extra"] == extra

    assert type(grant)(**serialized) == grant
