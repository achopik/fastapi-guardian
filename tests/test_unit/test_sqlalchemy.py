import pytest
from fastapi import Depends
from pydantic import ValidationError
from sqlalchemy import Select, and_, false, not_, or_, select, true, types
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

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
from fastapi_guardian.ext.sqlalchemy import (
    SqlalchemyAuthEngine,
    SqlalchemyPermissionExpression,
    SqlalchemyResource,
)


class Base(DeclarativeBase, SqlalchemyResource, __resource_abstract__=True):
    __resource_app_name__ = "auth"
    id: Mapped[int] = mapped_column(types.Integer, primary_key=True, autoincrement=True)


class User(Base):
    __tablename__ = "user"

    username: Mapped[str] = mapped_column(types.String(255))
    email: Mapped[str] = mapped_column(types.String(255))


predicates = [
    AuthPredicate[type[User], str](
        name="self", fn=lambda context: context.resource.id == context.principal.id
    ),
    AuthPredicate[type[User], str](
        name="only_admin_email",
        fn=lambda context: context.resource.email == "admin@example.com",
    ),
    AuthPredicate[type[User], str](
        name="only_admin_username",
        fn=lambda context: context.resource.username == "admin",
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
    expression = SqlalchemyPermissionExpression(
        expression=expression_str, predicates=predicates
    )
    assert str(expression) == expected_string


def test_resource_subclass_negative():
    with pytest.raises(exceptions.ImproperlyConfigured):

        class InvalidResource(SqlalchemyResource):
            pass

    with pytest.raises(exceptions.ImproperlyConfigured):

        class InvalidResourceWithoutAppName(SqlalchemyResource):
            __resource_name__ = "invalid_resource"

    with pytest.raises(exceptions.ImproperlyConfigured):

        class InvalidResourceWithoutTableName(SqlalchemyResource):
            __resource_app_name__ = "invalid_app"


def test_permission_initialization_positive():
    sa_auth_engine = SqlalchemyAuthEngine()

    class Permission(BasePermission[type[Base], str]):
        auth_engine = sa_auth_engine

        async def __call__(
            self, principal: Principal | None = Depends(lambda: None)
        ) -> AuthContext:
            return await self.authorize(principal=principal)

    permission = Permission(resource=User, action="read")
    assert permission.permission.resource == User
    assert permission.permission.action == "read"
    assert permission.permission.scopes == ["global"]
    assert permission.permission.predicates == []
    assert permission.auth_engine is sa_auth_engine

    sa_auth_engine2 = SqlalchemyAuthEngine()
    permission2 = Permission(resource=User, action="read", auth_engine=sa_auth_engine2)
    assert permission2.auth_engine is sa_auth_engine2


def test_permission_initialization_negative():
    with pytest.raises(exceptions.ImproperlyConfigured):

        class Permission(BasePermission[type[Base], str]):
            async def __call__(
                self, principal: Principal | None = Depends(lambda: None)
            ) -> AuthContext:
                return await self.authorize(principal=principal)

        Permission(resource=User, action="read")

    with pytest.raises(ValidationError):

        class ValidPermission(BasePermission[type[Base], str]):
            auth_engine = SqlalchemyAuthEngine()

            async def __call__(
                self, principal: Principal | None = Depends(lambda: None)
            ) -> AuthContext:
                return await self.authorize(principal=principal)

        ValidPermission(resource=User, action="read", scopes=["global", "conditional"])


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
        SqlalchemyPermissionExpression(expression=expression_str, predicates=predicates)


@pytest.mark.parametrize(
    ("expression_str", "expected_result"),
    [
        ("self", User.id == admin_principal.id),
        ("not self", not_(User.id == admin_principal.id)),
        (
            "self and only_admin_email",
            and_(User.id == admin_principal.id, User.email == "admin@example.com"),
        ),
        (
            "self or only_admin_email",
            or_(User.id == admin_principal.id, User.email == "admin@example.com"),
        ),
    ],
)
def test__permission_expression_evaluation__positive(expression_str, expected_result):
    expression = SqlalchemyPermissionExpression(
        expression=expression_str, predicates=predicates
    )
    assert str(
        expression.evaluate(
            context=AuthContext[type[User], str](
                principal=admin_principal,
                current_permission=PermissionDefinition[type[User], str](
                    resource=User,
                    action="read",
                    predicates=predicates,
                ),
            )
        )
    ) == str(expected_result)


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
    expression = SqlalchemyPermissionExpression(
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
                    fn=lambda context: context.resource.id == context.principal.id,
                ),
                {
                    "name": "only_admin_email",
                    "fn": lambda context: context.resource.email == "admin@example.com",
                },
            ],
        ),
    )


def _whereclause_str(query: Select) -> str:
    assert query.whereclause is not None
    return str(query.whereclause)


engine = SqlalchemyAuthEngine()


class _NoIdResource(SqlalchemyResource):
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


def test__filter_query__no_matching_grants__filters_out_all():
    grant = GlobalPermissionGrant(resource="auth.role", action="read")
    context = _make_context(_make_principal(grant))
    query = engine.filter_query(context=context, query=select(User))
    assert _whereclause_str(query) == str(false())


def test__filter_query__global_scope__allows_all():
    grant = GlobalPermissionGrant(resource="auth.user", action="read")
    context = _make_context(_make_principal(grant))
    query = engine.filter_query(context=context, query=select(User))
    assert _whereclause_str(query) == str(true())


def test__filter_query__resource_scope__filters_by_id_in():
    grants = [
        ResourcePermissionGrant(resource="auth.user", action="read", resource_id="42"),
        ResourcePermissionGrant(resource="auth.user", action="read", resource_id="43"),
    ]
    context = _make_context(_make_principal(*grants))
    query = engine.filter_query(context=context, query=select(User))
    assert _whereclause_str(query) == str(or_(User.id.in_(["42", "43"])))


def test__filter_query__conditional_scope__filters_by_expression():
    grant = ConditionalPermissionGrant(
        resource="auth.user", action="read", condition="self"
    )
    principal = _make_principal(grant)
    context = _make_context(principal)
    query = engine.filter_query(context=context, query=select(User))
    assert _whereclause_str(query) == str(or_(User.id == principal.id))


def test__filter_query__resource_and_conditional__combined_with_or():
    grants = [
        ConditionalPermissionGrant(
            resource="auth.user", action="read", condition="self"
        ),
        ResourcePermissionGrant(resource="auth.user", action="read", resource_id="42"),
    ]
    principal = _make_principal(*grants)
    context = _make_context(principal)
    query = engine.filter_query(context=context, query=select(User))
    expected = or_(User.id == principal.id, User.id.in_(["42"]))
    assert _whereclause_str(query) == str(expected)


def test__filter_query__global_short_circuits_other_scopes():
    grants = [
        ConditionalPermissionGrant(
            resource="auth.user", action="read", condition="self"
        ),
        GlobalPermissionGrant(resource="auth.user", action="read"),
        ResourcePermissionGrant(resource="auth.user", action="read", resource_id="42"),
    ]
    context = _make_context(_make_principal(*grants))
    query = engine.filter_query(context=context, query=select(User))
    assert _whereclause_str(query) == str(true())


def test__filter_query__resource_scope_without_id_column__raises():
    grant = ResourcePermissionGrant(
        resource="auth.no_id_resource", action="read", resource_id="42"
    )
    context = _make_context(_make_principal(grant), resource=_NoIdResource)
    with pytest.raises(exceptions.ImproperlyConfigured):
        engine.filter_query(context=context, query=select(User))


def test__filter_query__conditional_scope_with_unparseable_condition__raises():
    grant = ConditionalPermissionGrant(
        resource="auth.user", action="read", condition="!!invalid!!"
    )
    context = _make_context(_make_principal(grant))
    with pytest.raises(exceptions.ExpressionParsingError):
        engine.filter_query(context=context, query=select(User))


def test__filter_query__conditional_scope_with_unknown_predicate__raises():
    grant = ConditionalPermissionGrant(
        resource="auth.user", action="read", condition="nonexistent_predicate"
    )
    context = _make_context(_make_principal(grant))
    with pytest.raises(exceptions.InvalidPredicateError):
        engine.filter_query(context=context, query=select(User))


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
