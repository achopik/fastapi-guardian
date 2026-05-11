import functools
import typing
from collections.abc import Callable

from tortoise.expressions import Q
from tortoise.models import Model
from tortoise.queryset import QuerySet

from fastapi_guardian import exceptions
from fastapi_guardian.dto import AuthContext, AuthPredicate, PredicateContext
from fastapi_guardian.engine import BaseAuthEngine
from fastapi_guardian.expression import (
    AbstractAndNode,
    AbstractNotNode,
    AbstractOrNode,
    AbstractPredicateNode,
    ExpressionTransformer,
    PermissionExpression,
)
from fastapi_guardian.resource import Resource


class TortoisePredicateNode(AbstractPredicateNode):
    def evaluate(self, context: AuthContext) -> Q:
        predicate_context = PredicateContext[type[Resource], typing.Any](
            principal=context.principal, resource=context.current_permission.resource
        )
        return typing.cast("Q", self.predicate.fn(predicate_context))


class TortoiseNotNode(AbstractNotNode):
    def evaluate(self, context: AuthContext) -> Q:
        return ~self.child.evaluate(context)


class TortoiseAndNode(AbstractAndNode):
    def evaluate(self, context: AuthContext) -> Q:
        return functools.reduce(
            lambda left, right: left & right,
            (child.evaluate(context) for child in self.children),
        )


class TortoiseOrNode(AbstractOrNode):
    def evaluate(self, context: AuthContext) -> Q:
        return functools.reduce(
            lambda left, right: left | right,
            (child.evaluate(context) for child in self.children),
        )


AnyTortoiseNode = (
    TortoisePredicateNode | TortoiseNotNode | TortoiseAndNode | TortoiseOrNode
)


class TortoiseExpressionTransformer(ExpressionTransformer[AnyTortoiseNode]):
    predicate_node: type[TortoisePredicateNode] = TortoisePredicateNode
    not_node: type[TortoiseNotNode] = TortoiseNotNode
    and_node: type[TortoiseAndNode] = TortoiseAndNode
    or_node: type[TortoiseOrNode] = TortoiseOrNode


class TortoisePermissionExpression(PermissionExpression):
    def __init__(self, *, expression: str, predicates: list[AuthPredicate]) -> None:
        super().__init__(
            expression=expression,
            predicates=predicates,
            transformer_class=TortoiseExpressionTransformer,
        )


class LazyAttribute[T]:
    def __init__(self, *, getter: Callable[[type], T]) -> None:
        self.getter = getter

    def __get__(self, instance: typing.Any, owner: type[Model]) -> T:
        return self.getter(owner)


def get_resource_name(cls: type[Model]) -> str:
    resource_name = getattr(getattr(cls, "_meta", None), "db_table", None)
    if resource_name:
        return resource_name

    raise exceptions.ImproperlyConfigured(
        "Either __resource_name__ or Tortoise _meta.db_table must be available. Perhaps, you forgot to call Tortoise.init()?"
    )


def get_app_name(cls: type[Model]) -> str:
    resource_app_name = getattr(getattr(cls, "_meta", None), "app", None)
    if resource_app_name:
        return resource_app_name

    raise exceptions.ImproperlyConfigured(
        "Either __resource_app_name__ or Tortoise _meta.app must be available. Perhaps, you forgot to call Tortoise.init()?"
    )


def get_resource_code(cls: type[Resource]) -> str:
    return f"{cls.__resource_app_name__}.{cls.__resource_name__}".lower()


class TortoiseResource(Resource):
    """
    Base class for Tortoise-backed resources.


    Due to Tortoise paradigm of deferred model configuration, resource name and app name are resolved lazily. If no explicit override is set,
    they come from ``_meta.db_table`` and ``_meta.app`` and must be accessed only after ``Tortoise.init()`` has been called.
    """

    __resource_name__: typing.ClassVar[str] = typing.cast(
        "str", LazyAttribute(getter=get_resource_name)
    )
    __resource_app_name__: typing.ClassVar[str] = typing.cast(
        "str", LazyAttribute(getter=get_app_name)
    )
    __resource_code__: typing.ClassVar[str] = typing.cast(
        "str", LazyAttribute(getter=get_resource_code)
    )
    __resource_id_column__: typing.ClassVar[str] = "id"


class TortoiseAuthEngine(BaseAuthEngine):
    def filter_query[T: Model](
        self,
        context: AuthContext[type[TortoiseResource], typing.Any],
        query: QuerySet[T],
    ) -> QuerySet[T]:
        """
        Filter the query based on the principal's permissions for the given resource and action.

        New filter is applied as a chained filter() call. Tortoise ANDs chained
        filters with any user-provided filters already present on the query.
        """
        expression = self._build_scoped_filter(context=context)
        return query.filter(expression)

    def _build_scoped_filter(
        self,
        *,
        context: AuthContext[type[TortoiseResource], typing.Any],
    ) -> Q:
        grants = self.matching_grants(context=context)
        if not grants:
            return Q(pk__in=[])

        expressions: list[Q] = []
        resource_ids: list[str] = []

        for grant in grants:
            match grant.scope:
                case "global":
                    return Q()
                case "resource":
                    resource_ids.append(grant.resource_id)
                case "conditional":
                    expression = TortoisePermissionExpression(
                        expression=grant.condition,
                        predicates=context.current_permission.predicates,
                    )
                    expressions.append(expression.evaluate(context=context))

        if resource_ids:
            id_column = context.current_permission.resource.__resource_id_column__
            model_cls = typing.cast(type[Model], context.current_permission.resource)
            if id_column not in getattr(
                getattr(model_cls, "_meta", None), "fields_map", {}
            ):
                raise exceptions.ImproperlyConfigured(
                    f"Resource '{context.current_permission.resource.__resource_code__}' "
                    f"has no id column '{id_column}' but resource scoped permission provided"
                )
            filter_kwargs: typing.Any = {f"{id_column}__in": resource_ids}
            expressions.append(Q(**filter_kwargs))

        if not expressions:
            return Q(pk__in=[])

        return functools.reduce(lambda left, right: left | right, expressions)
