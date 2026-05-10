import typing

from sqlalchemy import Select, and_, false, not_, or_, true
from sqlalchemy.orm import InstrumentedAttribute
from sqlalchemy.sql.elements import ColumnElement

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


class SqlAlchemyPredicateNode(AbstractPredicateNode):
    def evaluate(self, context: AuthContext) -> ColumnElement[bool]:
        predicate_context = PredicateContext[type[Resource], typing.Any](
            principal=context.principal, resource=context.current_permission.resource
        )
        return typing.cast("ColumnElement[bool]", self.predicate.fn(predicate_context))


class SqlAlchemyNotNode(AbstractNotNode):
    def evaluate(self, context: AuthContext) -> typing.Any:
        return not_(self.child.evaluate(context))


class SqlAlchemyAndNode(AbstractAndNode):
    def evaluate(self, context: AuthContext) -> typing.Any:
        return and_(*(child.evaluate(context) for child in self.children))


class SqlAlchemyOrNode(AbstractOrNode):
    def evaluate(self, context: AuthContext) -> typing.Any:
        return or_(*(child.evaluate(context) for child in self.children))


AnySqlAlchemyNode = (
    SqlAlchemyPredicateNode | SqlAlchemyNotNode | SqlAlchemyAndNode | SqlAlchemyOrNode
)


class SqlAlchemyExpressionTransformer(ExpressionTransformer[AnySqlAlchemyNode]):
    predicate_node: type[SqlAlchemyPredicateNode] = SqlAlchemyPredicateNode
    not_node: type[SqlAlchemyNotNode] = SqlAlchemyNotNode
    and_node: type[SqlAlchemyAndNode] = SqlAlchemyAndNode
    or_node: type[SqlAlchemyOrNode] = SqlAlchemyOrNode


class SqlalchemyPermissionExpression(PermissionExpression):
    def __init__(self, *, expression: str, predicates: list[AuthPredicate]) -> None:
        super().__init__(
            expression=expression,
            predicates=predicates,
            transformer_class=SqlAlchemyExpressionTransformer,
        )


class SqlalchemyResource(Resource):
    __resource_id_column__: str = "id"

    def __init_subclass__(cls, __resource_abstract__: bool = False) -> None:
        if __resource_abstract__:
            return

        resource_name = getattr(cls, "__resource_name__", None) or getattr(
            cls, "__tablename__", None
        )
        if resource_name is None:
            raise exceptions.ImproperlyConfigured(
                "Either __resource_name__ or __tablename__ must be set"
            )

        if not isinstance(getattr(cls, "__resource_app_name__", None), str):
            raise exceptions.ImproperlyConfigured(
                "__resource_app_name__ string must be set for non-abstract resources"
            )

        cls.__resource_name__ = resource_name
        cls.__resource_code__ = (
            f"{cls.__resource_app_name__}.{cls.__resource_name__}".lower()
        )


class SqlalchemyAuthEngine(BaseAuthEngine):
    def filter_query[RowT: tuple[typing.Any, ...]](
        self,
        context: AuthContext[type[SqlalchemyResource], typing.Any],
        query: Select[RowT],
    ) -> Select[RowT]:
        """
        Filter the query based on the principal's permissions for the given resource and action.

        New filter applied as a chained filter() call,
        in current sqlalchemy implementation it's AND'ed with the existing filters,
        so for chained filter calls it should "Just Work™".
        """
        expression = self._build_scoped_filter(context=context)
        return query.filter(expression)

    def _build_scoped_filter(self, *, context: AuthContext) -> ColumnElement[bool]:
        grants = self.matching_grants(context=context)
        if not grants:
            return false()

        expressions: list[ColumnElement[bool]] = []
        resource_ids: list[str] = []

        for grant in grants:
            match grant.scope:
                case "global":
                    return true()
                case "resource":
                    resource_ids.append(grant.resource_id)
                case "conditional":
                    expression = SqlalchemyPermissionExpression(
                        expression=grant.condition,
                        predicates=context.current_permission.predicates,
                    )
                    if expression is not None:
                        expressions.append(expression.evaluate(context=context))

        if resource_ids:
            id_column = getattr(
                context.current_permission.resource,
                context.current_permission.resource.__resource_id_column__,
                None,
            )
            if id_column is None:
                raise exceptions.ImproperlyConfigured(
                    f"Resource '{context.current_permission.resource.__resource_code__}' "
                    f"has no id column '{context.current_permission.resource.__resource_id_column__}' but resource scoped permission provided"
                )
            else:
                id_column = typing.cast("InstrumentedAttribute[typing.Any]", id_column)
                expressions.append(id_column.in_(resource_ids))

        if not expressions:
            return false()

        return or_(*expressions)
