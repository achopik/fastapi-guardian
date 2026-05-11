"""
Module contains microlanguage definition for permission conditions.

Grammar is sufficient to parse permission conditions like:
'self or (attachment_cv or attachment_doc and not supervisor)'
... and convert to SQLAlchemy expression.
"""

import typing

from lark import Lark, Token, Transformer
from lark.exceptions import UnexpectedInput, VisitError

from fastapi_guardian import exceptions
from fastapi_guardian.dto import AuthContext, AuthPredicate

expression_grammar = Lark(
    r"""
    ?expression: or_expression

    ?or_expression: and_expression (OR and_expression)*
    ?and_expression: not_expression (AND not_expression)*
    ?not_expression: NOT not_expression -> not_expression
        | atom

    ?atom: PREDICATE -> predicate
        | "(" expression ")"

    OR.2: "or"
    AND.2: "and"
    NOT.2: "not"
    PREDICATE: /[A-Za-z_][A-Za-z0-9_]*/

    %import common.WS
    %ignore WS
""",
    parser="lalr",
    start="expression",
)


# Operator precedence used to decide whether to wrap a child node in parentheses
# during string serialization. Higher number = binds tighter.
_OR_PRECEDENCE = 1
_AND_PRECEDENCE = 2
_NOT_PRECEDENCE = 3
_ATOM_PRECEDENCE = 4


class AbstractPredicateNode:
    precedence: typing.ClassVar[int] = _ATOM_PRECEDENCE
    predicate: AuthPredicate

    __slots__ = ("predicate",)

    def __init__(self, *, predicate: AuthPredicate) -> None:
        self.predicate = predicate

    def to_string(self) -> str:
        return self.predicate.name

    def evaluate(self, context: AuthContext) -> typing.Any:
        raise NotImplementedError  # pragma: no cover


class AbstractNotNode:
    precedence: typing.ClassVar[int] = _NOT_PRECEDENCE
    child: AnyAbstractNode

    __slots__ = ("child",)

    def __init__(self, *, child: AnyAbstractNode) -> None:
        self.child = child

    def to_string(self) -> str:
        return f"not {_render_child(self.child, self.precedence)}"

    def evaluate(self, context: AuthContext) -> typing.Any:
        raise NotImplementedError  # pragma: no cover


class AbstractAndNode:
    precedence: typing.ClassVar[int] = _AND_PRECEDENCE
    children: tuple[AnyAbstractNode, ...]

    __slots__ = ("children",)

    def __init__(self, *, children: tuple[AnyAbstractNode, ...]) -> None:
        self.children = children

    def to_string(self) -> str:
        return " and ".join(
            _render_child(child, self.precedence) for child in self.children
        )

    def evaluate(self, context: AuthContext) -> typing.Any:
        raise NotImplementedError  # pragma: no cover


class AbstractOrNode:
    precedence: typing.ClassVar[int] = _OR_PRECEDENCE
    children: tuple[AnyAbstractNode, ...]

    __slots__ = ("children",)

    def __init__(self, *, children: tuple[AnyAbstractNode, ...]) -> None:
        self.children = children

    def to_string(self) -> str:
        return " or ".join(
            _render_child(child, self.precedence) for child in self.children
        )

    def evaluate(self, context: AuthContext) -> typing.Any:
        raise NotImplementedError  # pragma: no cover


AnyAbstractNode = (
    AbstractPredicateNode | AbstractNotNode | AbstractAndNode | AbstractOrNode
)


def _render_child(child: AnyAbstractNode, parent_precedence: int) -> str:
    rendered = child.to_string()
    if child.precedence < parent_precedence:
        return f"({rendered})"
    return rendered


class ExpressionTransformer[NodeT: AnyAbstractNode](Transformer[Token, NodeT]):
    """Transform Lark parse tree into AST of `Node` instances."""

    or_node: type[AbstractOrNode] = AbstractOrNode
    and_node: type[AbstractAndNode] = AbstractAndNode
    not_node: type[AbstractNotNode] = AbstractNotNode
    predicate_node: type[AbstractPredicateNode] = AbstractPredicateNode

    def __init__(self, *, predicates: list[AuthPredicate]) -> None:
        super().__init__()
        self._predicates_by_name = {
            predicate.name: predicate for predicate in predicates
        }

    def predicate(self, items: list[Token]) -> AbstractPredicateNode:
        name = items[0].value
        predicate = self._predicates_by_name.get(name)
        if predicate is None:
            raise exceptions.InvalidPredicateError(f"Unknown predicate '{name}'")
        return self.predicate_node(predicate=predicate)

    def not_expression(self, items: list[typing.Any]) -> AbstractNotNode:
        return self.not_node(child=items[1])

    def and_expression(self, items: list[typing.Any]) -> AbstractAndNode:
        return self.and_node(
            children=tuple(item for item in items if not isinstance(item, Token))
        )

    def or_expression(self, items: list[typing.Any]) -> AbstractOrNode:
        return self.or_node(
            children=tuple(item for item in items if not isinstance(item, Token))
        )


class PermissionExpression:
    def __init__(
        self,
        *,
        expression: str,
        predicates: list[AuthPredicate],
        transformer_class: type[ExpressionTransformer],
    ) -> None:
        self.expression = expression
        self.predicates = predicates
        try:
            parse_tree = expression_grammar.parse(expression)
        except UnexpectedInput as exc:
            raise exceptions.ExpressionParsingError(str(exc)) from exc
        try:
            self._root: AnyAbstractNode = transformer_class(
                predicates=predicates
            ).transform(parse_tree)
        except VisitError as exc:
            if isinstance(exc.orig_exc, exceptions.ExpressionError):
                raise exc.orig_exc from exc
            raise exceptions.ExpressionParsingError(str(exc.orig_exc)) from exc

    def __repr__(self) -> str:
        return self._root.to_string()

    def evaluate(self, context: AuthContext) -> typing.Any:
        try:
            return self._root.evaluate(context)
        except exceptions.ExpressionError:
            raise
        except Exception as exc:
            raise exceptions.ExpressionEvaluationError(str(exc)) from exc
