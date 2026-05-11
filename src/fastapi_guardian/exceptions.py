class GuardianException(Exception):
    pass


class ImproperlyConfigured(GuardianException):
    pass


class ExpressionError(GuardianException):
    pass


class ExpressionParsingError(ExpressionError):
    pass


class InvalidPredicateError(ExpressionError):
    pass


class ExpressionEvaluationError(ExpressionError):
    pass
