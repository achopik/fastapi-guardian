from fastapi_guardian import exceptions


class Resource:
    __resource_name__: str
    __resource_app_name__: str
    __resource_code__: str

    def __init_subclass__(cls, *, __resource_abstract__: bool = False) -> None:
        if __resource_abstract__:
            return

        if not (
            isinstance(getattr(cls, "__app_name__", None), str)
            and isinstance(getattr(cls, "__resource_app_name__", None), str)
        ):
            raise exceptions.ImproperlyConfigured(
                "__resource_name__ and __resource_app_name__ strings must be set for non-abstract resources"
            )

        cls.__resource_code__ = (
            f"{cls.__resource_app_name__}.{cls.__resource_name__}".lower()
        )
