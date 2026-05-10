import enum
import typing
from contextlib import asynccontextmanager

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request, status
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware
from tortoise import Tortoise, fields, models
from tortoise.expressions import Q

from fastapi_guardian.dependencies import BasePermission
from fastapi_guardian.dto import AuthContext, Principal
from fastapi_guardian.ext.tortoise import TortoiseAuthEngine, TortoiseResource

# We're using async in-memory sqlite here just for the sake of simplicity.
# Any Tortoise backend should work.
DATABASE_URL = "sqlite://:memory:"


# 1. Define your Tortoise models, inherit TortoiseResource
class Base(TortoiseResource, models.Model):
    __resource_app_name__ = "example"

    id = fields.IntField(primary_key=True)

    class Meta:
        abstract = True


class Role(Base):
    __resource_name__ = "roles"

    name = fields.CharField(max_length=255)
    permission_grants: fields.ReverseRelation["RolePermissionGrant"]
    users: fields.ReverseRelation["UserRole"]

    class Meta:
        table = "roles"


class RolePermissionGrant(Base):
    __resource_name__ = "role_permission_grants"

    role: fields.ForeignKeyRelation[Role] = fields.ForeignKeyField(
        "example.Role", related_name="permission_grants"
    )
    resource = fields.CharField(max_length=255)
    action = fields.CharField(max_length=255)
    scope = fields.CharField(max_length=255)
    extra = fields.JSONField[dict[str, typing.Any]]()

    class Meta:
        table = "role_permission_grants"


class User(Base):
    __resource_name__ = "users"

    username = fields.CharField(max_length=255)
    email = fields.CharField(max_length=255)
    password = fields.CharField(max_length=255)

    articles: fields.ReverseRelation["Article"]
    roles: fields.ReverseRelation["UserRole"]

    class Meta:
        table = "users"


class UserRole(Base):
    __resource_name__ = "user_roles"

    user: fields.ForeignKeyRelation[User] = fields.ForeignKeyField(
        "example.User", related_name="roles"
    )
    role: fields.ForeignKeyRelation[Role] = fields.ForeignKeyField(
        "example.Role", related_name="users"
    )

    class Meta:
        table = "user_roles"


class Article(Base):
    __resource_name__ = "articles"

    title = fields.CharField(max_length=255)
    content = fields.CharField(max_length=255)
    author: fields.ForeignKeyRelation[User] = fields.ForeignKeyField(
        "example.User", related_name="articles"
    )
    category = fields.CharField(max_length=255)

    class Meta:
        table = "articles"


# 2. Create your auth engine
auth_engine = TortoiseAuthEngine()


# Note: You can use any string value as an action, enum prefered here for typed suggestions and consistency across the application.
class AuthAction(enum.StrEnum):
    READ = "read"
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"


# Your preferred dependencies and DB handling logic
async def get_authorized_principal(request: Request) -> Principal[int] | None:
    user_id = request.session.get("user_id")
    if user_id is None:
        return None  # Alternatively, you can raise an HTTPException here, but None is handled by permission itself
    user = await User.get_or_none(id=user_id)
    if user is None:
        return None

    permissions = await RolePermissionGrant.filter(role__users__user_id=user_id).all()

    return Principal[int](
        id=user.id,
        email=user.email,
        username=user.username,
        permissions=[
            {
                "resource": permission.resource,
                "action": permission.action,
                "scope": permission.scope,
                **permission.extra,
            }
            for permission in permissions
        ],
    )


# 3. Define your app permission class
class AppPermission[T: type[Base]](BasePermission[T, int]):
    auth_engine = auth_engine

    async def __call__(self, principal: Principal = Depends(get_authorized_principal)):
        return await self.authorize(principal=principal)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> typing.AsyncIterator[None]:
    await setup_demo_data()
    try:
        yield
    finally:
        await Tortoise.close_connections()


app = FastAPI(lifespan=lifespan)
app.add_middleware(SessionMiddleware, secret_key="ch4ng3m3-0r-y0u-w1ll-b3-f1r3d")


class SignInRequestDto(BaseModel):
    username: str
    password: str


class UserCreateDto(BaseModel):
    username: str
    email: str
    password: str


class UserDto(BaseModel):
    id: int
    username: str
    email: str


class ArticleDto(BaseModel):
    id: int
    title: str
    content: str
    author_id: int
    category: str


class PredicateDto(BaseModel):
    name: str
    description: str


class PermissionDefinitionDto(BaseModel):
    resource: str
    action: str
    scopes: list[str]
    predicates: list[PredicateDto]


@app.post("/auth/sign-in")
async def sign_in(request: Request, body: SignInRequestDto) -> str:
    user = await User.get_or_none(username=body.username)
    # Needless to say, in production you should use hashed passwords and a proper authentication system.
    # Details omitted for brevity of example.
    if user is None or user.password != body.password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
        )
    request.session["user_id"] = user.id
    return "OK"


@app.get("/users")
async def get_users(
    auth_ctx: AuthContext = Depends(
        AppPermission(
            resource=User,
            action=AuthAction.READ,
            scopes=["global", "resource", "conditional"],
            predicates=[
                {
                    "name": "self",
                    "fn": lambda ctx: Q(id=ctx.principal.id),
                    "description": "Allow access to own user resource",
                },
            ],
        )
    ),
) -> list[UserDto]:
    query = User.all()
    query = auth_engine.filter_query(context=auth_ctx, query=query)
    users = await query
    return [
        UserDto(id=user.id, username=user.username, email=user.email) for user in users
    ]


@app.post("/users")
async def create_user(
    body: UserCreateDto,
    # By default, permission assumes only global scope, which is the case for most of CREATE actions
    _auth: AuthContext = Depends(
        AppPermission(resource=User, action=AuthAction.CREATE)
    ),
) -> UserDto:
    user = await User.create(
        username=body.username, email=body.email, password=body.password
    )
    return UserDto(id=user.id, username=user.username, email=user.email)


@app.get("/articles")
async def get_articles(
    auth_ctx: AuthContext = Depends(
        AppPermission(
            resource=Article,
            action=AuthAction.READ,
            scopes=["global", "resource", "conditional"],
            predicates=[
                {
                    "name": "self",
                    "fn": lambda ctx: Q(author_id=ctx.principal.id),
                    "description": "Allow access to own articles",
                },
                {
                    "name": "only_published",
                    "fn": lambda ctx: Q(category="published"),
                    "description": "Allow access to published articles only",
                },
            ],
        )
    ),
) -> list[ArticleDto]:
    query = Article.all()
    query = auth_engine.filter_query(context=auth_ctx, query=query)
    articles = await query
    return [
        ArticleDto(
            id=article.id,
            title=article.title,
            content=article.content,
            author_id=article.author.id,
            category=article.category,
        )
        for article in articles
    ]


# By default, permission registers itself into auth engine, so you can introspect all registered permissions
# Can be useful for custom OpenAPI generation, permission management UI, etc.
@app.get("/permissions")
async def get_permissions() -> dict[str, list[PermissionDefinitionDto]]:
    permissions = auth_engine.permissions_by_resource
    return {
        resource: [
            PermissionDefinitionDto(
                resource=permission.resource.__resource_code__,
                action=permission.action,
                scopes=permission.scopes,
                predicates=[
                    PredicateDto(
                        name=predicate.name,
                        description=predicate.description,
                    )
                    for predicate in permission.predicates
                ],
            )
            for permission in resource_permissions
        ]
        for resource, resource_permissions in permissions.items()
    }


async def setup_demo_data() -> None:
    await Tortoise.init(
        db_url=DATABASE_URL,
        modules={"example": [__name__]},
        _enable_global_fallback=True,
    )
    await Tortoise.generate_schemas()

    if await User.exists():
        return

    admin_role = await Role.create(name="admin")
    author_role = await Role.create(name="author")
    admin = await User.create(
        username="admin", email="admin@example.com", password="admin"
    )
    alice = await User.create(
        username="alice", email="alice@example.com", password="alice"
    )
    bob = await User.create(username="bob", email="bob@example.com", password="bob")

    await UserRole.bulk_create(
        [
            UserRole(user_id=admin.id, role_id=admin_role.id),
            UserRole(user_id=alice.id, role_id=author_role.id),
            UserRole(user_id=bob.id, role_id=author_role.id),
        ]
    )
    await RolePermissionGrant.bulk_create(
        [
            RolePermissionGrant(
                role_id=admin_role.id,
                resource=User.__resource_code__,
                action=AuthAction.READ,
                scope="global",
                extra={},
            ),
            RolePermissionGrant(
                role_id=admin_role.id,
                resource=User.__resource_code__,
                action=AuthAction.CREATE,
                scope="global",
                extra={},
            ),
            RolePermissionGrant(
                role_id=admin_role.id,
                resource=Article.__resource_code__,
                action=AuthAction.READ,
                scope="global",
                extra={},
            ),
            RolePermissionGrant(
                role_id=author_role.id,
                resource=User.__resource_code__,
                action=AuthAction.READ,
                scope="conditional",
                extra={"condition": "self"},
            ),
            RolePermissionGrant(
                role_id=author_role.id,
                resource=Article.__resource_code__,
                action=AuthAction.READ,
                scope="conditional",
                # Notice that we can use expression mini-DSL here to build complex conditions.
                extra={"condition": "self or only_published"},
            ),
        ]
    )
    await Article.bulk_create(
        [
            Article(
                title="Alice draft",
                content="Only Alice and admins can read this.",
                author_id=alice.id,
                category="draft",
            ),
            Article(
                title="Bob notes",
                content="Only Bob and admins can read this.",
                author_id=bob.id,
                category="draft",
            ),
            Article(
                title="Alice published letter",
                content="All authors can read this.",
                author_id=alice.id,
                category="published",
            ),
        ]
    )


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
