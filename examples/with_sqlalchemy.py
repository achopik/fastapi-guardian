import enum
import typing

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.engine import create_engine
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    mapped_column,
    relationship,
    sessionmaker,
)
from sqlalchemy.pool import StaticPool
from sqlalchemy.schema import ForeignKey
from sqlalchemy.sql import select
from sqlalchemy.types import JSON, Integer, String
from starlette.middleware.sessions import SessionMiddleware

from fastapi_guardian.dependencies import BasePermission
from fastapi_guardian.dto import AuthContext, Principal
from fastapi_guardian.ext.sqlalchemy import SqlalchemyAuthEngine, SqlalchemyResource

# We're using sync in-memory sqlite here just for the sake of simplicity.
# Any sqlalchemy backend should work.
engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


# 1. Define your sqlalchemy models, inherit SqlalchemyResource
class Base(DeclarativeBase, SqlalchemyResource, __resource_abstract__=True):
    __resource_app_name__ = "example"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)


class Role(Base):
    __tablename__ = "roles"

    name: Mapped[str] = mapped_column(String(255))
    permission_grants: Mapped[list["RolePermissionGrant"]] = relationship(
        "RolePermissionGrant", back_populates="role"
    )
    users: Mapped[list["UserRole"]] = relationship("UserRole", back_populates="role")


class RolePermissionGrant(Base):
    __tablename__ = "role_permission_grants"

    role_id: Mapped[int] = mapped_column(Integer, ForeignKey("roles.id"))
    role: Mapped["Role"] = relationship("Role", back_populates="permission_grants")
    resource: Mapped[str] = mapped_column(String(255))
    action: Mapped[str] = mapped_column(String(255))
    scope: Mapped[str] = mapped_column(String(255))
    extra: Mapped[dict] = mapped_column(JSON)


class User(Base):
    __tablename__ = "users"

    username: Mapped[str] = mapped_column(String(255))
    email: Mapped[str] = mapped_column(String(255))
    password: Mapped[str] = mapped_column(String(255))

    articles: Mapped[list["Article"]] = relationship("Article", back_populates="author")
    roles: Mapped[list["UserRole"]] = relationship("UserRole", back_populates="user")


class UserRole(Base):
    __tablename__ = "user_roles"

    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"))
    user: Mapped["User"] = relationship("User", back_populates="roles")
    role_id: Mapped[int] = mapped_column(Integer, ForeignKey("roles.id"))
    role: Mapped["Role"] = relationship("Role", back_populates="users")


class Article(Base):
    __tablename__ = "articles"

    title: Mapped[str] = mapped_column(String(255))
    content: Mapped[str] = mapped_column(String(255))
    author_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"))
    author: Mapped["User"] = relationship("User", back_populates="articles")
    category: Mapped[str] = mapped_column(String(255))


# 2. Create your auth engine
auth_engine = SqlalchemyAuthEngine()


# Note: You can use any string value as an action, enum prefered here for typed suggestions and consistency across the application.
class AuthAction(enum.StrEnum):
    READ = "read"
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"


# Your preferred dependencies and DB handling logic
def get_db() -> typing.Generator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_authorized_principal(
    request: Request, db: Session = Depends(get_db)
) -> Principal[int] | None:
    user_id = request.session.get("user_id")
    if user_id is None:
        return None  # Alternatively, you can raise an HTTPException here, but None is handled by permission itself
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        return None

    permissions = (
        db.query(RolePermissionGrant)
        .join(Role, Role.id == RolePermissionGrant.role_id)
        .join(UserRole, UserRole.role_id == Role.id)
        .filter(UserRole.user_id == user_id)
        .all()
    )

    return Principal(
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


app = FastAPI()
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
async def sign_in(
    request: Request, body: SignInRequestDto, db: Session = Depends(get_db)
) -> str:
    user = db.query(User).filter(User.username == body.username).first()
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
                    "fn": lambda ctx: ctx.resource.id == ctx.principal.id,
                    "description": "Allow access to own user resource",
                },
            ],
        )
    ),
    db: Session = Depends(get_db),
) -> list[UserDto]:
    query = select(User)
    query = auth_engine.filter_query(context=auth_ctx, query=query)
    users = db.execute(query).scalars().all()
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
    db: Session = Depends(get_db),
) -> UserDto:
    user = User(username=body.username, email=body.email, password=body.password)
    db.add(user)
    db.commit()
    db.refresh(user)
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
                    "fn": lambda ctx: ctx.resource.author_id == ctx.principal.id,
                    "description": "Allow access to own articles",
                },
                {
                    "name": "only_published",
                    "fn": lambda ctx: ctx.resource.category == "published",
                    "description": "Allow access to published articles only",
                },
            ],
        )
    ),
    db: Session = Depends(get_db),
) -> list[ArticleDto]:
    query = select(Article)
    query = auth_engine.filter_query(context=auth_ctx, query=query)
    articles = db.execute(query).scalars().all()
    return [
        ArticleDto(
            id=article.id,
            title=article.title,
            content=article.content,
            author_id=article.author_id,
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


def setup_demo_data() -> None:
    Base.metadata.create_all(bind=engine)

    with SessionLocal() as db:
        if db.query(User).first() is not None:
            return

        admin_role = Role(name="admin")
        author_role = Role(name="author")
        admin = User(username="admin", email="admin@example.com", password="admin")
        alice = User(username="alice", email="alice@example.com", password="alice")
        bob = User(username="bob", email="bob@example.com", password="bob")
        db.add_all([admin_role, author_role, admin, alice, bob])
        db.flush()

        db.add_all(
            [
                UserRole(user_id=admin.id, role_id=admin_role.id),
                UserRole(user_id=alice.id, role_id=author_role.id),
                UserRole(user_id=bob.id, role_id=author_role.id),
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
        db.add_all(
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
        db.commit()


if __name__ == "__main__":
    setup_demo_data()
    uvicorn.run(app, host="0.0.0.0", port=8000)
