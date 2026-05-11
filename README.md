# fastapi-guardian

```fastapi-guardian``` is a WIP Python library created for flexible permission management in FastAPI applications. It provides a generic engine and ORM bindings to perform access checks and DB-level filtering operations.

## Features

- Generic engine for permission management
- SQLAlchemy and Tortoise ORM bindings for access filtering
- Database-agnostic core decision engine
- Expression mini-DSL for permission conditions (AND, OR, NOT) with custom dev-defined predicates (e.g, 'self', 'only_drafts')
- 3 scopes of permissions: global, resource-based (access to specific resource instance denoted by ID) and conditional (access to specific resource instance based on custom conditions defined in application code)
- FastAPI-native dependency injection via `Permission` dependency.
- Fully typed library definitions, especially user-facing interfaces.
- 🚧 Minimal AI involvement and fully covered with tests. 


## Supported Python version

Currently, library is designed to work with Python 3.14+


## Installation

```bash
pip install fastapi-guardian
```

## Quickstart

```py
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
from sqlalchemy.schema import ForeignKey
from sqlalchemy.sql import select
from sqlalchemy.types import JSON, Integer, String
from starlette.middleware.sessions import SessionMiddleware

from fastapi_guardian.dependencies import BasePermission
from fastapi_guardian.dto import AuthContext, Principal
from fastapi_guardian.ext.sqlalchemy import SqlalchemyAuthEngine, SqlalchemyResource



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


class Article(Base):
    __tablename__ = "articles"

    title: Mapped[str] = mapped_column(String(255))
    content: Mapped[str] = mapped_column(String(255))
    author_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"))
    author: Mapped["User"] = relationship("User", back_populates="articles")
    category: Mapped[str] = mapped_column(String(255))



# 2. Create your auth engine
auth_engine = SqlalchemyAuthEngine[Base]()


# 3. Create your permission dependency class and authentication logic
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


class AppPermission[T: type[Base]](BasePermission[T, int]):
    auth_engine = auth_engine

    async def __call__(self, principal: typing.Annotated[Principal, Depends(get_authorized_principal)]):
        return await self.authorize(principal=principal)


# Note: You can use any string value as an action, enum prefered here for typed suggestions and consistency across the application.
class AuthAction(enum.StrEnum):
    READ = "read"
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"


# 4. Define your API endpoints
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
    # Note: Apply filter to query manually here. Expression will be added as AND statement to the existing filters.
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

# 5. Create and store permission grants somewhere (completely up to you, check examples for to-go model definitions, auth engine only cares about Principal DTO):
grant = RolePermissionGrant(
    role_id=author_role.id,
    resource=Article.__resource_code__,
    action=AuthAction.READ,
    scope="conditional",
    # Notice that we can use expression mini-DSL here to build complex conditions.
    extra={"condition": "self or only_published"},
)
```

For detailed ready-to-run examples, see [examples](examples) directory.