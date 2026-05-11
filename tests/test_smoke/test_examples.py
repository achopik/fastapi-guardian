import typing

import pytest
import pytest_asyncio
from fastapi import FastAPI, status
from fastapi.testclient import TestClient
from pytest_lazy_fixtures import lf

from examples.with_sqlalchemy import (
    Article,
    AuthAction,
    User,
    app,
    setup_demo_data,
)
from examples.with_tortoise import app as tortoise_app
from examples.with_tortoise import setup_demo_data as tortoise_setup_demo_data


@pytest.fixture(scope="session")
def sqlalchemy_test_app():
    setup_demo_data()
    return app


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def tortoise_test_app():
    await tortoise_setup_demo_data()
    return tortoise_app


@pytest.fixture()
def sqlalchemy_app_client(sqlalchemy_test_app: FastAPI) -> typing.Generator[TestClient]:
    with TestClient(sqlalchemy_test_app) as client:
        yield client


@pytest.fixture()
def tortoise_app_client(tortoise_test_app: FastAPI) -> typing.Generator[TestClient]:
    with TestClient(tortoise_test_app) as client:
        yield client


def _sign_in(client: TestClient, username: str, password: str | None = None) -> None:
    response = client.post(
        "/auth/sign-in", json={"username": username, "password": password or username}
    )
    assert response.status_code == status.HTTP_200_OK, response.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "client", [lf("sqlalchemy_app_client"), lf("tortoise_app_client")]
)
async def test__get_users__unauthenticated__returns_401(
    client: TestClient,
) -> None:
    response = client.get("/users")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "client", [lf("sqlalchemy_app_client"), lf("tortoise_app_client")]
)
async def test__get_users__admin_global_scope__returns_all_users(
    client: TestClient,
) -> None:
    _sign_in(client, "admin")

    response = client.get("/users")

    assert response.status_code == status.HTTP_200_OK
    usernames = {user["username"] for user in response.json()}
    assert usernames == {"admin", "alice", "bob"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "client", [lf("sqlalchemy_app_client"), lf("tortoise_app_client")]
)
async def test__get_users__author_conditional_self__returns_only_self(
    client: TestClient,
) -> None:
    _sign_in(client, "alice")

    response = client.get("/users")

    assert response.status_code == status.HTTP_200_OK
    payload = response.json()
    assert len(payload) == 1
    assert payload[0]["username"] == "alice"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "client", [lf("sqlalchemy_app_client"), lf("tortoise_app_client")]
)
async def test__create_user__unauthenticated__returns_401(client: TestClient) -> None:
    response = client.post(
        "/users",
        json={"username": "new", "email": "new@example.com", "password": "new"},
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "client", [lf("sqlalchemy_app_client"), lf("tortoise_app_client")]
)
async def test__create_user__author_without_create_permission__returns_403(
    client: TestClient,
) -> None:
    _sign_in(client, "alice")

    response = client.post(
        "/users",
        json={"username": "nope", "email": "nope@example.com", "password": "nope"},
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "client", [lf("sqlalchemy_app_client"), lf("tortoise_app_client")]
)
async def test__get_articles__unauthenticated__returns_401(client: TestClient) -> None:
    response = client.get("/articles")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "client", [lf("sqlalchemy_app_client"), lf("tortoise_app_client")]
)
async def test__get_articles__admin_global__returns_all(client: TestClient) -> None:
    _sign_in(client, "admin")

    response = client.get("/articles")

    assert response.status_code == status.HTTP_200_OK
    titles = {article["title"] for article in response.json()}
    assert titles == {"Alice draft", "Bob notes", "Alice published letter"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "client", [lf("sqlalchemy_app_client"), lf("tortoise_app_client")]
)
async def test__get_articles__alice_self_or_published__returns_own_and_published(
    client: TestClient,
) -> None:
    _sign_in(client, "alice")

    response = client.get("/articles")

    assert response.status_code == status.HTTP_200_OK
    titles = {article["title"] for article in response.json()}
    # Alice owns both Alice articles; "Bob notes" is a draft, not visible.
    assert titles == {"Alice draft", "Alice published letter"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "client", [lf("sqlalchemy_app_client"), lf("tortoise_app_client")]
)
async def test__get_articles__bob_self_or_published__returns_own_and_published(
    client: TestClient,
) -> None:
    _sign_in(client, "bob")

    response = client.get("/articles")

    assert response.status_code == status.HTTP_200_OK
    titles = {article["title"] for article in response.json()}
    # Bob sees his own draft and Alice's published article, but not Alice's draft.
    assert titles == {"Bob notes", "Alice published letter"}


@pytest.mark.asyncio
async def test__get_permissions__returns_registered_permissions(
    sqlalchemy_app_client: TestClient,
) -> None:
    response = sqlalchemy_app_client.get("/permissions")

    assert response.status_code == status.HTTP_200_OK
    payload = response.json()

    assert User.__resource_code__ in payload
    assert Article.__resource_code__ in payload

    user_actions = {entry["action"] for entry in payload[User.__resource_code__]}
    assert user_actions == {AuthAction.READ, AuthAction.CREATE}

    article_actions = {entry["action"] for entry in payload[Article.__resource_code__]}
    assert article_actions == {AuthAction.READ}

    user_read = next(
        entry
        for entry in payload[User.__resource_code__]
        if entry["action"] == AuthAction.READ
    )
    assert set(user_read["scopes"]) == {"global", "resource", "conditional"}
    assert [predicate["name"] for predicate in user_read["predicates"]] == ["self"]

    article_read = next(
        entry
        for entry in payload[Article.__resource_code__]
        if entry["action"] == AuthAction.READ
    )
    assert {predicate["name"] for predicate in article_read["predicates"]} == {
        "self",
        "only_published",
    }
