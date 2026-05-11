import typing

import pytest
from fastapi import FastAPI, status
from fastapi.testclient import TestClient

from examples.with_sqlalchemy import (
    Article,
    AuthAction,
    SessionLocal,
    User,
    app,
    setup_demo_data,
)


@pytest.fixture(scope="session")
def test_app():
    setup_demo_data()
    return app


@pytest.fixture()
def client(test_app: FastAPI) -> typing.Generator[TestClient]:
    with TestClient(test_app) as client:
        yield client


def _sign_in(client: TestClient, username: str, password: str | None = None) -> None:
    response = client.post(
        "/auth/sign-in", json={"username": username, "password": password or username}
    )
    assert response.status_code == status.HTTP_200_OK, response.text


def test__sign_in__valid_credentials__returns_ok(client: TestClient) -> None:
    response = client.post(
        "/auth/sign-in", json={"username": "admin", "password": "admin"}
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == "OK"


def test__sign_in__invalid_password__returns_401(client: TestClient) -> None:
    response = client.post(
        "/auth/sign-in", json={"username": "admin", "password": "wrong"}
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test__sign_in__unknown_user__returns_401(client: TestClient) -> None:
    response = client.post(
        "/auth/sign-in", json={"username": "ghost", "password": "ghost"}
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test__get_users__unauthenticated__returns_401(client: TestClient) -> None:
    response = client.get("/users")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test__get_users__admin_global_scope__returns_all_users(client: TestClient) -> None:
    _sign_in(client, "admin")

    response = client.get("/users")

    assert response.status_code == status.HTTP_200_OK
    usernames = {user["username"] for user in response.json()}
    assert usernames == {"admin", "alice", "bob"}


def test__get_users__author_conditional_self__returns_only_self(
    client: TestClient,
) -> None:
    _sign_in(client, "alice")

    response = client.get("/users")

    assert response.status_code == status.HTTP_200_OK
    payload = response.json()
    assert len(payload) == 1
    assert payload[0]["username"] == "alice"


def test__create_user__unauthenticated__returns_401(client: TestClient) -> None:
    response = client.post(
        "/users",
        json={"username": "new", "email": "new@example.com", "password": "new"},
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test__create_user__admin__creates_and_returns_user(client: TestClient) -> None:
    _sign_in(client, "admin")

    response = client.post(
        "/users",
        json={
            "username": "charlie",
            "email": "charlie@example.com",
            "password": "charlie",
        },
    )

    assert response.status_code == status.HTTP_200_OK
    payload = response.json()
    assert payload["username"] == "charlie"
    assert payload["email"] == "charlie@example.com"
    assert isinstance(payload["id"], int)

    with SessionLocal() as db:
        created = db.query(User).filter(User.username == "charlie").first()
        assert created is not None
        assert created.email == "charlie@example.com"


def test__create_user__author_without_create_permission__returns_403(
    client: TestClient,
) -> None:
    _sign_in(client, "alice")

    response = client.post(
        "/users",
        json={"username": "nope", "email": "nope@example.com", "password": "nope"},
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN


# ----- GET /articles -----


def test__get_articles__unauthenticated__returns_401(client: TestClient) -> None:
    response = client.get("/articles")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test__get_articles__admin_global__returns_all(client: TestClient) -> None:
    _sign_in(client, "admin")

    response = client.get("/articles")

    assert response.status_code == status.HTTP_200_OK
    titles = {article["title"] for article in response.json()}
    assert titles == {"Alice draft", "Bob notes", "Alice published letter"}


def test__get_articles__alice_self_or_published__returns_own_and_published(
    client: TestClient,
) -> None:
    _sign_in(client, "alice")

    response = client.get("/articles")

    assert response.status_code == status.HTTP_200_OK
    titles = {article["title"] for article in response.json()}
    # Alice owns both Alice articles; "Bob notes" is a draft, not visible.
    assert titles == {"Alice draft", "Alice published letter"}


def test__get_articles__bob_self_or_published__returns_own_and_published(
    client: TestClient,
) -> None:
    _sign_in(client, "bob")

    response = client.get("/articles")

    assert response.status_code == status.HTTP_200_OK
    titles = {article["title"] for article in response.json()}
    # Bob sees his own draft and Alice's published article, but not Alice's draft.
    assert titles == {"Bob notes", "Alice published letter"}


# ----- GET /permissions -----


def test__get_permissions__returns_registered_permissions(client: TestClient) -> None:
    response = client.get("/permissions")

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


# ----- session isolation -----


def test__session_isolation__second_client_is_unauthenticated(
    test_app: FastAPI,
) -> None:
    with TestClient(test_app) as authed:
        _sign_in(authed, "admin")
        assert authed.get("/users").status_code == status.HTTP_200_OK

    with TestClient(test_app) as anon:
        assert anon.get("/users").status_code == status.HTTP_401_UNAUTHORIZED
