from __future__ import annotations

import os
from pathlib import Path

TEST_DB_PATH = Path("/workspace/test_app.db")
if TEST_DB_PATH.exists():
    TEST_DB_PATH.unlink()
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB_PATH}"

from fastapi.testclient import TestClient  # noqa: E402

from app.main import (  # noqa: E402
    Base,
    Followup,
    Note,
    SessionLocal,
    User,
    app,
    engine,
    validate_password,
    verify_password,
)


client = TestClient(app)
Base.metadata.drop_all(bind=engine)
Base.metadata.create_all(bind=engine)


def test_status_endpoint() -> None:
    response = client.get("/status")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_register_login_and_user_flow() -> None:
    register = client.post(
        "/register", json={"username": "alice", "password": "supersecret123"}
    )
    assert register.status_code == 201
    user_id = register.json()["user_id"]

    login = client.post(
        "/login", json={"username": "alice", "password": "supersecret123"}
    )
    assert login.status_code == 200
    token = login.json()["access_token"]
    refresh_token = login.json()["refresh_token"]
    assert refresh_token

    me = client.get("/user", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    assert me.json() == {"user_id": user_id}

    refreshed = client.post("/refresh", json={"refresh_token": refresh_token})
    assert refreshed.status_code == 200
    assert refreshed.json().get("access_token")


def test_user_requires_authentication() -> None:
    response = client.get("/user")
    assert response.status_code == 401


def test_login_rejects_bad_credentials() -> None:
    register = client.post(
        "/register", json={"username": "bob", "password": "anothersecret123"}
    )
    assert register.status_code == 201

    login = client.post(
        "/login", json={"username": "bob", "password": "wrong-password"}
    )
    assert login.status_code == 401


def test_register_rejects_duplicate_username() -> None:
    first = client.post("/register", json={"username": "chris", "password": "123456789012"})
    assert first.status_code == 201

    second = client.post("/register", json={"username": "chris", "password": "abcdefghijkl"})
    assert second.status_code == 409


def test_password_is_stored_hashed() -> None:
    raw_password = "verysecret123"
    register = client.post(
        "/register", json={"username": "dana", "password": raw_password}
    )
    assert register.status_code == 201
    user_id = register.json()["user_id"]

    with SessionLocal() as db:
        user = db.get(User, user_id)
        assert user is not None
        assert user.password_hash != raw_password
        assert verify_password(raw_password, user.password_hash)


def test_register_rejects_password_shorter_than_12() -> None:
    response = client.post(
        "/register", json={"username": "shortpass", "password": "short123"}
    )
    assert response.status_code == 422


def test_register_accepts_password_with_length_12() -> None:
    response = client.post(
        "/register", json={"username": "length12", "password": "123456789012"}
    )
    assert response.status_code == 201


def test_validate_password_extension_point_allows_current_valid_password() -> None:
    validate_password("this-is-valid-12")


def test_change_password_success_and_new_password_works() -> None:
    register = client.post(
        "/register", json={"username": "pwchange", "password": "initialpass123"}
    )
    assert register.status_code == 201

    login = client.post(
        "/login", json={"username": "pwchange", "password": "initialpass123"}
    )
    assert login.status_code == 200
    token = login.json()["access_token"]

    change = client.post(
        "/change-password",
        json={"current_password": "initialpass123", "new_password": "newpassword123"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert change.status_code == 200
    assert change.json() == {"status": "ok"}

    old_login = client.post(
        "/login", json={"username": "pwchange", "password": "initialpass123"}
    )
    assert old_login.status_code == 401

    new_login = client.post(
        "/login", json={"username": "pwchange", "password": "newpassword123"}
    )
    assert new_login.status_code == 200


def test_refresh_rejects_access_token() -> None:
    register = client.post(
        "/register", json={"username": "refreshbad", "password": "initialpass123"}
    )
    assert register.status_code == 201

    login = client.post(
        "/login", json={"username": "refreshbad", "password": "initialpass123"}
    )
    access_token = login.json()["access_token"]

    response = client.post("/refresh", json={"refresh_token": access_token})
    assert response.status_code == 401


def test_refresh_rejects_invalid_token() -> None:
    response = client.post("/refresh", json={"refresh_token": "not-a-real-token"})
    assert response.status_code == 401


def test_change_password_rejects_wrong_current_password() -> None:
    register = client.post(
        "/register", json={"username": "wrongcurrent", "password": "initialpass123"}
    )
    assert register.status_code == 201

    login = client.post(
        "/login", json={"username": "wrongcurrent", "password": "initialpass123"}
    )
    token = login.json()["access_token"]

    response = client.post(
        "/change-password",
        json={"current_password": "nottherightone", "new_password": "newpassword123"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 401


def test_change_password_requires_authentication() -> None:
    response = client.post(
        "/change-password",
        json={"current_password": "initialpass123", "new_password": "newpassword123"},
    )
    assert response.status_code == 401


def test_change_password_rejects_short_new_password() -> None:
    register = client.post(
        "/register", json={"username": "shortnewpass", "password": "initialpass123"}
    )
    assert register.status_code == 201

    login = client.post(
        "/login", json={"username": "shortnewpass", "password": "initialpass123"}
    )
    token = login.json()["access_token"]

    response = client.post(
        "/change-password",
        json={"current_password": "initialpass123", "new_password": "short123"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 422


def _register_and_login(username: str, password: str = "initialpass123") -> str:
    register = client.post("/register", json={"username": username, "password": password})
    assert register.status_code == 201
    login = client.post("/login", json={"username": username, "password": password})
    assert login.status_code == 200
    return login.json()["access_token"]


def test_notes_crud_flow_for_owner() -> None:
    token = _register_and_login("notesowner")
    headers = {"Authorization": f"Bearer {token}"}

    create = client.post("/notes", json={"value": "first note"}, headers=headers)
    assert create.status_code == 201
    created = create.json()
    note_id = created["id"]
    assert created["value"] == "first note"
    assert created["created_at"]

    fetched = client.get(f"/notes/{note_id}", headers=headers)
    assert fetched.status_code == 200
    assert fetched.json()["id"] == note_id
    assert fetched.json()["value"] == "first note"

    listed = client.get("/notes", headers=headers)
    assert listed.status_code == 200
    assert any(note["id"] == note_id for note in listed.json())

    updated = client.put(f"/notes/{note_id}", json={"value": "updated note"}, headers=headers)
    assert updated.status_code == 200
    assert updated.json()["id"] == note_id
    assert updated.json()["value"] == "updated note"

    deleted = client.delete(f"/notes/{note_id}", headers=headers)
    assert deleted.status_code == 204

    fetch_after_delete = client.get(f"/notes/{note_id}", headers=headers)
    assert fetch_after_delete.status_code == 404


def test_notes_enforce_owner_isolation() -> None:
    token_a = _register_and_login("ownera")
    token_b = _register_and_login("ownerb")
    headers_a = {"Authorization": f"Bearer {token_a}"}
    headers_b = {"Authorization": f"Bearer {token_b}"}

    created = client.post("/notes", json={"value": "private"}, headers=headers_a)
    note_id = created.json()["id"]

    get_other = client.get(f"/notes/{note_id}", headers=headers_b)
    assert get_other.status_code == 404

    update_other = client.put(f"/notes/{note_id}", json={"value": "hijack"}, headers=headers_b)
    assert update_other.status_code == 404

    delete_other = client.delete(f"/notes/{note_id}", headers=headers_b)
    assert delete_other.status_code == 404


def test_notes_require_authentication() -> None:
    assert client.get("/notes").status_code == 401
    assert client.post("/notes", json={"value": "test"}).status_code == 401
    assert client.get("/notes/some-id").status_code == 401
    assert client.put("/notes/some-id", json={"value": "test"}).status_code == 401
    assert client.delete("/notes/some-id").status_code == 401


def test_note_value_max_length_validation() -> None:
    token = _register_and_login("maxlength")
    headers = {"Authorization": f"Bearer {token}"}

    ok_value = "a" * 512
    too_long = "b" * 513

    ok_create = client.post("/notes", json={"value": ok_value}, headers=headers)
    assert ok_create.status_code == 201

    bad_create = client.post("/notes", json={"value": too_long}, headers=headers)
    assert bad_create.status_code == 422


def test_note_creation_time_is_recorded_in_db() -> None:
    token = _register_and_login("createdattest")
    headers = {"Authorization": f"Bearer {token}"}
    created = client.post("/notes", json={"value": "timestamp note"}, headers=headers)
    note_id = created.json()["id"]

    with SessionLocal() as db:
        note = db.get(Note, note_id)
        assert note is not None
        assert note.created_at is not None


def test_create_followup_for_owned_note() -> None:
    token = _register_and_login("followupowner")
    headers = {"Authorization": f"Bearer {token}"}

    note = client.post("/notes", json={"value": "needs checkup"}, headers=headers)
    note_id = note.json()["id"]

    created = client.post(
        f"/notes/{note_id}/followups",
        json={
            "appointment_at": "2030-01-15T10:30:00Z",
            "description": "Six month follow-up cleaning",
            "completed_at": None,
        },
        headers=headers,
    )
    assert created.status_code == 201
    body = created.json()
    assert body["id"]
    assert body["note_id"] == note_id
    assert body["description"] == "Six month follow-up cleaning"
    assert body["appointment_at"]
    assert body["created_at"]
    assert body["completed_at"] is None


def test_create_followup_rejects_unowned_note() -> None:
    token_a = _register_and_login("followupunowneda")
    token_b = _register_and_login("followupunownedb")
    headers_a = {"Authorization": f"Bearer {token_a}"}
    headers_b = {"Authorization": f"Bearer {token_b}"}

    note = client.post("/notes", json={"value": "private note"}, headers=headers_a)
    note_id = note.json()["id"]

    response = client.post(
        f"/notes/{note_id}/followups",
        json={
            "appointment_at": "2030-01-15T10:30:00Z",
            "description": "Unauthorized attempt",
        },
        headers=headers_b,
    )
    assert response.status_code == 404


def test_list_followups_for_user_returns_only_owned_followups() -> None:
    token_a = _register_and_login("followuplista")
    token_b = _register_and_login("followuplistb")
    headers_a = {"Authorization": f"Bearer {token_a}"}
    headers_b = {"Authorization": f"Bearer {token_b}"}

    note_a = client.post("/notes", json={"value": "note a"}, headers=headers_a).json()["id"]
    note_b = client.post("/notes", json={"value": "note b"}, headers=headers_b).json()["id"]

    client.post(
        f"/notes/{note_a}/followups",
        json={"appointment_at": "2030-01-10T10:00:00Z", "description": "a1"},
        headers=headers_a,
    )
    client.post(
        f"/notes/{note_b}/followups",
        json={"appointment_at": "2030-01-11T10:00:00Z", "description": "b1"},
        headers=headers_b,
    )

    followups_a = client.get("/followups", headers=headers_a)
    assert followups_a.status_code == 200
    assert len(followups_a.json()) == 1
    assert followups_a.json()[0]["description"] == "a1"


def test_list_followups_for_specific_note() -> None:
    token = _register_and_login("followupnote")
    headers = {"Authorization": f"Bearer {token}"}

    note1 = client.post("/notes", json={"value": "note 1"}, headers=headers).json()["id"]
    note2 = client.post("/notes", json={"value": "note 2"}, headers=headers).json()["id"]

    client.post(
        f"/notes/{note1}/followups",
        json={"appointment_at": "2030-01-12T09:00:00Z", "description": "n1-f1"},
        headers=headers,
    )
    client.post(
        f"/notes/{note1}/followups",
        json={"appointment_at": "2030-01-13T09:00:00Z", "description": "n1-f2"},
        headers=headers,
    )
    client.post(
        f"/notes/{note2}/followups",
        json={"appointment_at": "2030-01-14T09:00:00Z", "description": "n2-f1"},
        headers=headers,
    )

    listed = client.get(f"/notes/{note1}/followups", headers=headers)
    assert listed.status_code == 200
    descriptions = [f["description"] for f in listed.json()]
    assert descriptions == ["n1-f1", "n1-f2"]


def test_followup_endpoints_require_authentication() -> None:
    assert client.get("/followups").status_code == 401
    assert (
        client.post(
            "/notes/some-note/followups",
            json={"appointment_at": "2030-01-12T09:00:00Z", "description": "x"},
        ).status_code
        == 401
    )
    assert client.get("/notes/some-note/followups").status_code == 401


def test_followup_validation_for_bad_payloads() -> None:
    token = _register_and_login("followupvalidation")
    headers = {"Authorization": f"Bearer {token}"}
    note_id = client.post("/notes", json={"value": "note"}, headers=headers).json()["id"]

    bad_datetime = client.post(
        f"/notes/{note_id}/followups",
        json={"appointment_at": "not-a-datetime", "description": "bad"},
        headers=headers,
    )
    assert bad_datetime.status_code == 422

    too_long_description = client.post(
        f"/notes/{note_id}/followups",
        json={"appointment_at": "2030-01-12T09:00:00Z", "description": "a" * 513},
        headers=headers,
    )
    assert too_long_description.status_code == 422


def test_followup_creation_time_is_recorded_in_db() -> None:
    token = _register_and_login("followupdbstamp")
    headers = {"Authorization": f"Bearer {token}"}
    note_id = client.post("/notes", json={"value": "note"}, headers=headers).json()["id"]

    created = client.post(
        f"/notes/{note_id}/followups",
        json={"appointment_at": "2030-01-12T09:00:00Z", "description": "db check"},
        headers=headers,
    )
    followup_id = created.json()["id"]

    with SessionLocal() as db:
        followup = db.get(Followup, followup_id)
        assert followup is not None
        assert followup.created_at is not None


def test_followup_completion_toggle_complete_then_incomplete() -> None:
    token = _register_and_login("followuptoggle")
    headers = {"Authorization": f"Bearer {token}"}
    note_id = client.post("/notes", json={"value": "toggle note"}, headers=headers).json()["id"]
    followup_id = client.post(
        f"/notes/{note_id}/followups",
        json={"appointment_at": "2030-01-12T09:00:00Z", "description": "toggle me"},
        headers=headers,
    ).json()["id"]

    complete = client.patch(
        f"/followups/{followup_id}/completion",
        json={"is_completed": True},
        headers=headers,
    )
    assert complete.status_code == 200
    assert complete.json()["completed_at"] is not None

    incomplete = client.patch(
        f"/followups/{followup_id}/completion",
        json={"is_completed": False},
        headers=headers,
    )
    assert incomplete.status_code == 200
    assert incomplete.json()["completed_at"] is None


def test_followup_completion_requires_authentication() -> None:
    response = client.patch(
        "/followups/some-followup/completion",
        json={"is_completed": True},
    )
    assert response.status_code == 401


def test_followup_completion_rejects_unowned_followup() -> None:
    token_a = _register_and_login("followupcompletea")
    token_b = _register_and_login("followupcompleteb")
    headers_a = {"Authorization": f"Bearer {token_a}"}
    headers_b = {"Authorization": f"Bearer {token_b}"}

    note_id = client.post("/notes", json={"value": "private"}, headers=headers_a).json()["id"]
    followup_id = client.post(
        f"/notes/{note_id}/followups",
        json={"appointment_at": "2030-01-12T09:00:00Z", "description": "private followup"},
        headers=headers_a,
    ).json()["id"]

    response = client.patch(
        f"/followups/{followup_id}/completion",
        json={"is_completed": True},
        headers=headers_b,
    )
    assert response.status_code == 404


def test_followup_completion_rejects_unknown_followup() -> None:
    token = _register_and_login("followupmissing")
    headers = {"Authorization": f"Bearer {token}"}

    response = client.patch(
        "/followups/not-a-real-id/completion",
        json={"is_completed": True},
        headers=headers,
    )
    assert response.status_code == 404
