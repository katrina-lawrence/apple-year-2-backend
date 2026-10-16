from __future__ import annotations

import os
import json
from pathlib import Path
from datetime import datetime
from urllib.error import URLError

import pytest

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
    hash_password,
    validate_password,
    verify_password,
)
from app.db.bootstrap import maybe_seed_sample_data  # noqa: E402
from app.db.sample_data import (  # noqa: E402
    SEED_FOLLOWUP_ID_1,
    SEED_FOLLOWUP_ID_2,
    SEED_NOTE_ID_1,
    SEED_NOTE_ID_2,
    SEED_USERNAME,
    seed_sample_data,
)


client: TestClient
Base.metadata.drop_all(bind=engine)
Base.metadata.create_all(bind=engine)


@pytest.fixture(scope="module", autouse=True)
def _client_lifespan() -> None:
    global client
    with TestClient(app) as test_client:
        client = test_client
        yield


def _reset_db() -> None:
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def test_status_endpoint() -> None:
    response = client.get("/status")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_sample_seed_disabled_by_default(monkeypatch) -> None:
    _reset_db()
    monkeypatch.delenv("SEED_SAMPLE_DATA", raising=False)

    inserted = maybe_seed_sample_data(
        SessionLocal,
        lambda db: seed_sample_data(db, User, Note, Followup, hash_password),
    )
    assert inserted is False

    with SessionLocal() as db:
        demo_user = db.query(User).filter(User.username == SEED_USERNAME).first()
        assert demo_user is None


def test_sample_seed_enabled_inserts_demo_rows(monkeypatch) -> None:
    _reset_db()
    monkeypatch.setenv("SEED_SAMPLE_DATA", "true")

    inserted = maybe_seed_sample_data(
        SessionLocal,
        lambda db: seed_sample_data(db, User, Note, Followup, hash_password),
    )
    assert inserted is True

    with SessionLocal() as db:
        demo_user = db.query(User).filter(User.username == SEED_USERNAME).first()
        assert demo_user is not None
        assert db.get(Note, SEED_NOTE_ID_1) is not None
        assert db.get(Note, SEED_NOTE_ID_2) is not None
        assert db.get(Followup, SEED_FOLLOWUP_ID_1) is not None
        assert db.get(Followup, SEED_FOLLOWUP_ID_2) is not None


def test_sample_seed_is_idempotent(monkeypatch) -> None:
    _reset_db()
    monkeypatch.setenv("SEED_SAMPLE_DATA", "true")

    maybe_seed_sample_data(
        SessionLocal,
        lambda db: seed_sample_data(db, User, Note, Followup, hash_password),
    )
    maybe_seed_sample_data(
        SessionLocal,
        lambda db: seed_sample_data(db, User, Note, Followup, hash_password),
    )

    with SessionLocal() as db:
        assert db.query(User).filter(User.username == SEED_USERNAME).count() == 1
        assert db.query(Note).filter(Note.id.in_([SEED_NOTE_ID_1, SEED_NOTE_ID_2])).count() == 2
        assert (
            db.query(Followup)
            .filter(Followup.id.in_([SEED_FOLLOWUP_ID_1, SEED_FOLLOWUP_ID_2]))
            .count()
            == 2
        )


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


def test_sync_user_returns_notes_followups_and_server_time() -> None:
    token = _register_and_login("syncowner")
    headers = {"Authorization": f"Bearer {token}"}

    note_1 = client.post("/notes", json={"value": "sync note 1"}, headers=headers)
    note_2 = client.post("/notes", json={"value": "sync note 2"}, headers=headers)
    assert note_1.status_code == 201
    assert note_2.status_code == 201

    note_1_id = note_1.json()["id"]
    note_2_id = note_2.json()["id"]

    followup_1 = client.post(
        f"/notes/{note_1_id}/followups",
        json={"descriptionText": "sync followup 1", "type": "task"},
        headers=headers,
    )
    followup_2 = client.post(
        f"/notes/{note_2_id}/followups",
        json={"descriptionText": "sync followup 2", "type": "task"},
        headers=headers,
    )
    assert followup_1.status_code == 201
    assert followup_2.status_code == 201

    response = client.get("/sync/user", headers=headers)
    assert response.status_code == 200
    body = response.json()

    assert set(body.keys()) == {"notes", "followups", "serverTimeUTC"}
    parsed_server_time = datetime.fromisoformat(body["serverTimeUTC"].replace("Z", "+00:00"))
    assert parsed_server_time.tzinfo is not None

    notes_response = client.get("/notes", headers=headers)
    followups_response = client.get("/followups", headers=headers)
    assert notes_response.status_code == 200
    assert followups_response.status_code == 200
    assert body["notes"] == notes_response.json()
    assert body["followups"] == followups_response.json()


def test_sync_user_requires_authentication() -> None:
    response = client.get("/sync/user")
    assert response.status_code == 401


def test_sync_user_enforces_owner_isolation() -> None:
    token_a = _register_and_login("syncisolationa")
    token_b = _register_and_login("syncisolationb")
    headers_a = {"Authorization": f"Bearer {token_a}"}
    headers_b = {"Authorization": f"Bearer {token_b}"}

    note_a = client.post("/notes", json={"value": "owner a note"}, headers=headers_a)
    note_b = client.post("/notes", json={"value": "owner b note"}, headers=headers_b)
    assert note_a.status_code == 201
    assert note_b.status_code == 201
    note_a_id = note_a.json()["id"]
    note_b_id = note_b.json()["id"]

    followup_a = client.post(
        f"/notes/{note_a_id}/followups",
        json={"descriptionText": "owner a followup", "type": "task"},
        headers=headers_a,
    )
    followup_b = client.post(
        f"/notes/{note_b_id}/followups",
        json={"descriptionText": "owner b followup", "type": "task"},
        headers=headers_b,
    )
    assert followup_a.status_code == 201
    assert followup_b.status_code == 201

    sync_a = client.get("/sync/user", headers=headers_a)
    assert sync_a.status_code == 200
    body_a = sync_a.json()

    assert {note["id"] for note in body_a["notes"]} == {note_a_id}
    assert {followup["id"] for followup in body_a["followups"]} == {followup_a.json()["id"]}


def test_sync_note_updates_note_and_overwrites_followups() -> None:
    token = _register_and_login("syncnoteowner")
    headers = {"Authorization": f"Bearer {token}"}

    note_id = client.post("/notes", json={"value": "original"}, headers=headers).json()["id"]
    old_1 = client.post(
        f"/notes/{note_id}/followups",
        json={"descriptionText": "old 1", "type": "task"},
        headers=headers,
    ).json()["id"]
    old_2 = client.post(
        f"/notes/{note_id}/followups",
        json={"descriptionText": "old 2", "type": "task"},
        headers=headers,
    ).json()["id"]

    response = client.post(
        f"/sync/note/{note_id}",
        json={
            "value": "synced note",
            "summary": "new summary",
            "followups": [
                {"descriptionText": "new 1", "type": "task"},
                {"descriptionText": "new 2", "type": "checkup"},
            ],
        },
        headers=headers,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["note"]["id"] == note_id
    assert body["note"]["value"] == "synced note"
    assert body["note"]["summary"] == "new summary"
    assert [f["descriptionText"] for f in body["followups"]] == ["new 1", "new 2"]

    note = client.get(f"/notes/{note_id}", headers=headers)
    assert note.status_code == 200
    assert note.json()["value"] == "synced note"
    assert note.json()["summary"] == "new summary"

    followups = client.get(f"/notes/{note_id}/followups", headers=headers)
    assert followups.status_code == 200
    assert [f["descriptionText"] for f in followups.json()] == ["new 1", "new 2"]
    assert {f["id"] for f in followups.json()}.isdisjoint({old_1, old_2})


def test_sync_note_empty_followups_deletes_all_for_note() -> None:
    token = _register_and_login("syncnoteempty")
    headers = {"Authorization": f"Bearer {token}"}

    note_id = client.post("/notes", json={"value": "has followups"}, headers=headers).json()["id"]
    client.post(
        f"/notes/{note_id}/followups",
        json={"descriptionText": "to remove", "type": "task"},
        headers=headers,
    )

    response = client.post(
        f"/sync/note/{note_id}",
        json={"followups": []},
        headers=headers,
    )
    assert response.status_code == 200
    assert response.json()["followups"] == []

    followups = client.get(f"/notes/{note_id}/followups", headers=headers)
    assert followups.status_code == 200
    assert followups.json() == []


def test_sync_note_requires_authentication() -> None:
    response = client.post("/sync/note/some-note-id", json={"followups": []})
    assert response.status_code == 401


def test_sync_note_rejects_unowned_note() -> None:
    token_a = _register_and_login("syncnoteforbiddena")
    token_b = _register_and_login("syncnoteforbiddenb")
    headers_a = {"Authorization": f"Bearer {token_a}"}
    headers_b = {"Authorization": f"Bearer {token_b}"}

    note_id = client.post("/notes", json={"value": "private"}, headers=headers_a).json()["id"]
    response = client.post(
        f"/sync/note/{note_id}",
        json={"followups": []},
        headers=headers_b,
    )
    assert response.status_code == 404


def test_notes_crud_flow_for_owner() -> None:
    token = _register_and_login("notesowner")
    headers = {"Authorization": f"Bearer {token}"}

    create = client.post(
        "/notes",
        json={
            "value": "first note",
            "summary": "brief",
            "balanceDueAmount": 120.5,
            "balanceDueCurrency": "USD",
            "categories": ["billing", "priority"],
            "appointmentTiming": "next week",
        },
        headers=headers,
    )
    assert create.status_code == 201
    created = create.json()
    note_id = created["id"]
    assert created["value"] == "first note"
    assert created["summary"] == "brief"
    assert created["balanceDueAmount"] == 120.5
    assert created["balanceDueCurrency"] == "USD"
    assert created["categories"] == ["billing", "priority"]
    assert created["appointmentTiming"] == "next week"
    assert created["createdAtUTC"]
    assert created["editedAtUTC"]

    fetched = client.get(f"/notes/{note_id}", headers=headers)
    assert fetched.status_code == 200
    assert fetched.json()["id"] == note_id
    assert fetched.json()["value"] == "first note"
    assert fetched.json()["summary"] == "brief"

    listed = client.get("/notes", headers=headers)
    assert listed.status_code == 200
    assert any(note["id"] == note_id for note in listed.json())

    updated = client.put(
        f"/notes/{note_id}",
        json={"value": "updated note", "summary": None, "categories": ["updated"]},
        headers=headers,
    )
    assert updated.status_code == 200
    assert updated.json()["id"] == note_id
    assert updated.json()["value"] == "updated note"
    assert updated.json()["summary"] is None
    assert updated.json()["categories"] == ["updated"]
    assert updated.json()["balanceDueAmount"] == 120.5
    assert updated.json()["balanceDueCurrency"] == "USD"

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
        assert note.created_at_utc is not None
        assert note.edited_at_utc is not None


def test_note_modified_at_updates_on_edit() -> None:
    token = _register_and_login("modifiedattest")
    headers = {"Authorization": f"Bearer {token}"}

    created = client.post("/notes", json={"value": "initial"}, headers=headers)
    assert created.status_code == 201
    note_id = created.json()["id"]
    initial_modified_at = created.json()["editedAtUTC"]

    updated = client.put(f"/notes/{note_id}", json={"value": "updated"}, headers=headers)
    assert updated.status_code == 200
    assert updated.json()["editedAtUTC"] != initial_modified_at


def test_note_update_requires_at_least_one_field() -> None:
    token = _register_and_login("noteupdateempty")
    headers = {"Authorization": f"Bearer {token}"}
    note_id = client.post("/notes", json={"value": "initial"}, headers=headers).json()["id"]

    response = client.put(f"/notes/{note_id}", json={}, headers=headers)
    assert response.status_code == 422


def test_delete_note_removes_associated_followups() -> None:
    token = _register_and_login("notecascade")
    headers = {"Authorization": f"Bearer {token}"}

    note_id = client.post("/notes", json={"value": "note with followup"}, headers=headers).json()["id"]
    followup_id = client.post(
        f"/notes/{note_id}/followups",
        json={"descriptionText": "linked", "type": "reminder"},
        headers=headers,
    ).json()["id"]

    deleted = client.delete(f"/notes/{note_id}", headers=headers)
    assert deleted.status_code == 204

    listed = client.get("/followups", headers=headers)
    assert listed.status_code == 200
    assert all(f["id"] != followup_id for f in listed.json())

    with SessionLocal() as db:
        followup = db.get(Followup, followup_id)
        assert followup is None


def test_create_followup_for_owned_note() -> None:
    token = _register_and_login("followupowner")
    headers = {"Authorization": f"Bearer {token}"}

    note = client.post("/notes", json={"value": "needs checkup"}, headers=headers)
    note_id = note.json()["id"]

    created = client.post(
        f"/notes/{note_id}/followups",
        json={
            "descriptionText": "Six month follow-up cleaning",
            "type": "checkup",
        },
        headers=headers,
    )
    assert created.status_code == 201
    body = created.json()
    assert body["id"]
    assert body["noteID"] == note_id
    assert body["descriptionText"] == "Six month follow-up cleaning"
    assert body["type"] == "checkup"
    assert body["completed"] is False
    assert body["createdAtUTC"]
    assert body["editedAtUTC"]


def test_create_followup_without_parent_note() -> None:
    token = _register_and_login("followuporphan")
    headers = {"Authorization": f"Bearer {token}"}

    created = client.post(
        "/followups",
        json={
            "descriptionText": "General reminder",
            "type": "reminder",
        },
        headers=headers,
    )
    assert created.status_code == 201
    body = created.json()
    assert body["id"]
    assert body["noteID"] is None
    assert body["descriptionText"] == "General reminder"
    assert body["type"] == "reminder"
    assert body["completed"] is False


def test_create_followup_with_note_id_on_user_endpoint() -> None:
    token = _register_and_login("followupuserendpoint")
    headers = {"Authorization": f"Bearer {token}"}

    note_id = client.post("/notes", json={"value": "has parent"}, headers=headers).json()["id"]
    created = client.post(
        "/followups",
        json={
            "descriptionText": "linked via user endpoint",
            "type": "task",
            "noteID": note_id,
        },
        headers=headers,
    )
    assert created.status_code == 201
    assert created.json()["noteID"] == note_id


def test_create_followup_with_unowned_note_id_on_user_endpoint_rejected() -> None:
    token_a = _register_and_login("followupuserendowna")
    token_b = _register_and_login("followupuserendownb")
    headers_a = {"Authorization": f"Bearer {token_a}"}
    headers_b = {"Authorization": f"Bearer {token_b}"}

    note_id = client.post("/notes", json={"value": "private note"}, headers=headers_a).json()["id"]
    response = client.post(
        "/followups",
        json={
            "descriptionText": "Unauthorized attempt",
            "type": "checkup",
            "noteID": note_id,
        },
        headers=headers_b,
    )
    assert response.status_code == 404


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
            "descriptionText": "Unauthorized attempt",
            "type": "checkup",
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
        json={"descriptionText": "a1", "type": "task"},
        headers=headers_a,
    )
    client.post(
        f"/notes/{note_b}/followups",
        json={"descriptionText": "b1", "type": "task"},
        headers=headers_b,
    )

    followups_a = client.get("/followups", headers=headers_a)
    assert followups_a.status_code == 200
    assert len(followups_a.json()) == 1
    assert followups_a.json()[0]["descriptionText"] == "a1"


def test_list_followups_for_specific_note() -> None:
    token = _register_and_login("followupnote")
    headers = {"Authorization": f"Bearer {token}"}

    note1 = client.post("/notes", json={"value": "note 1"}, headers=headers).json()["id"]
    note2 = client.post("/notes", json={"value": "note 2"}, headers=headers).json()["id"]

    client.post(
        f"/notes/{note1}/followups",
        json={"descriptionText": "n1-f1", "type": "task"},
        headers=headers,
    )
    client.post(
        f"/notes/{note1}/followups",
        json={"descriptionText": "n1-f2", "type": "task"},
        headers=headers,
    )
    client.post(
        f"/notes/{note2}/followups",
        json={"descriptionText": "n2-f1", "type": "task"},
        headers=headers,
    )

    listed = client.get(f"/notes/{note1}/followups", headers=headers)
    assert listed.status_code == 200
    descriptions = [f["descriptionText"] for f in listed.json()]
    assert descriptions == ["n1-f1", "n1-f2"]


def test_followup_endpoints_require_authentication() -> None:
    assert client.get("/followups").status_code == 401
    assert (
        client.post(
            "/followups",
            json={"descriptionText": "x", "type": "task"},
        ).status_code
        == 401
    )
    assert (
        client.post(
            "/notes/some-note/followups",
            json={"descriptionText": "x", "type": "task"},
        ).status_code
        == 401
    )
    assert client.get("/notes/some-note/followups").status_code == 401


def test_followup_validation_for_bad_payloads() -> None:
    token = _register_and_login("followupvalidation")
    headers = {"Authorization": f"Bearer {token}"}
    note_id = client.post("/notes", json={"value": "note"}, headers=headers).json()["id"]

    empty_type = client.post(
        f"/notes/{note_id}/followups",
        json={"descriptionText": "bad", "type": ""},
        headers=headers,
    )
    assert empty_type.status_code == 422

    too_long_description = client.post(
        f"/notes/{note_id}/followups",
        json={"descriptionText": "a" * 513, "type": "task"},
        headers=headers,
    )
    assert too_long_description.status_code == 422

    missing_description = client.post(
        "/followups",
        json={"type": "task"},
        headers=headers,
    )
    assert missing_description.status_code == 422


def test_followup_creation_time_is_recorded_in_db() -> None:
    token = _register_and_login("followupdbstamp")
    headers = {"Authorization": f"Bearer {token}"}
    note_id = client.post("/notes", json={"value": "note"}, headers=headers).json()["id"]

    created = client.post(
        f"/notes/{note_id}/followups",
        json={"descriptionText": "db check", "type": "task"},
        headers=headers,
    )
    followup_id = created.json()["id"]

    with SessionLocal() as db:
        followup = db.get(Followup, followup_id)
        assert followup is not None
        assert followup.completed is False
        assert followup.created_at_utc is not None
        assert followup.edited_at_utc is not None


def test_followup_completion_toggle_complete_then_incomplete() -> None:
    token = _register_and_login("followuptoggle")
    headers = {"Authorization": f"Bearer {token}"}
    note_id = client.post("/notes", json={"value": "toggle note"}, headers=headers).json()["id"]
    created = client.post(
        f"/notes/{note_id}/followups",
        json={"descriptionText": "toggle me", "type": "task"},
        headers=headers,
    )
    followup_id = created.json()["id"]
    initial_modified_at = created.json()["editedAtUTC"]

    complete = client.patch(
        f"/followups/{followup_id}/completion",
        json={"completed": True},
        headers=headers,
    )
    assert complete.status_code == 200
    assert complete.json()["completed"] is True
    assert complete.json()["editedAtUTC"] != initial_modified_at
    complete_modified_at = complete.json()["editedAtUTC"]

    incomplete = client.patch(
        f"/followups/{followup_id}/completion",
        json={"completed": False},
        headers=headers,
    )
    assert incomplete.status_code == 200
    assert incomplete.json()["completed"] is False
    assert incomplete.json()["editedAtUTC"] != complete_modified_at


def test_update_followup_description_and_type_success() -> None:
    token = _register_and_login("followupupdate")
    headers = {"Authorization": f"Bearer {token}"}
    note_id = client.post("/notes", json={"value": "update note"}, headers=headers).json()["id"]
    created = client.post(
        f"/notes/{note_id}/followups",
        json={"descriptionText": "old description", "type": "task"},
        headers=headers,
    )
    followup_id = created.json()["id"]
    initial_edited_at = created.json()["editedAtUTC"]

    updated = client.patch(
        f"/followups/{followup_id}",
        json={"descriptionText": "new description", "type": "reminder"},
        headers=headers,
    )
    assert updated.status_code == 200
    body = updated.json()
    assert body["id"] == followup_id
    assert body["descriptionText"] == "new description"
    assert body["type"] == "reminder"
    assert body["completed"] is False
    assert body["noteID"] == note_id
    assert body["editedAtUTC"] != initial_edited_at


def test_update_followup_partial_fields_success() -> None:
    token = _register_and_login("followupupdatepartial")
    headers = {"Authorization": f"Bearer {token}"}
    note_id = client.post("/notes", json={"value": "partial note"}, headers=headers).json()["id"]
    created = client.post(
        f"/notes/{note_id}/followups",
        json={"descriptionText": "initial description", "type": "task"},
        headers=headers,
    )
    followup_id = created.json()["id"]

    updated_description = client.patch(
        f"/followups/{followup_id}",
        json={"descriptionText": "description only"},
        headers=headers,
    )
    assert updated_description.status_code == 200
    assert updated_description.json()["descriptionText"] == "description only"
    assert updated_description.json()["type"] == "task"

    updated_type = client.patch(
        f"/followups/{followup_id}",
        json={"type": "checkup"},
        headers=headers,
    )
    assert updated_type.status_code == 200
    assert updated_type.json()["descriptionText"] == "description only"
    assert updated_type.json()["type"] == "checkup"


def test_update_followup_rejects_empty_payload() -> None:
    token = _register_and_login("followupupdateempty")
    headers = {"Authorization": f"Bearer {token}"}
    note_id = client.post("/notes", json={"value": "empty payload note"}, headers=headers).json()["id"]
    followup_id = client.post(
        f"/notes/{note_id}/followups",
        json={"descriptionText": "existing", "type": "task"},
        headers=headers,
    ).json()["id"]

    response = client.patch(f"/followups/{followup_id}", json={}, headers=headers)
    assert response.status_code == 422


def test_update_followup_validation_for_bad_payloads() -> None:
    token = _register_and_login("followupupdatevalidation")
    headers = {"Authorization": f"Bearer {token}"}
    note_id = client.post("/notes", json={"value": "validation note"}, headers=headers).json()["id"]
    followup_id = client.post(
        f"/notes/{note_id}/followups",
        json={"descriptionText": "existing", "type": "task"},
        headers=headers,
    ).json()["id"]

    empty_type = client.patch(
        f"/followups/{followup_id}",
        json={"type": ""},
        headers=headers,
    )
    assert empty_type.status_code == 422

    too_long_description = client.patch(
        f"/followups/{followup_id}",
        json={"descriptionText": "a" * 513},
        headers=headers,
    )
    assert too_long_description.status_code == 422


def test_followup_completion_requires_authentication() -> None:
    response = client.patch(
        "/followups/some-followup/completion",
        json={"completed": True},
    )
    assert response.status_code == 401


def test_update_followup_requires_authentication() -> None:
    response = client.patch(
        "/followups/some-followup",
        json={"descriptionText": "updated"},
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
        json={"descriptionText": "private followup", "type": "task"},
        headers=headers_a,
    ).json()["id"]

    response = client.patch(
        f"/followups/{followup_id}/completion",
        json={"completed": True},
        headers=headers_b,
    )
    assert response.status_code == 404


def test_update_followup_rejects_unowned_followup() -> None:
    token_a = _register_and_login("followupupdateowna")
    token_b = _register_and_login("followupupdateownb")
    headers_a = {"Authorization": f"Bearer {token_a}"}
    headers_b = {"Authorization": f"Bearer {token_b}"}

    note_id = client.post("/notes", json={"value": "private"}, headers=headers_a).json()["id"]
    followup_id = client.post(
        f"/notes/{note_id}/followups",
        json={"descriptionText": "private followup", "type": "task"},
        headers=headers_a,
    ).json()["id"]

    response = client.patch(
        f"/followups/{followup_id}",
        json={"descriptionText": "hijack"},
        headers=headers_b,
    )
    assert response.status_code == 404


def test_followup_completion_rejects_unknown_followup() -> None:
    token = _register_and_login("followupmissing")
    headers = {"Authorization": f"Bearer {token}"}

    response = client.patch(
        "/followups/not-a-real-id/completion",
        json={"completed": True},
        headers=headers,
    )
    assert response.status_code == 404


def test_update_followup_rejects_unknown_followup() -> None:
    token = _register_and_login("followupupdatemissing")
    headers = {"Authorization": f"Bearer {token}"}

    response = client.patch(
        "/followups/not-a-real-id",
        json={"descriptionText": "updated"},
        headers=headers,
    )
    assert response.status_code == 404


def test_delete_followup_success() -> None:
    token = _register_and_login("followupdelete")
    headers = {"Authorization": f"Bearer {token}"}
    note_id = client.post("/notes", json={"value": "delete note"}, headers=headers).json()["id"]
    followup_id = client.post(
        f"/notes/{note_id}/followups",
        json={"descriptionText": "delete me", "type": "task"},
        headers=headers,
    ).json()["id"]

    deleted = client.delete(f"/followups/{followup_id}", headers=headers)
    assert deleted.status_code == 204

    listed = client.get("/followups", headers=headers)
    assert listed.status_code == 200
    assert all(f["id"] != followup_id for f in listed.json())


def test_delete_followup_requires_authentication() -> None:
    response = client.delete("/followups/some-followup")
    assert response.status_code == 401


def test_delete_followup_rejects_unowned_followup() -> None:
    token_a = _register_and_login("followupdeletea")
    token_b = _register_and_login("followupdeleteb")
    headers_a = {"Authorization": f"Bearer {token_a}"}
    headers_b = {"Authorization": f"Bearer {token_b}"}

    note_id = client.post("/notes", json={"value": "private"}, headers=headers_a).json()["id"]
    followup_id = client.post(
        f"/notes/{note_id}/followups",
        json={"descriptionText": "private followup", "type": "task"},
        headers=headers_a,
    ).json()["id"]

    response = client.delete(f"/followups/{followup_id}", headers=headers_b)
    assert response.status_code == 404


def test_delete_followup_rejects_unknown_followup() -> None:
    token = _register_and_login("followupdeletemissing")
    headers = {"Authorization": f"Bearer {token}"}

    response = client.delete("/followups/not-a-real-id", headers=headers)
    assert response.status_code == 404


class _FakeAIResponse:
    def __init__(self, payload: dict) -> None:
        self._payload = payload

    def read(self) -> bytes:
        return json.dumps(self._payload).encode("utf-8")

    def __enter__(self) -> "_FakeAIResponse":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None


def test_process_note_requires_authentication() -> None:
    response = client.post("/notes/process", json={"noteID": "some-note-id"})
    assert response.status_code == 401


def test_process_note_returns_404_for_unowned_note() -> None:
    token_a = _register_and_login("processownera")
    token_b = _register_and_login("processownerb")
    headers_a = {"Authorization": f"Bearer {token_a}"}
    headers_b = {"Authorization": f"Bearer {token_b}"}
    note_id = client.post("/notes", json={"value": "owner a only"}, headers=headers_a).json()["id"]

    response = client.post("/notes/process", json={"noteID": note_id}, headers=headers_b)
    assert response.status_code == 404


def test_process_note_returns_500_when_ai_provider_not_configured(monkeypatch) -> None:
    token = _register_and_login("processmissingcfg")
    headers = {"Authorization": f"Bearer {token}"}
    note_id = client.post("/notes", json={"value": "config check"}, headers=headers).json()["id"]
    monkeypatch.delenv("AI_ENDPOINT", raising=False)
    monkeypatch.delenv("AI_MODEL", raising=False)
    monkeypatch.delenv("AI_API_KEY", raising=False)

    response = client.post("/notes/process", json={"noteID": note_id}, headers=headers)
    assert response.status_code == 500
    assert response.json()["detail"] == "AI provider is not configured"


def test_process_note_success_with_provider_response(monkeypatch) -> None:
    token = _register_and_login("processsuccess")
    headers = {"Authorization": f"Bearer {token}"}
    note = client.post("/notes", json={"value": "Patient owes $120 and needs call back in March."}, headers=headers)
    note_id = note.json()["id"]

    monkeypatch.setenv("AI_ENDPOINT", "https://provider.example/v1/messages")
    monkeypatch.setenv("AI_MODEL", "test-model")
    monkeypatch.setenv("AI_API_KEY", "test-key")

    captured: dict[str, str] = {}

    def _fake_urlopen(request, timeout):  # noqa: ANN001
        assert timeout == 30
        captured["endpoint"] = request.full_url
        body = json.loads(request.data.decode("utf-8"))
        captured["system"] = body["system"]
        captured["user"] = body["messages"][0]["content"]
        return _FakeAIResponse(
            {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(
                            {
                                "summary": "Patient has an outstanding balance and requested follow-up.",
                                "categories": ["Payment", "Appointment"],
                                "balance_due": {"amount": 120, "currency": "USD"},
                                "actions": [{"type": "Appointment", "description": "Call patient back"}],
                                "appointment_timing": "March",
                            }
                        ),
                    }
                ]
            }
        )

    monkeypatch.setattr("app.main.urlopen", _fake_urlopen)
    response = client.post("/notes/process", json={"noteID": note_id}, headers=headers)
    assert response.status_code == 200
    body = response.json()
    assert body["summary"]
    assert body["categories"] == ["Payment", "Appointment"]
    assert body["balance_due"] == {"amount": 120.0, "currency": "USD"}
    assert body["actions"] == [{"type": "Appointment", "description": "Call patient back"}]
    assert body["appointment_timing"] == "March"

    assert captured["endpoint"] == "https://provider.example/v1/messages"
    assert "Analyze the user's dental note and return:" in captured["system"]
    assert "Patient owes $120 and needs call back in March." in captured["user"]
    assert "Reference date (note created date):" in captured["user"]


def test_process_note_returns_502_for_provider_network_failure(monkeypatch) -> None:
    token = _register_and_login("processnetfail")
    headers = {"Authorization": f"Bearer {token}"}
    note_id = client.post("/notes", json={"value": "network fail"}, headers=headers).json()["id"]

    monkeypatch.setenv("AI_ENDPOINT", "https://provider.example/v1/messages")
    monkeypatch.setenv("AI_MODEL", "test-model")
    monkeypatch.setenv("AI_API_KEY", "test-key")

    def _raise_network_error(*args, **kwargs):  # noqa: ANN002, ANN003
        raise URLError("network down")

    monkeypatch.setattr("app.main.urlopen", _raise_network_error)
    response = client.post("/notes/process", json={"noteID": note_id}, headers=headers)
    assert response.status_code == 502
    assert response.json()["detail"] == "AI provider request failed"


def test_process_note_returns_502_for_invalid_extraction_payload(monkeypatch) -> None:
    token = _register_and_login("processbadpayload")
    headers = {"Authorization": f"Bearer {token}"}
    note_id = client.post("/notes", json={"value": "bad payload"}, headers=headers).json()["id"]

    monkeypatch.setenv("AI_ENDPOINT", "https://provider.example/v1/messages")
    monkeypatch.setenv("AI_MODEL", "test-model")
    monkeypatch.setenv("AI_API_KEY", "test-key")

    def _fake_urlopen(*args, **kwargs):  # noqa: ANN002, ANN003
        return _FakeAIResponse({"content": [{"type": "text", "text": "{\"summary\": \"missing fields\"}"}]})

    monkeypatch.setattr("app.main.urlopen", _fake_urlopen)
    response = client.post("/notes/process", json={"noteID": note_id}, headers=headers)
    assert response.status_code == 502
    assert response.json()["detail"] == "AI provider returned invalid extraction JSON"


def test_process_note_rejects_path_traversal_in_prompt_loader(monkeypatch) -> None:
    token = _register_and_login("processprompttraversal")
    headers = {"Authorization": f"Bearer {token}"}
    note_id = client.post("/notes", json={"value": "prompt traversal"}, headers=headers).json()["id"]

    monkeypatch.setenv("AI_ENDPOINT", "https://provider.example/v1/messages")
    monkeypatch.setenv("AI_MODEL", "test-model")
    monkeypatch.setenv("AI_API_KEY", "test-key")

    from app.main import _load_prompt_text as original_loader
    def _patched_loader(file_name: str):  # noqa: ANN001
        if file_name == "PromptSystem.md":
            return original_loader("../README.md")
        return original_loader(file_name)

    monkeypatch.setattr("app.main._load_prompt_text", _patched_loader)
    response = client.post("/notes/process", json={"noteID": note_id}, headers=headers)
    assert response.status_code == 500
    assert response.json()["detail"] == "Prompt file missing"


def test_process_note_rejects_absolute_path_in_prompt_loader(monkeypatch) -> None:
    token = _register_and_login("processpromptabsolute")
    headers = {"Authorization": f"Bearer {token}"}
    note_id = client.post("/notes", json={"value": "prompt absolute path"}, headers=headers).json()["id"]

    monkeypatch.setenv("AI_ENDPOINT", "https://provider.example/v1/messages")
    monkeypatch.setenv("AI_MODEL", "test-model")
    monkeypatch.setenv("AI_API_KEY", "test-key")

    from app.main import _load_prompt_text as original_loader
    def _patched_loader(file_name: str):  # noqa: ANN001
        if file_name == "PromptSystem.md":
            return original_loader("/etc/passwd")
        return original_loader(file_name)

    monkeypatch.setattr("app.main._load_prompt_text", _patched_loader)
    response = client.post("/notes/process", json={"noteID": note_id}, headers=headers)
    assert response.status_code == 500
    assert response.json()["detail"] == "Prompt file missing"
