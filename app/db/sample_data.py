from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone

from sqlalchemy.orm import Session


SEED_USER_ID = "11111111-1111-1111-1111-111111111111"
SEED_NOTE_ID_1 = "22222222-2222-2222-2222-222222222221"
SEED_NOTE_ID_2 = "22222222-2222-2222-2222-222222222222"
SEED_FOLLOWUP_ID_1 = "33333333-3333-3333-3333-333333333331"
SEED_FOLLOWUP_ID_2 = "33333333-3333-3333-3333-333333333332"
SEED_USERNAME = "demo_user"
SEED_PASSWORD = "demo-password-123"


def seed_sample_data(
    db: Session,
    user_model: type,
    note_model: type,
    followup_model: type,
    hash_password_fn: Callable[[str], str],
) -> None:
    existing_user = db.query(user_model).filter(user_model.username == SEED_USERNAME).first()
    if existing_user is None:
        existing_user = user_model(
            id=SEED_USER_ID,
            username=SEED_USERNAME,
            password_hash=hash_password_fn(SEED_PASSWORD),
        )
        db.add(existing_user)

    now = datetime.now(timezone.utc)

    existing_note_1 = db.get(note_model, SEED_NOTE_ID_1)
    if existing_note_1 is None:
        db.add(
            note_model(
                id=SEED_NOTE_ID_1,
                owner_id=existing_user.id,
                value="Demo note: outstanding balance for cleaning visit",
                summary="Follow up on billing",
                balance_due_amount=85.0,
                balance_due_currency="USD",
                categories=["billing", "follow-up"],
                appointment_timing="next week",
                created_at_utc=now,
                edited_at_utc=now,
            )
        )

    existing_note_2 = db.get(note_model, SEED_NOTE_ID_2)
    if existing_note_2 is None:
        db.add(
            note_model(
                id=SEED_NOTE_ID_2,
                owner_id=existing_user.id,
                value="Demo note: treatment plan confirmed",
                summary="Prep next appointment",
                categories=["treatment"],
                appointment_timing="tomorrow morning",
                created_at_utc=now,
                edited_at_utc=now,
            )
        )

    existing_followup_1 = db.get(followup_model, SEED_FOLLOWUP_ID_1)
    if existing_followup_1 is None:
        db.add(
            followup_model(
                id=SEED_FOLLOWUP_ID_1,
                owner_id=existing_user.id,
                note_id=SEED_NOTE_ID_1,
                description_text="Call patient to confirm payment method.",
                type="billing",
                completed=False,
                created_at_utc=now,
                edited_at_utc=now,
            )
        )

    existing_followup_2 = db.get(followup_model, SEED_FOLLOWUP_ID_2)
    if existing_followup_2 is None:
        db.add(
            followup_model(
                id=SEED_FOLLOWUP_ID_2,
                owner_id=existing_user.id,
                note_id=SEED_NOTE_ID_2,
                description_text="Send prep checklist by email.",
                type="reminder",
                completed=False,
                created_at_utc=now,
                edited_at_utc=now,
            )
        )
