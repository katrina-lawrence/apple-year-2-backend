from __future__ import annotations

import os
import secrets
import json
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from uuid import uuid4

import jwt
from fastapi import Depends, FastAPI, HTTPException, Response, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, Field, ValidationError, model_validator
from pwdlib import PasswordHash
from sqlalchemy import JSON, Boolean, DateTime, Float, String, Text, create_engine, func
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from app.db.bootstrap import init_db, maybe_seed_sample_data
from app.db.sample_data import seed_sample_data

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY") or secrets.token_urlsafe(64)
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "60"))
JWT_REFRESH_EXPIRE_DAYS = int(os.getenv("JWT_REFRESH_EXPIRE_DAYS", "30"))
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./app.db")
PROMPTS_DIR = Path(__file__).resolve().parent / "prompts"
# Match the note and follow-up description editors in the iOS app.
MAX_TEXT_LENGTH = 2048

password_hash = PasswordHash.recommended()


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String(50), nullable=False, unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)


class Note(Base):
    __tablename__ = "notes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, index=True)
    owner_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    balance_due_amount: Mapped[float | None] = mapped_column(Float, nullable=True)
    balance_due_currency: Mapped[str | None] = mapped_column(String(16), nullable=True)
    categories: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    appointment_timing: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    edited_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class Followup(Base):
    __tablename__ = "followups"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, index=True)
    owner_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    note_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    description_text: Mapped[str] = mapped_column(Text, nullable=False)
    type: Mapped[str] = mapped_column(String(64), nullable=False)
    completed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="0")
    created_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    edited_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=12)


class RegisterResponse(BaseModel):
    user_id: str


class LoginRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=12)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class AccessTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserResponse(BaseModel):
    user_id: str


class UserSyncResponse(BaseModel):
    notes: list["NoteResponse"]
    followups: list["FollowupResponse"]
    serverTimeUTC: datetime


class StatusResponse(BaseModel):
    status: str


class NoteCreateRequest(BaseModel):
    value: str = Field(min_length=1, max_length=MAX_TEXT_LENGTH)
    summary: str | None = None
    balanceDueAmount: float | None = None
    balanceDueCurrency: str | None = None
    categories: list[str] | None = None
    appointmentTiming: str | None = None


class NoteUpdateRequest(BaseModel):
    value: str | None = Field(default=None, min_length=1, max_length=MAX_TEXT_LENGTH)
    summary: str | None = None
    balanceDueAmount: float | None = None
    balanceDueCurrency: str | None = None
    categories: list[str] | None = None
    appointmentTiming: str | None = None

    @model_validator(mode="after")
    def validate_at_least_one_field(self) -> "NoteUpdateRequest":
        if self.model_fields_set:
            return self
        raise ValueError("At least one field must be provided")


class NoteResponse(BaseModel):
    id: str
    value: str
    summary: str | None
    balanceDueAmount: float | None
    balanceDueCurrency: str | None
    categories: list[str] | None
    appointmentTiming: str | None
    createdAtUTC: datetime
    editedAtUTC: datetime


class CreateFollowupRequest(BaseModel):
    descriptionText: str = Field(min_length=1, max_length=MAX_TEXT_LENGTH)
    type: str = Field(min_length=1, max_length=64)


class CreateUserFollowupRequest(CreateFollowupRequest):
    noteID: str | None = None


class FollowupResponse(BaseModel):
    id: str
    descriptionText: str
    type: str
    noteID: str | None
    createdAtUTC: datetime
    editedAtUTC: datetime
    completed: bool


class FollowupCompletionRequest(BaseModel):
    completed: bool


class BackupNote(NoteCreateRequest):
    id: str = Field(min_length=1, max_length=36)
    createdAtUTC: datetime
    editedAtUTC: datetime


class BackupFollowup(CreateUserFollowupRequest):
    id: str = Field(min_length=1, max_length=36)
    createdAtUTC: datetime
    editedAtUTC: datetime
    isCompleted: bool


class BackupRestoreRequest(BaseModel):
    formatVersion: Literal[1]
    exportedAtUTC: datetime
    notes: list[BackupNote]
    followups: list[BackupFollowup]

    @model_validator(mode="after")
    def validate_record_ids(self) -> "BackupRestoreRequest":
        note_ids = {note.id for note in self.notes}
        followup_ids = {followup.id for followup in self.followups}
        if len(note_ids) != len(self.notes) or len(followup_ids) != len(self.followups):
            raise ValueError("Backup contains duplicate record IDs")
        if any(item.noteID is not None and item.noteID not in note_ids for item in self.followups):
            raise ValueError("A follow-up references a note missing from the backup")
        return self


class BackupRestoreResponse(BaseModel):
    restoredNotes: int
    restoredFollowups: int
    skippedNotes: int
    skippedFollowups: int


class FollowupUpdateRequest(BaseModel):
    descriptionText: str | None = Field(default=None, min_length=1, max_length=MAX_TEXT_LENGTH)
    type: str | None = Field(default=None, min_length=1, max_length=64)

    @model_validator(mode="after")
    def validate_at_least_one_field(self) -> "FollowupUpdateRequest":
        if self.model_fields_set:
            return self
        raise ValueError("At least one field must be provided")


class SyncNoteRequest(BaseModel):
    value: str | None = Field(default=None, min_length=1, max_length=MAX_TEXT_LENGTH)
    summary: str | None = None
    balanceDueAmount: float | None = None
    balanceDueCurrency: str | None = None
    categories: list[str] | None = None
    appointmentTiming: str | None = None
    followups: list[CreateFollowupRequest]


class SyncNoteResponse(BaseModel):
    note: NoteResponse
    followups: list[FollowupResponse]


class ProcessNoteRequest(BaseModel):
    noteID: str


class ProcessedBalanceDue(BaseModel):
    amount: float | None
    currency: str | None


class ProcessedAction(BaseModel):
    type: str
    description: str


class ProcessedNoteResponse(BaseModel):
    summary: str
    categories: list[str]
    balance_due: ProcessedBalanceDue
    actions: list[ProcessedAction]
    appointment_timing: str | None


connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def startup_initialize_database() -> None:
    init_db(Base, engine)
    maybe_seed_sample_data(
        SessionLocal,
        lambda db: seed_sample_data(db, User, Note, Followup, hash_password),
    )


@asynccontextmanager
async def lifespan(_: FastAPI):
    startup_initialize_database()
    yield


app = FastAPI(title="FastAPI Auth API", lifespan=lifespan)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def hash_password(password: str) -> str:
    return password_hash.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    return password_hash.verify(password, hashed_password)


def create_access_token(user_id: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRE_MINUTES)
    payload = {"sub": user_id, "exp": expire, "type": "access"}
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def create_refresh_token(user_id: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(days=JWT_REFRESH_EXPIRE_DAYS)
    payload = {"sub": user_id, "exp": expire, "type": "refresh"}
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> str:
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("sub")
        if not user_id:
            raise jwt.InvalidTokenError("Missing sub claim")
        token_type = payload.get("type")
        if token_type != "access":
            raise jwt.InvalidTokenError("Wrong token type")
        return user_id
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def decode_refresh_token(token: str) -> str:
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("sub")
        if not user_id:
            raise jwt.InvalidTokenError("Missing sub claim")
        token_type = payload.get("type")
        if token_type != "refresh":
            raise jwt.InvalidTokenError("Wrong token type")
        return user_id
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate refresh token",
        ) from exc


def validate_password(password: str) -> None:
    checks = (
        (
            len(password) >= 12,
            "Password must be at least 12 characters long",
        ),
    )

    for passed, message in checks:
        if not passed:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=message)


@app.get("/status", response_model=StatusResponse)
def get_status() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED)
def register_user(payload: RegisterRequest, db: Session = Depends(get_db)) -> RegisterResponse:
    validate_password(payload.password)

    existing_user = db.query(User).filter(User.username == payload.username).first()
    if existing_user is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already exists")

    user_id = str(uuid4())
    user = User(id=user_id, username=payload.username, password_hash=hash_password(payload.password))
    db.add(user)
    db.commit()
    return RegisterResponse(user_id=user_id)


@app.post("/login", response_model=TokenResponse)
def login_user(payload: LoginRequest, db: Session = Depends(get_db)) -> TokenResponse:
    user = db.query(User).filter(User.username == payload.username).first()
    if user is None or not verify_password(payload.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return TokenResponse(
        access_token=create_access_token(user.id),
        refresh_token=create_refresh_token(user.id),
    )


@app.post("/refresh", response_model=AccessTokenResponse)
def refresh_access_token(payload: RefreshTokenRequest, db: Session = Depends(get_db)) -> AccessTokenResponse:
    user_id = decode_refresh_token(payload.refresh_token)
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User does not exist",
        )
    return AccessTokenResponse(access_token=create_access_token(user.id))


def get_current_user_id(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> str:
    user_id = decode_access_token(token)
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User does not exist",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user.id


@app.get("/user", response_model=UserResponse)
def get_user(user_id: str = Depends(get_current_user_id)) -> UserResponse:
    return UserResponse(user_id=user_id)


@app.get("/sync/user", response_model=UserSyncResponse)
def sync_user_data(
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> UserSyncResponse:
    notes = db.query(Note).filter(Note.owner_id == user_id).order_by(Note.created_at_utc.desc()).all()
    followups = (
        db.query(Followup)
        .filter(Followup.owner_id == user_id)
        .order_by(Followup.created_at_utc.asc())
        .all()
    )
    return UserSyncResponse(
        notes=[build_note_response(note) for note in notes],
        followups=[build_followup_response(followup) for followup in followups],
        serverTimeUTC=datetime.now(timezone.utc),
    )


@app.post("/change-password", response_model=StatusResponse)
def change_password(
    payload: ChangePasswordRequest,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> StatusResponse:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User does not exist",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid current password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    validate_password(payload.new_password)
    user.password_hash = hash_password(payload.new_password)
    db.add(user)
    db.commit()
    return StatusResponse(status="ok")


def build_note_response(note: Note) -> NoteResponse:
    return NoteResponse(
        id=note.id,
        value=note.value,
        summary=note.summary,
        balanceDueAmount=note.balance_due_amount,
        balanceDueCurrency=note.balance_due_currency,
        categories=note.categories,
        appointmentTiming=note.appointment_timing,
        createdAtUTC=note.created_at_utc,
        editedAtUTC=note.edited_at_utc,
    )


def build_followup_response(followup: Followup) -> FollowupResponse:
    return FollowupResponse(
        id=followup.id,
        descriptionText=followup.description_text,
        type=followup.type,
        noteID=followup.note_id,
        createdAtUTC=followup.created_at_utc,
        editedAtUTC=followup.edited_at_utc,
        completed=followup.completed,
    )


def _load_prompt_text(file_name: str) -> str:
    try:
        # Guard against path traversal; prompt files must stay under PROMPTS_DIR.
        prompts_root = PROMPTS_DIR.resolve()
        prompt_path = (prompts_root / file_name).resolve()
        prompt_path.relative_to(prompts_root)
        return prompt_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Prompt file missing") from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Prompt file missing") from exc


def _extract_json_candidate(raw_text: str) -> str:
    text = raw_text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if len(lines) >= 3 and lines[-1].strip() == "```":
            text = "\n".join(lines[1:-1]).strip()
    return text


def _normalize_processed_note_payload(parsed_json: dict[str, object]) -> dict[str, object]:
    normalized = dict(parsed_json)
    balance_due = normalized.get("balance_due")
    if balance_due is None:
        normalized["balance_due"] = {"amount": None, "currency": None}
    elif isinstance(balance_due, dict):
        normalized["balance_due"] = {
            "amount": balance_due.get("amount"),
            "currency": balance_due.get("currency"),
        }
    return normalized


def _call_ai_note_processor(system_prompt: str, user_prompt: str) -> ProcessedNoteResponse:
    ai_endpoint = os.getenv("AI_ENDPOINT")
    ai_model = os.getenv("AI_MODEL")
    ai_api_key = os.getenv("AI_API_KEY")
    if not ai_endpoint or not ai_model or not ai_api_key:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="AI provider is not configured",
        )

    payload = {
        "model": ai_model,
        "max_tokens": 1024,
        "system": system_prompt,
        "messages": [{"role": "user", "content": user_prompt}],
    }
    request = Request(
        ai_endpoint,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "x-api-key": ai_api_key,
            "Authorization": f"Bearer {ai_api_key}",
            "anthropic-version": "2023-06-01",
        },
    )
    try:
        with urlopen(request, timeout=30) as response:
            response_body = response.read().decode("utf-8")
    except (HTTPError, URLError, TimeoutError) as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="AI provider request failed") from exc

    try:
        provider_json = json.loads(response_body)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="AI provider returned invalid JSON") from exc

    content_blocks = provider_json.get("content")
    if not isinstance(content_blocks, list):
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="AI provider returned invalid content")
    text_blocks = [
        block.get("text", "")
        for block in content_blocks
        if isinstance(block, dict) and block.get("type") == "text" and isinstance(block.get("text"), str)
    ]
    if not text_blocks:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="AI provider returned empty response")

    parsed_content = _extract_json_candidate("\n".join(text_blocks))
    try:
        parsed_json = json.loads(parsed_content)
        if isinstance(parsed_json, dict):
            parsed_json = _normalize_processed_note_payload(parsed_json)
        result = ProcessedNoteResponse.model_validate(parsed_json)
        return result
    except (json.JSONDecodeError, ValidationError) as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="AI provider returned invalid extraction JSON") from exc


@app.post("/backups/restore", response_model=BackupRestoreResponse)
def restore_backup(
    payload: BackupRestoreRequest,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> BackupRestoreResponse:
    # Check the whole backup before writing. Existing records are never overwritten.
    existing_notes = {
        item.id: item for item in db.query(Note).filter(Note.id.in_([n.id for n in payload.notes])).all()
    }
    existing_followups = {
        item.id: item for item in db.query(Followup).filter(
            Followup.id.in_([f.id for f in payload.followups])
        ).all()
    }
    if any(item.owner_id != user_id for item in [*existing_notes.values(), *existing_followups.values()]):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Backup record IDs conflict with another account")

    for note in payload.notes:
        if note.id not in existing_notes:
            db.add(Note(
                id=note.id, owner_id=user_id, value=note.value, summary=note.summary,
                balance_due_amount=note.balanceDueAmount, balance_due_currency=note.balanceDueCurrency,
                categories=note.categories, appointment_timing=note.appointmentTiming,
                created_at_utc=note.createdAtUTC, edited_at_utc=note.editedAtUTC,
            ))
    for followup in payload.followups:
        if followup.id not in existing_followups:
            db.add(Followup(
                id=followup.id, owner_id=user_id, note_id=followup.noteID,
                description_text=followup.descriptionText, type=followup.type,
                completed=followup.isCompleted,
                created_at_utc=followup.createdAtUTC, edited_at_utc=followup.editedAtUTC,
            ))

    # One transaction prevents a failed restore from leaving half a backup saved.
    db.commit()
    return BackupRestoreResponse(
        restoredNotes=len(payload.notes) - len(existing_notes),
        restoredFollowups=len(payload.followups) - len(existing_followups),
        skippedNotes=len(existing_notes), skippedFollowups=len(existing_followups),
    )


@app.post("/notes", response_model=NoteResponse, status_code=status.HTTP_201_CREATED)
def create_note(
    payload: NoteCreateRequest,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> NoteResponse:
    note = Note(
        id=str(uuid4()),
        owner_id=user_id,
        value=payload.value,
        summary=payload.summary,
        balance_due_amount=payload.balanceDueAmount,
        balance_due_currency=payload.balanceDueCurrency,
        categories=payload.categories,
        appointment_timing=payload.appointmentTiming,
    )
    db.add(note)
    db.commit()
    db.refresh(note)
    return build_note_response(note)


@app.get("/notes", response_model=list[NoteResponse])
def list_notes(
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> list[NoteResponse]:
    notes = db.query(Note).filter(Note.owner_id == user_id).order_by(Note.created_at_utc.desc()).all()
    return [build_note_response(n) for n in notes]


@app.get("/notes/{note_id}", response_model=NoteResponse)
def get_note(
    note_id: str,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> NoteResponse:
    note = db.query(Note).filter(Note.id == note_id, Note.owner_id == user_id).first()
    if note is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found")
    return build_note_response(note)


@app.put("/notes/{note_id}", response_model=NoteResponse)
def update_note(
    note_id: str,
    payload: NoteUpdateRequest,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> NoteResponse:
    note = db.query(Note).filter(Note.id == note_id, Note.owner_id == user_id).first()
    if note is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found")
    changed_fields = payload.model_dump(exclude_unset=True)
    if "value" in changed_fields:
        note.value = payload.value  # type: ignore[assignment]
    if "summary" in changed_fields:
        note.summary = payload.summary
    if "balanceDueAmount" in changed_fields:
        note.balance_due_amount = payload.balanceDueAmount
    if "balanceDueCurrency" in changed_fields:
        note.balance_due_currency = payload.balanceDueCurrency
    if "categories" in changed_fields:
        note.categories = payload.categories
    if "appointmentTiming" in changed_fields:
        note.appointment_timing = payload.appointmentTiming

    note.edited_at_utc = datetime.now(timezone.utc)
    db.add(note)
    db.commit()
    db.refresh(note)
    return build_note_response(note)


@app.post("/sync/note/{note_id}", response_model=SyncNoteResponse)
def sync_note(
    note_id: str,
    payload: SyncNoteRequest,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> SyncNoteResponse:
    note = db.query(Note).filter(Note.id == note_id, Note.owner_id == user_id).first()
    if note is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found")

    changed_fields = payload.model_dump(exclude={"followups"}, exclude_unset=True)
    if "value" in changed_fields:
        note.value = payload.value  # type: ignore[assignment]
    if "summary" in changed_fields:
        note.summary = payload.summary
    if "balanceDueAmount" in changed_fields:
        note.balance_due_amount = payload.balanceDueAmount
    if "balanceDueCurrency" in changed_fields:
        note.balance_due_currency = payload.balanceDueCurrency
    if "categories" in changed_fields:
        note.categories = payload.categories
    if "appointmentTiming" in changed_fields:
        note.appointment_timing = payload.appointmentTiming
    if changed_fields:
        note.edited_at_utc = datetime.now(timezone.utc)

    db.query(Followup).filter(Followup.owner_id == user_id, Followup.note_id == note_id).delete(
        synchronize_session=False
    )

    inserted_followups: list[Followup] = []
    for item in payload.followups:
        followup = Followup(
            id=str(uuid4()),
            owner_id=user_id,
            note_id=note_id,
            description_text=item.descriptionText,
            type=item.type,
            completed=False,
        )
        db.add(followup)
        inserted_followups.append(followup)

    db.add(note)
    db.commit()
    db.refresh(note)
    for followup in inserted_followups:
        db.refresh(followup)

    return SyncNoteResponse(
        note=build_note_response(note),
        followups=[build_followup_response(followup) for followup in inserted_followups],
    )


@app.delete("/notes/{note_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_note(
    note_id: str,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> Response:
    note = db.query(Note).filter(Note.id == note_id, Note.owner_id == user_id).first()
    if note is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found")
    db.query(Followup).filter(Followup.note_id == note_id).delete(synchronize_session=False)
    db.delete(note)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.post("/notes/{note_id}/followups", response_model=FollowupResponse, status_code=status.HTTP_201_CREATED)
def create_followup_for_note(
    note_id: str,
    payload: CreateFollowupRequest,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> FollowupResponse:
    note = db.query(Note).filter(Note.id == note_id, Note.owner_id == user_id).first()
    if note is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found")

    followup = Followup(
        id=str(uuid4()),
        owner_id=user_id,
        note_id=note_id,
        description_text=payload.descriptionText,
        type=payload.type,
        completed=False,
    )
    db.add(followup)
    db.commit()
    db.refresh(followup)
    return build_followup_response(followup)


@app.post("/notes/process", response_model=ProcessedNoteResponse)
def process_note(
    payload: ProcessNoteRequest,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> ProcessedNoteResponse:
    note = db.query(Note).filter(Note.id == payload.noteID, Note.owner_id == user_id).first()
    if note is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found")

    system_prompt = _load_prompt_text("PromptSystem.md")
    user_prompt_template = _load_prompt_text("PromptUser.md")
    reference_iso = note.created_at_utc.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    user_prompt = (
        user_prompt_template.replace("{{referenceISO}}", reference_iso).replace("{{noteText}}", note.value)
    )
    return _call_ai_note_processor(system_prompt, user_prompt)


@app.post("/followups", response_model=FollowupResponse, status_code=status.HTTP_201_CREATED)
def create_followup_for_user(
    payload: CreateUserFollowupRequest,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> FollowupResponse:
    if payload.noteID is not None:
        note = db.query(Note).filter(Note.id == payload.noteID, Note.owner_id == user_id).first()
        if note is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found")

    followup = Followup(
        id=str(uuid4()),
        owner_id=user_id,
        note_id=payload.noteID,
        description_text=payload.descriptionText,
        type=payload.type,
        completed=False,
    )
    db.add(followup)
    db.commit()
    db.refresh(followup)
    return build_followup_response(followup)


@app.get("/followups", response_model=list[FollowupResponse])
def list_followups_for_user(
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> list[FollowupResponse]:
    followups = (
        db.query(Followup)
        .filter(Followup.owner_id == user_id)
        .order_by(Followup.created_at_utc.asc())
        .all()
    )
    return [build_followup_response(f) for f in followups]


@app.get("/notes/{note_id}/followups", response_model=list[FollowupResponse])
def list_followups_for_note(
    note_id: str,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> list[FollowupResponse]:
    note = db.query(Note).filter(Note.id == note_id, Note.owner_id == user_id).first()
    if note is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found")

    followups = (
        db.query(Followup)
        .filter(Followup.owner_id == user_id, Followup.note_id == note_id)
        .order_by(Followup.created_at_utc.asc())
        .all()
    )
    return [build_followup_response(f) for f in followups]


@app.patch("/followups/{followup_id}/completion", response_model=FollowupResponse)
def set_followup_completion(
    followup_id: str,
    payload: FollowupCompletionRequest,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> FollowupResponse:
    followup = db.query(Followup).filter(Followup.id == followup_id, Followup.owner_id == user_id).first()
    if followup is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Followup not found")

    followup.completed = payload.completed
    followup.edited_at_utc = datetime.now(timezone.utc)
    db.add(followup)
    db.commit()
    db.refresh(followup)
    return build_followup_response(followup)


@app.patch("/followups/{followup_id}", response_model=FollowupResponse)
def update_followup(
    followup_id: str,
    payload: FollowupUpdateRequest,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> FollowupResponse:
    followup = db.query(Followup).filter(Followup.id == followup_id, Followup.owner_id == user_id).first()
    if followup is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Followup not found")

    changed_fields = payload.model_dump(exclude_unset=True)
    if "descriptionText" in changed_fields:
        followup.description_text = payload.descriptionText  # type: ignore[assignment]
    if "type" in changed_fields:
        followup.type = payload.type  # type: ignore[assignment]

    followup.edited_at_utc = datetime.now(timezone.utc)
    db.add(followup)
    db.commit()
    db.refresh(followup)
    return build_followup_response(followup)


@app.delete("/followups/{followup_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_followup(
    followup_id: str,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> Response:
    followup = db.query(Followup).filter(Followup.id == followup_id, Followup.owner_id == user_id).first()
    if followup is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Followup not found")
    db.delete(followup)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
