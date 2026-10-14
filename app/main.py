from __future__ import annotations

import os
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import jwt
from fastapi import Depends, FastAPI, HTTPException, Response, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, Field, model_validator
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
    note_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
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
    value: str = Field(min_length=1, max_length=512)
    summary: str | None = None
    balanceDueAmount: float | None = None
    balanceDueCurrency: str | None = None
    categories: list[str] | None = None
    appointmentTiming: str | None = None


class NoteUpdateRequest(BaseModel):
    value: str | None = Field(default=None, min_length=1, max_length=512)
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
    descriptionText: str = Field(min_length=1, max_length=512)
    type: str = Field(min_length=1, max_length=64)


class FollowupResponse(BaseModel):
    id: str
    descriptionText: str
    type: str
    noteID: str
    createdAtUTC: datetime
    editedAtUTC: datetime
    completed: bool


class FollowupCompletionRequest(BaseModel):
    completed: bool


class SyncNoteRequest(BaseModel):
    value: str | None = Field(default=None, min_length=1, max_length=512)
    summary: str | None = None
    balanceDueAmount: float | None = None
    balanceDueCurrency: str | None = None
    categories: list[str] | None = None
    appointmentTiming: str | None = None
    followups: list[CreateFollowupRequest]


class SyncNoteResponse(BaseModel):
    note: NoteResponse
    followups: list[FollowupResponse]


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
