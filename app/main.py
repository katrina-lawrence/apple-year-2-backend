from __future__ import annotations

import os
import secrets
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import jwt
from fastapi import Depends, FastAPI, HTTPException, Response, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, Field
from pwdlib import PasswordHash
from sqlalchemy import DateTime, String, Text, create_engine, func
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

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
    created_at: Mapped[datetime] = mapped_column(
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


class StatusResponse(BaseModel):
    status: str


class NoteWriteRequest(BaseModel):
    value: str = Field(min_length=1, max_length=512)


class NoteResponse(BaseModel):
    id: str
    value: str
    created_at: datetime


connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)

app = FastAPI(title="FastAPI Auth API")
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


@app.post("/notes", response_model=NoteResponse, status_code=status.HTTP_201_CREATED)
def create_note(
    payload: NoteWriteRequest,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> NoteResponse:
    note = Note(id=str(uuid4()), owner_id=user_id, value=payload.value)
    db.add(note)
    db.commit()
    db.refresh(note)
    return NoteResponse(id=note.id, value=note.value, created_at=note.created_at)


@app.get("/notes", response_model=list[NoteResponse])
def list_notes(
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> list[NoteResponse]:
    notes = db.query(Note).filter(Note.owner_id == user_id).order_by(Note.created_at.desc()).all()
    return [NoteResponse(id=n.id, value=n.value, created_at=n.created_at) for n in notes]


@app.get("/notes/{note_id}", response_model=NoteResponse)
def get_note(
    note_id: str,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> NoteResponse:
    note = db.query(Note).filter(Note.id == note_id, Note.owner_id == user_id).first()
    if note is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found")
    return NoteResponse(id=note.id, value=note.value, created_at=note.created_at)


@app.put("/notes/{note_id}", response_model=NoteResponse)
def update_note(
    note_id: str,
    payload: NoteWriteRequest,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> NoteResponse:
    note = db.query(Note).filter(Note.id == note_id, Note.owner_id == user_id).first()
    if note is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found")
    note.value = payload.value
    db.add(note)
    db.commit()
    db.refresh(note)
    return NoteResponse(id=note.id, value=note.value, created_at=note.created_at)


@app.delete("/notes/{note_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_note(
    note_id: str,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> Response:
    note = db.query(Note).filter(Note.id == note_id, Note.owner_id == user_id).first()
    if note is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found")
    db.delete(note)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
