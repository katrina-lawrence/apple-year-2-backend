# FastAPI Auth API

API-only FastAPI project with:
- user registration (username + password, UUID user ID generated server-side)
- unique username enforcement
- password minimum length of 12
- JWT login authentication
- public status endpoint
- authenticated user endpoint

## Requirements

- Python 3.11+

## Install

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
```

## Run

```bash
uvicorn app.main:app --reload
```

## Run With Docker

Docker Compose is optional. Plain Docker works directly.

```bash
docker build -t fastapi-auth-api .
docker run --rm -p 8000:8000 \
  -e JWT_SECRET_KEY='replace-with-a-secure-random-secret' \
  fastapi-auth-api
```

To persist SQLite data across container restarts:

```bash
docker volume create fastapi_auth_data
docker run --rm -p 8000:8000 \
  -e JWT_SECRET_KEY='replace-with-a-secure-random-secret' \
  -e DATABASE_URL='sqlite:////app/data/app.db' \
  -v fastapi_auth_data:/app/data \
  fastapi-auth-api
```

### Run With Docker Compose (Optional)

Set `JWT_SECRET_KEY` in your shell or a `.env` file first, then run:

```bash
docker compose up --build
```

## Endpoints

- `GET /status` -> `{ "status": "ok" }`
- `POST /register` with JSON body `{ "username": "your-username", "password": "your-password" }`
- `POST /login` with JSON body `{ "username": "your-username", "password": "your-password" }` returns access and refresh tokens
- `POST /refresh` with JSON body `{ "refresh_token": "..." }` returns a new access token
- `GET /user` with bearer token in `Authorization` header
- `POST /change-password` with JSON body `{ "current_password": "...", "new_password": "..." }` and bearer token
- `POST /notes` with JSON body `{ "value": "..." }` (max 512 chars) and bearer token
- `GET /notes` list authenticated user's notes
- `GET /notes/{note_id}` fetch one of authenticated user's notes
- `PUT /notes/{note_id}` with JSON body `{ "value": "..." }` to modify note text
- `DELETE /notes/{note_id}` delete authenticated user's note (`204` on success)
- `POST /notes/{note_id}/followups` create follow-up for an owned note with `{ "appointment_at": "<ISO-8601 UTC>", "description": "...", "completed_at": null | "<ISO-8601 UTC>" }`
- `GET /followups` list all follow-ups for authenticated user
- `GET /notes/{note_id}/followups` list follow-ups for one owned note
- `PATCH /followups/{followup_id}/completion` with `{ "is_completed": true | false }` to set `completed_at` to now or null

Password validation during registration is implemented through an extensible `validate_password()` function (currently enforcing minimum length 12, designed for adding future checks like breached-password checks).

## Example Flow

```bash
# 1) Register
curl -s -X POST http://127.0.0.1:8000/register \
  -H 'content-type: application/json' \
  -d '{"username":"alice","password":"supersecret123"}'

# 2) Login
curl -s -X POST http://127.0.0.1:8000/login \
  -H 'content-type: application/json' \
  -d '{"username":"alice","password":"supersecret123"}'

# 3) Refresh access token
curl -s -X POST http://127.0.0.1:8000/refresh \
  -H 'content-type: application/json' \
  -d '{"refresh_token":"<refresh-token-from-login>"}'

# 4) Get user
curl -s http://127.0.0.1:8000/user \
  -H 'Authorization: Bearer <token-from-login>'
```

## Configuration

- `JWT_SECRET_KEY` (recommended: set explicitly; if omitted, a secure random key is generated at startup)
- `JWT_EXPIRE_MINUTES` (default: `60`)
- `JWT_REFRESH_EXPIRE_DAYS` (default: `30`)
- `DATABASE_URL` (default: `sqlite:///./app.db`)
