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

To load sample seed data in local/dev startup:

```bash
SEED_SAMPLE_DATA=true uvicorn app.main:app --reload
```

## Run With Docker

Docker Compose is optional. Plain Docker works directly.

You can also configure Docker runs from a local `.env` file:

```bash
cp .env.example .env
```

```bash
docker build -t fastapi-auth-api .
docker run --rm -p 8000:8000 \
  --env-file .env \
  fastapi-auth-api
```

To persist SQLite data across container restarts:

```bash
docker volume create fastapi_auth_data
docker run --rm -p 8000:8000 \
  --env-file .env \
  -v fastapi_auth_data:/app/data \
  fastapi-auth-api
```

### Run With Docker Compose (Optional)

Create a `.env` from the example, then run Compose:

```bash
cp .env.example .env
```

```bash
docker compose up --build
```

## Endpoints

### Unauthenticated Endpoints

- `GET /status` -> `{ "status": "ok" }`
- `POST /register` with JSON body `{ "username": "your-username", "password": "your-password" }`
- `POST /login` with JSON body `{ "username": "your-username", "password": "your-password" }` returns access and refresh tokens
- `POST /refresh` with JSON body `{ "refresh_token": "..." }` returns a new access token

### Authenticated Endpoints (Require `Authorization: Bearer <access_token>`)

- `GET /user`
- `GET /sync/user` returns `{ "notes": [...], "followups": [...], "serverTimeUTC": "..." }` for authenticated user
- `POST /sync/note/{note_id}` updates an owned note and fully replaces that note's follow-ups using `{ ...noteFieldsToPatch, "followups": [{ "descriptionText": "...", "type": "..." }, ...] }` (`"followups": []` deletes all follow-ups for the note)
- `POST /change-password` with JSON body `{ "current_password": "...", "new_password": "..." }`
- `POST /notes` with JSON body
  `{ "value": "...", "summary": "...?", "balanceDueAmount": 10.5?, "balanceDueCurrency": "USD"?, "categories": ["..."]?, "appointmentTiming": "...?" }`
- `POST /notes/process` with JSON body `{ "noteID": "..." }` analyzes one owned note using configured AI provider and returns:
  `{ "summary": "...", "categories": ["..."], "balance_due": { "amount": 10.5|null, "currency": "USD"|null }, "actions": [{ "type": "...", "description": "..." }], "appointment_timing": "..."|null }`
- `GET /notes` list authenticated user's notes
- `GET /notes/{note_id}` fetch one of authenticated user's notes
- `PUT /notes/{note_id}` with JSON body containing one or more writable note fields to patch that note (updates `editedAtUTC`)
- `DELETE /notes/{note_id}` delete authenticated user's note (`204` on success)
- `POST /notes/{note_id}/followups` create follow-up for an owned note with `{ "descriptionText": "...", "type": "..." }` (`completed` starts as `false`)
- `POST /followups` create follow-up for authenticated user with `{ "descriptionText": "...", "type": "...", "noteID": "note-id?" }` (`noteID` is optional; when provided, it must reference an owned note; `completed` starts as `false`)
- `GET /followups` list all follow-ups for authenticated user (includes both note-linked and orphan follow-ups)
- `GET /notes/{note_id}/followups` list follow-ups for one owned note
- `PATCH /followups/{followup_id}` with `{ "descriptionText": "...?", "type": "...?" }` to edit one or both attributes (at least one field required)
- `PATCH /followups/{followup_id}/completion` with `{ "completed": true | false }` to mark/unmark completion
- `DELETE /followups/{followup_id}` delete one owned follow-up

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
- `SEED_SAMPLE_DATA` (default: `false`; set to `true` in local/dev to insert sample rows at startup)
- `AI_ENDPOINT` (Anthropic-style messages endpoint, e.g. `https://api.anthropic.com/v1/messages`)
- `AI_MODEL` (provider model name)
- `AI_API_KEY` (API key used for note processing requests)
