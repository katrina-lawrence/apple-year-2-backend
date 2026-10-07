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

## Endpoints

- `GET /status` -> `{ "status": "ok" }`
- `POST /register` with JSON body `{ "username": "your-username", "password": "your-password" }`
- `POST /login` with JSON body `{ "username": "your-username", "password": "your-password" }` returns access and refresh tokens
- `POST /refresh` with JSON body `{ "refresh_token": "..." }` returns a new access token
- `GET /user` with bearer token in `Authorization` header
- `POST /change-password` with JSON body `{ "current_password": "...", "new_password": "..." }` and bearer token

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
