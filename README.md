# Secure Login System

A secure login web app built with Flask + SQLite.

## Features
- Registration and login with **bcrypt**-hashed passwords
- Input validation + **parameterized SQL queries** (SQL injection protection)
- Session management (HttpOnly cookies, 30-min expiry, session reset on login) and **logout**
- **Optional 2FA** (TOTP: Google Authenticator, Authy, Microsoft Authenticator)
- Extras: CSRF tokens, account lockout (5 failed attempts = 5 min), security headers

## Run it
```bash
cd secure-login
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000

## Try it
1. Click **Register** and create an account (password: 8+ chars, upper/lower, number, symbol).
2. **Log in** and you land on the dashboard.
3. Click **Enable 2FA**, add the setup key in your authenticator app, enter the 6-digit code.
4. Log out and log in again: you will be asked for a code.
5. Run the tests: `python test_app.py`

## Project structure
```
app.py            routes, hashing, validation, sessions, 2FA
templates/        HTML pages
static/style.css  styling
test_app.py       automated security tests
requirements.txt  dependencies
```

## Deploying
- Serve over HTTPS and set `COOKIE_SECURE=1`.
- Set a fixed `SECRET_KEY` environment variable.
- Use a production server (e.g. `gunicorn app:app`), not the Flask dev server.

## Security notes (for your submission write-up)
| Requirement | Where |
|---|---|
| Hashed passwords | `hash_password()` uses bcrypt (12 rounds) |
| SQL injection protection | every query uses `?` placeholders; usernames validated by regex |
| Session management | `start_session()`, `logout()`, `login_required` |
| 2FA | `/2fa/setup`, `/2fa/verify` (RFC 6238 TOTP) |
