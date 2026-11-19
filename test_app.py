"""Run with:  python test_app.py"""
import os
import re
import tempfile

os.environ["DB_PATH"] = os.path.join(tempfile.mkdtemp(), "test.db")
import app as A  # noqa: E402

client = A.app.test_client()
PW = "Str0ng!Pass"


def token(path):
    html = client.get(path).get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def post(path, data, follow=False):
    data = dict(data, csrf_token=token(path if path != "/logout" else "/dashboard"))
    return client.post(path, data=data, follow_redirects=follow)


def check(name, cond):
    print(("PASS" if cond else "FAIL"), "-", name)
    assert cond, name


# registration
r = post("/register", {"username": "alice", "email": "a@x.com", "password": "weak", "confirm": "weak"})
check("weak password rejected", r.status_code == 400)
r = post("/register", {"username": "alice", "email": "a@x.com", "password": PW, "confirm": PW})
check("registration succeeds (redirect)", r.status_code == 302)
r = post("/register", {"username": "alice", "email": "b@x.com", "password": PW, "confirm": PW})
check("duplicate username rejected", r.status_code == 400)

# password is hashed
row = A.sqlite3.connect(A.DB_PATH).execute("SELECT password_hash FROM users").fetchone()[0]
check("password stored hashed, not plaintext", PW not in row and len(row) > 30)
print("   hash scheme:", row[:7], "(bcrypt)" if A.HAS_BCRYPT else "(scrypt fallback)")

# CSRF
r = client.post("/login", data={"username": "alice", "password": PW})
check("POST without CSRF token blocked", r.status_code == 400)

# SQL injection
r = post("/login", {"username": "' OR '1'='1' --", "password": "x"})
check("SQL injection in username fails", r.status_code == 401)
r = post("/login", {"username": "alice", "password": "' OR '1'='1"})
check("SQL injection in password fails", r.status_code == 401)
r = post("/register", {"username": "bob'; DROP TABLE users;--", "email": "b@x.com", "password": PW, "confirm": PW})
check("malicious username rejected by validation", r.status_code == 400)
check("users table still exists", A.sqlite3.connect(A.DB_PATH).execute("SELECT COUNT(*) FROM users").fetchone()[0] == 1)

# protected page + login/logout
check("dashboard needs login", client.get("/dashboard").status_code == 302)
r = post("/login", {"username": "alice", "password": PW})
check("valid login redirects", r.status_code == 302)
check("dashboard accessible after login", client.get("/dashboard").status_code == 200)
post("/logout", {})
check("dashboard blocked after logout", client.get("/dashboard").status_code == 302)

# 2FA
post("/login", {"username": "alice", "password": PW})
client.get("/2fa/setup")
with client.session_transaction() as s:
    secret = s["setup_secret"]
r = post("/2fa/setup", {"code": "000000"})
check("wrong 2FA setup code rejected", A.sqlite3.connect(A.DB_PATH).execute("SELECT totp_secret FROM users").fetchone()[0] is None)
r = post("/2fa/setup", {"code": A.totp_code(secret)})
check("2FA enabled with valid code", A.sqlite3.connect(A.DB_PATH).execute("SELECT totp_secret FROM users").fetchone()[0] == secret)
post("/logout", {})
r = post("/login", {"username": "alice", "password": PW})
check("login now redirects to 2FA step", r.status_code == 302 and "/2fa/verify" in r.location)
check("dashboard blocked before 2FA", client.get("/dashboard").status_code == 302)
r = post("/2fa/verify", {"code": "123456"})
check("wrong 2FA code rejected", r.status_code == 401)
r = post("/2fa/verify", {"code": A.totp_code(secret)})
check("correct 2FA code logs in", r.status_code == 302 and client.get("/dashboard").status_code == 200)
# RFC 6238 test vector (secret "12345678901234567890", T=59 -> 94287082 -> last 6 = 287082)
import base64  # noqa: E402
check("TOTP matches RFC 6238 vector",
      A.totp_code(base64.b32encode(b"12345678901234567890").decode(), 59) == "287082")

# lockout
post("/logout", {})
A.get_db  # noqa
db = A.sqlite3.connect(A.DB_PATH)
db.execute("UPDATE users SET totp_secret=NULL"); db.commit(); db.close()
for _ in range(5):
    post("/login", {"username": "alice", "password": "wrong"})
r = post("/login", {"username": "alice", "password": PW})
check("account locked after 5 failures (even with right password)", r.status_code == 429)
print("\nAll tests passed.")
