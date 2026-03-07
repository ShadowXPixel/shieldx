import asyncpg
import os
import jwt
import time
import uuid
import re
import httpx
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext

# -----------------------------------
# Config
# -----------------------------------

DATABASE_URL = os.getenv("DATABASE_URL")
JWT_SECRET = os.getenv("JWT_SECRET")
UPSTASH_URL = os.getenv("UPSTASH_REDIS_REST_URL")
UPSTASH_TOKEN = os.getenv("UPSTASH_REDIS_REST_TOKEN")
RESEND_API_KEY = os.getenv("RESEND_API_KEY")
INTERNAL_API_KEY = os.getenv("INTERNAL_API_KEY")
CONTACT_EMAIL = "kjuhi1496@gmail.com"  # where contact emails are sent
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE = 60 * 15            # 15 minutes
REFRESH_TOKEN_EXPIRE = 60 * 60 * 24 * 7  # 7 days

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer_scheme = HTTPBearer()

def safe_uuid(val: str) -> uuid.UUID:
    try:
        return uuid.UUID(val)
    except ValueError:
        raise HTTPException(status_code=401, detail="invalid token format")

# -----------------------------------
# App
# -----------------------------------

app = FastAPI(
    title="Ageinx API",
    version="1.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://ageinx.vercel.app",
        "http://localhost:3000",
        "http://localhost:8000",
    ],
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------------
# DB Pool — Lazy (serverless safe)
# -----------------------------------

pool = None

async def get_pool():
    global pool
    if pool is None:
        pool = await asyncpg.create_pool(
            DATABASE_URL,
            min_size=1,
            max_size=3,
            statement_cache_size=0  # required for pgBouncer / Supabase transaction mode
        )
    return pool

# -----------------------------------
# HTTP Client — Global (connection pooling)
# -----------------------------------

http_client: httpx.AsyncClient | None = None

def get_http_client() -> httpx.AsyncClient:
    global http_client
    if http_client is None or http_client.is_closed:
        http_client = httpx.AsyncClient(timeout=3.0)
    return http_client

# -----------------------------------
# Rate Limiter — Upstash Redis
# -----------------------------------

def get_client_ip(request: Request) -> str:
    # Vercel trusted header — most reliable on Vercel
    vercel_ip = request.headers.get("x-vercel-forwarded-for")
    if vercel_ip:
        return vercel_ip.split(",")[-1].strip()
    # Take LAST IP in x-forwarded-for to prevent spoofing
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[-1].strip()
    # Fall back to x-real-ip
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    # Final fallback
    return request.client.host if request.client else "127.0.0.1"

async def rate_limit(key: str, limit: int, window: int):
    """
    key    — unique identifier e.g. "signup:1.2.3.4"
    limit  — max requests allowed
    window — time window in seconds
    Fail-open: if Redis is down, allow the request through
    """
    if not UPSTASH_URL or not UPSTASH_TOKEN:
        return  # skip if not configured

    redis_key = f"rl:{key}"
    headers = {"Authorization": f"Bearer {UPSTASH_TOKEN}"}

    try:
        client = get_http_client()
        # Increment counter
        r = await client.post(
            f"{UPSTASH_URL}/incr/{redis_key}",
            headers=headers
        )
        try:
            count = r.json().get("result", 1)
        except ValueError:
            count = 1  # Upstash returned non-JSON (502/504), fail-open

        # Set expiry only on first request
        if count == 1:
            await client.post(
                f"{UPSTASH_URL}/expire/{redis_key}/{window}",
                headers=headers
            )

        if count > limit:
            raise HTTPException(
                status_code=429,
                detail="Too many requests. Try again later."
            )
    except HTTPException:
        raise  # re-raise 429s
    except Exception:
        pass  # fail-open: Redis down → let request through

# -----------------------------------
# Middleware
# -----------------------------------

@app.middleware("http")
async def limit_body_size(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if request.method in ("POST", "PUT", "PATCH"):
        if content_length is None:
            return JSONResponse(status_code=411, content={"detail": "Content-Length required"})
        if not content_length.isdigit() or int(content_length) > 10000:
            return JSONResponse(status_code=413, content={"detail": "Payload too large"})
    return await call_next(request)

# -----------------------------------
# Models
# -----------------------------------

class DevSignup(BaseModel):
    email: EmailStr
    password: str
    slug: str
    callback_url: str

class DevLogin(BaseModel):
    email: EmailStr
    password: str

class ContactForm(BaseModel):
    name: str
    email: EmailStr
    plan: str = ""
    message: str

class ChangePassword(BaseModel):
    current_password: str
    new_password: str

# -----------------------------------
# Helpers
# -----------------------------------

def create_token(payload: dict, expires_in: int) -> str:
    data = payload.copy()
    data["exp"] = int(time.time()) + expires_in
    return jwt.encode(data, JWT_SECRET, algorithm=ALGORITHM)

def validate_slug(slug: str):
    if not re.match(r'^[a-z0-9\-]{3,30}$', slug):
        raise HTTPException(
            status_code=400,
            detail="slug must be 3-30 chars, lowercase letters, numbers, hyphens only"
        )

def validate_password(password: str):
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="password must be at least 8 characters")

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="invalid token type")
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="invalid token")

# -----------------------------------
# Risk Engine
# -----------------------------------

def run_signals(ip_str: str, user_agent: str | None):
    risk_score = 0
    signals = {
        "header_anomaly": False,
        "ip_private": False,
        "ua_suspicious": False
    }

    if not user_agent:
        signals["header_anomaly"] = True
        risk_score += 20

    if ip_str.startswith("192.") or ip_str.startswith("127.") or ip_str.startswith("10."):
        signals["ip_private"] = True
        risk_score += 10

    if user_agent:
        ua = user_agent.lower()
        if "curl" in ua or "python" in ua or "bot" in ua:
            signals["ua_suspicious"] = True
            risk_score += 15

    return risk_score, signals

def compute_decision(score: int):
    if score < 20:
        return "allow", "low"
    elif score < 50:
        return "challenge", "medium"
    else:
        return "block", "high"

# -----------------------------------
# Health
# -----------------------------------

@app.get("/health")
async def health():
    return {"status": "ok"}

# -----------------------------------
# /platform — Dev Signup & Login
# -----------------------------------

@app.post("/platform/dev/signup")
async def dev_signup(request: Request, data: DevSignup):
    # Rate limit: 5 signups per IP per hour
    ip = get_client_ip(request)
    await rate_limit(f"signup:{ip}", limit=5, window=3600)

    validate_slug(data.slug)
    validate_password(data.password)

    db_pool = await get_pool()
    async with db_pool.acquire() as conn:
        password_hash = pwd_context.hash(data.password)
        api_key = f"ax_live_{uuid.uuid4().hex}"

        try:
            await conn.execute(
                """
                INSERT INTO developers (email, password_hash, api_key, slug, callback_url, is_active)
                VALUES ($1, $2, $3, $4, $5, true)
                """,
                data.email,
                password_hash,
                api_key,
                data.slug,
                data.callback_url
            )
        except asyncpg.exceptions.UniqueViolationError as e:
            if "email" in str(e):
                raise HTTPException(status_code=400, detail="email already registered")
            raise HTTPException(status_code=400, detail="slug already taken")

    return {
        "message": "account created. save your api key — it won't be shown again.",
        "api_key": api_key,
        "login_url": f"https://ageinx.vercel.app/auth/{data.slug}",
        "active": True
    }


@app.post("/platform/dev/login")
async def dev_login(request: Request, data: DevLogin):
    # Rate limit: 10 login attempts per IP per 15 minutes
    ip = get_client_ip(request)
    await rate_limit(f"login:{ip}", limit=10, window=900)

    db_pool = await get_pool()
    async with db_pool.acquire() as conn:
        dev = await conn.fetchrow(
            "SELECT id, email, password_hash, is_active FROM developers WHERE email = $1",
            data.email
        )

    if not dev or not pwd_context.verify(data.password, dev["password_hash"]):
        raise HTTPException(status_code=401, detail="invalid credentials")

    if not dev["is_active"]:
        raise HTTPException(status_code=403, detail="account not yet activated")

    access_token = create_token(
        {"sub": str(dev["id"]), "type": "access"},
        ACCESS_TOKEN_EXPIRE
    )
    refresh_token = create_token(
        {"sub": str(dev["id"]), "type": "refresh"},
        REFRESH_TOKEN_EXPIRE
    )

    db_pool = await get_pool()
    async with db_pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO dev_sessions (developer_id, refresh_token, expires_at)
            VALUES ($1, $2, to_timestamp($3))
            """,
            dev["id"],
            refresh_token,
            int(time.time()) + REFRESH_TOKEN_EXPIRE
        )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE
    }

# -----------------------------------
# /platform/dev/me — Dashboard Data
# -----------------------------------

@app.get("/platform/dev/me")
async def dev_me(token: dict = Depends(verify_token)):
    dev_id = str(token["sub"])

    db_pool = await get_pool()
    async with db_pool.acquire() as conn:
        dev = await conn.fetchrow(
            """
            SELECT email, api_key, slug, callback_url, plan, is_active, created_at
            FROM developers WHERE id = $1
            """,
            safe_uuid(dev_id)
        )

        if not dev:
            raise HTTPException(status_code=404, detail="developer not found")

        user_count = await conn.fetchval(
            "SELECT COUNT(*) FROM users WHERE developer_id = $1",
            safe_uuid(dev_id)
        )

        sessions_this_month = await conn.fetchval(
            """
            SELECT COUNT(*) FROM dev_sessions
            WHERE developer_id = $1
            AND created_at >= date_trunc('month', now())
            """,
            safe_uuid(dev_id)
        )

    plan = dev["plan"] or "starter"
    plan_limits = {"starter": 1000, "pro": 50000, "business": 500000}
    limit = plan_limits.get(plan, 1000)

    return {
        "email": dev["email"],
        "api_key": dev["api_key"],
        "slug": dev["slug"],
        "callback_url": dev["callback_url"],
        "plan": plan,
        "is_active": dev["is_active"],
        "created_at": str(dev["created_at"]),
        "usage": {
            "users_registered": user_count or 0,
            "sessions_this_month": sessions_this_month or 0,
            "api_calls_limit": limit,
        }
    }

@app.post("/platform/dev/change-password")
async def change_password(data: ChangePassword, token: dict = Depends(verify_token)):
    dev_id = str(token["sub"])

    db_pool = await get_pool()
    async with db_pool.acquire() as conn:
        dev = await conn.fetchrow(
            "SELECT password_hash FROM developers WHERE id = $1",
            safe_uuid(dev_id)
        )

        if not dev or not pwd_context.verify(data.current_password, dev["password_hash"]):
            raise HTTPException(status_code=401, detail="current password is incorrect")

        validate_password(data.new_password)
        new_hash = pwd_context.hash(data.new_password)

        await conn.execute(
            "UPDATE developers SET password_hash = $1 WHERE id = $2",
            new_hash, safe_uuid(dev_id)
        )

    return {"message": "password updated successfully"}

@app.post("/platform/dev/logout")
async def logout(token: dict = Depends(verify_token)):
    dev_id = str(token["sub"])

    db_pool = await get_pool()
    async with db_pool.acquire() as conn:
        await conn.execute(
            "DELETE FROM dev_sessions WHERE developer_id = $1",
            safe_uuid(dev_id)
        )

    return {"message": "logged out successfully"}

# -----------------------------------
# /contact — Contact Form
# -----------------------------------

@app.post("/contact")
async def contact(request: Request, data: ContactForm):
    ip = get_client_ip(request)
    await rate_limit(f"contact:{ip}", limit=3, window=3600)  # 3 per hour

    if not data.name.strip() or not data.message.strip():
        raise HTTPException(status_code=400, detail="name and message are required")

    if len(data.message) > 2000:
        raise HTTPException(status_code=400, detail="message too long")

    if not RESEND_API_KEY:
        raise HTTPException(status_code=500, detail="email service not configured")

    plan_line = f"<p><strong>Plan interest:</strong> {data.plan}</p>" if data.plan else ""
    html_body = f"""
    <h2>New contact from Ageinx</h2>
    <p><strong>Name:</strong> {data.name}</p>
    <p><strong>Email:</strong> {data.email}</p>
    {plan_line}
    <p><strong>Message:</strong></p>
    <p style="white-space:pre-wrap">{data.message}</p>
    """

    client = get_http_client()
    try:
        r = await client.post(
            "https://api.resend.com/emails",
            headers={
                "Authorization": f"Bearer {RESEND_API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "from": "Ageinx Contact <onboarding@resend.dev>",
                "to": [CONTACT_EMAIL],
                "reply_to": data.email,
                "subject": f"[Ageinx] Message from {data.name}",
                "html": html_body
            }
        )
        if r.status_code not in (200, 201):
            raise HTTPException(status_code=500, detail="failed to send email")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="email service error")

    return {"message": "Message sent! We'll get back to you within one business day."}

# -----------------------------------
# /internal — Fraud Filter
# -----------------------------------

@app.post("/internal/check", include_in_schema=False)
async def internal_check(request: Request):
    key = request.headers.get("x-internal-key")
    if not INTERNAL_API_KEY or key != INTERNAL_API_KEY:
        raise HTTPException(status_code=403, detail="forbidden")
    start_time = time.time()
    request_id = f"ax_{uuid.uuid4().hex[:8]}"

    ip_str = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent")

    score, signals = run_signals(ip_str, user_agent)
    decision, level = compute_decision(score)

    return {
        "request_id": request_id,
        "decision": decision,
        "risk": {"score": score, "level": level},
        "signals": signals,
        "meta": {"processing_ms": round((time.time() - start_time) * 1000, 2)}
    }

# -----------------------------------
# /auth — AuthaaS Core Flow
# -----------------------------------

USER_ACCESS_EXPIRE = 60 * 60 * 24  # 24 hours for end users

class UserSignup(BaseModel):
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str


@app.get("/auth/userinfo")
async def auth_userinfo(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[ALGORITHM])
        if payload.get("type") != "user_access":
            raise HTTPException(status_code=401, detail="invalid token type")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="invalid token")
    return {
        "user_id": payload["sub"],
        "email": payload["email"],
        "developer_id": payload["dev"],
        "token_type": "user_access"
    }


@app.get("/auth/{slug}")
async def auth_page(slug: str):
    from fastapi.responses import HTMLResponse
    db_pool = await get_pool()
    async with db_pool.acquire() as conn:
        dev = await conn.fetchrow(
            "SELECT slug, callback_url FROM developers WHERE slug = $1 AND is_active = true", slug
        )
    if not dev:
        raise HTTPException(status_code=404, detail="app not found")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Sign in</title>
<link href="https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600&display=swap" rel="stylesheet"/>
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Geist',sans-serif;background:#f8f7f5;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}}
.card{{background:#fff;border:1px solid #e2e1de;border-radius:14px;padding:40px;width:100%;max-width:420px;box-shadow:0 16px 48px rgba(0,0,0,0.1)}}
.brand{{font-size:0.78rem;color:#9a9895;margin-bottom:20px;font-weight:500}}
.brand span{{color:#1b6ef2;font-weight:600}}
h1{{font-size:1.4rem;font-weight:600;color:#18170f;letter-spacing:-0.02em;margin-bottom:6px}}
.sub{{font-size:0.84rem;color:#6a6965;margin-bottom:28px}}
.tabs{{display:flex;gap:2px;background:#f3f3f1;border-radius:8px;padding:3px;margin-bottom:24px}}
.tab{{flex:1;padding:7px;border:none;background:none;font-family:'Geist',sans-serif;font-size:0.875rem;font-weight:500;color:#9a9895;border-radius:6px;cursor:pointer;transition:all 0.15s}}
.tab.active{{background:#fff;color:#18170f;box-shadow:0 1px 4px rgba(0,0,0,0.08)}}
.fg{{margin-bottom:14px}}
.fg label{{display:block;font-size:0.73rem;font-weight:600;color:#2b2a27;margin-bottom:5px}}
.fg input{{width:100%;background:#fff;border:1px solid #c6c5c1;color:#18170f;padding:9px 12px;border-radius:6px;font-family:'Geist',sans-serif;font-size:0.875rem;outline:none;transition:border-color 0.15s,box-shadow 0.15s}}
.fg input:focus{{border-color:#1b6ef2;box-shadow:0 0 0 3px rgba(27,110,242,0.1)}}
.fg input::placeholder{{color:#9a9895}}
.btn{{width:100%;background:#18170f;color:#fff;border:none;padding:10px;border-radius:7px;font-family:'Geist',sans-serif;font-size:0.9rem;font-weight:500;cursor:pointer;transition:background 0.15s;margin-top:4px}}
.btn:hover{{background:#2b2a27}}
.btn:disabled{{opacity:0.55;cursor:default}}
.msg{{display:none;padding:10px 13px;border-radius:7px;font-size:0.82rem;line-height:1.55;margin-top:14px}}
.msg-success{{background:#f0fdf4;color:#15803d;border:1px solid #bbf7d0}}
.msg-error{{background:#fff1f2;color:#be123c;border:1px solid #fecdd3}}
.powered{{text-align:center;font-size:0.72rem;color:#9a9895;margin-top:22px}}
.powered a{{color:#1b6ef2;text-decoration:none;font-weight:500}}
</style>
</head>
<body>
<div class="card">
  <div class="brand">Secured by <span>Ageinx</span></div>
  <h1>Welcome back</h1>
  <p class="sub">Sign in or create an account to continue</p>
  <div class="tabs">
    <button class="tab active" id="tab-login" onclick="switchTab('login')">Sign in</button>
    <button class="tab" id="tab-signup" onclick="switchTab('signup')">Create account</button>
  </div>
  <div id="form-login">
    <div class="fg"><label>Email</label><input type="email" id="li-email" placeholder="you@example.com"/></div>
    <div class="fg"><label>Password</label><input type="password" id="li-password" placeholder="Your password"/></div>
    <button class="btn" id="li-btn" onclick="handleLogin()">Sign in</button>
    <div class="msg" id="li-msg"></div>
  </div>
  <div id="form-signup" style="display:none">
    <div class="fg"><label>Email</label><input type="email" id="su-email" placeholder="you@example.com"/></div>
    <div class="fg"><label>Password</label><input type="password" id="su-password" placeholder="Min. 8 characters"/></div>
    <button class="btn" id="su-btn" onclick="handleSignup()">Create account</button>
    <div class="msg" id="su-msg"></div>
  </div>
  <div class="powered">Protected by <a href="https://ageinx.vercel.app" target="_blank">Ageinx</a></div>
</div>
<script>
const SLUG = "{slug}";
const API = window.location.origin;
function switchTab(tab) {{
  document.getElementById('tab-login').classList.toggle('active', tab==='login');
  document.getElementById('tab-signup').classList.toggle('active', tab==='signup');
  document.getElementById('form-login').style.display = tab==='login'?'block':'none';
  document.getElementById('form-signup').style.display = tab==='signup'?'block':'none';
}}
function showMsg(id, html, type) {{
  const el = document.getElementById(id);
  el.innerHTML = html; el.style.display = 'block';
  el.className = 'msg msg-' + type;
}}
async function handleLogin() {{
  const btn = document.getElementById('li-btn');
  const email = document.getElementById('li-email').value.trim();
  const password = document.getElementById('li-password').value;
  if (!email || !password) {{ showMsg('li-msg','All fields required.','error'); return; }}
  btn.disabled = true; btn.textContent = 'Signing in…';
  try {{
    const res = await fetch(`${{API}}/auth/${{SLUG}}/login`, {{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{email,password}})}});
    const data = await res.json();
    if (!res.ok) {{ showMsg('li-msg', data.detail||'Login failed.','error'); return; }}
    showMsg('li-msg','✅ Signed in! Redirecting…','success');
    setTimeout(()=>{{ window.location.href = data.redirect_url; }}, 800);
  }} catch(e) {{ showMsg('li-msg','Network error. Try again.','error'); }}
  finally {{ btn.disabled=false; btn.textContent='Sign in'; }}
}}
async function handleSignup() {{
  const btn = document.getElementById('su-btn');
  const email = document.getElementById('su-email').value.trim();
  const password = document.getElementById('su-password').value;
  if (!email || !password) {{ showMsg('su-msg','All fields required.','error'); return; }}
  btn.disabled = true; btn.textContent = 'Creating account…';
  try {{
    const res = await fetch(`${{API}}/auth/${{SLUG}}/signup`, {{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{email,password}})}});
    const data = await res.json();
    if (!res.ok) {{ showMsg('su-msg', data.detail||'Signup failed.','error'); return; }}
    showMsg('su-msg','✅ Account created! Redirecting…','success');
    setTimeout(()=>{{ window.location.href = data.redirect_url; }}, 800);
  }} catch(e) {{ showMsg('su-msg','Network error. Try again.','error'); }}
  finally {{ btn.disabled=false; btn.textContent='Create account'; }}
}}
</script>
</body>
</html>"""
    return HTMLResponse(content=html)


@app.post("/auth/{slug}/signup")
async def auth_user_signup(slug: str, request: Request, data: UserSignup):
    ip = get_client_ip(request)
    await rate_limit(f"auth_signup:{ip}", limit=10, window=3600)
    validate_password(data.password)
    db_pool = await get_pool()
    async with db_pool.acquire() as conn:
        dev = await conn.fetchrow(
            "SELECT id, callback_url FROM developers WHERE slug = $1 AND is_active = true", slug
        )
        if not dev:
            raise HTTPException(status_code=404, detail="app not found")
        password_hash = pwd_context.hash(data.password)
        try:
            user_id = await conn.fetchval(
                "INSERT INTO users (developer_id, email, password_hash) VALUES ($1, $2, $3) RETURNING id",
                dev["id"], data.email, password_hash
            )
        except asyncpg.exceptions.UniqueViolationError:
            raise HTTPException(status_code=400, detail="email already registered")
    token = create_token(
        {"sub": str(user_id), "dev": str(dev["id"]), "email": data.email, "type": "user_access"},
        60 * 60 * 24
    )
    return {"message": "account created", "redirect_url": f"{dev['callback_url']}#token={token}", "token": token}


@app.post("/auth/{slug}/login")
async def auth_user_login(slug: str, request: Request, data: UserLogin):
    ip = get_client_ip(request)
    await rate_limit(f"auth_login:{ip}", limit=10, window=900)
    db_pool = await get_pool()
    async with db_pool.acquire() as conn:
        dev = await conn.fetchrow(
            "SELECT id, callback_url FROM developers WHERE slug = $1 AND is_active = true", slug
        )
        if not dev:
            raise HTTPException(status_code=404, detail="app not found")
        user = await conn.fetchrow(
            "SELECT id, email, password_hash FROM users WHERE developer_id = $1 AND email = $2",
            dev["id"], data.email
        )
    if not user or not pwd_context.verify(data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="invalid credentials")
    token = create_token(
        {"sub": str(user["id"]), "dev": str(dev["id"]), "email": user["email"], "type": "user_access"},
        60 * 60 * 24
    )
    return {"message": "login successful", "redirect_url": f"{dev['callback_url']}#token={token}", "token": token}
