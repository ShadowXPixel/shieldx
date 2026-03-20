import asyncio
import asyncpg
import datetime
import os
import jwt
import time
import uuid
import re
import json
import base64
import httpx
import hashlib
import secrets

from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext

# -----------------------------------
# Config
# -----------------------------------

DATABASE_URL         = os.getenv("DATABASE_URL")
JWT_SECRET           = os.getenv("JWT_SECRET")
UPSTASH_URL          = os.getenv("UPSTASH_REDIS_REST_URL")
UPSTASH_TOKEN        = os.getenv("UPSTASH_REDIS_REST_TOKEN")
RESEND_API_KEY       = os.getenv("RESEND_API_KEY")
INTERNAL_API_KEY     = os.getenv("INTERNAL_API_KEY")

# OAuth Config
GOOGLE_CLIENT_ID     = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GITHUB_CLIENT_ID     = os.getenv("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")
APP_URL              = "https://ageinx.vercel.app" # Your production URL

CONTACT_EMAIL        = "kjuhi1496@gmail.com"
ALGORITHM            = "HS256"
ACCESS_TOKEN_EXPIRE  = 60 * 60 * 24  # 24 hours
REFRESH_TOKEN_EXPIRE = 60 * 60 * 24 * 7   # 7 days
USER_ACCESS_EXPIRE   = 60 * 60 * 24       # 24 hours

PLAN_LIMITS = {"starter": 1000, "pro": 50000, "business": 500000}
UPGRADE_MESSAGES = {
    "starter":  f"API limit reached (1,000 calls/month). To upgrade to Pro and restore access, contact {CONTACT_EMAIL}",
    "pro":      f"API limit reached (50,000 calls/month). To upgrade to Business and restore access, contact {CONTACT_EMAIL}",
    "business": f"API limit reached (500,000 calls/month). To discuss Enterprise pricing, contact {CONTACT_EMAIL}",
}

pwd_context   = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=10)
bearer_scheme = HTTPBearer()

# -----------------------------------
# App
# -----------------------------------

app = FastAPI(
    title="Ageinx API",
    version="0.1",
    docs_url=None,
    redoc_url=None,
    openapi_url=None
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------------
# DB Pool
# -----------------------------------

pool = None

async def get_pool():
    global pool
    if pool is None:
        pool = await asyncpg.create_pool(
            DATABASE_URL,
            min_size=1,
            max_size=3,
            command_timeout=60,
            statement_cache_size=0
        )
    return pool

# -----------------------------------
# HTTP Client
# -----------------------------------

http_client: httpx.AsyncClient | None = None

def get_http_client() -> httpx.AsyncClient:
    global http_client
    if http_client is None or http_client.is_closed:
        http_client = httpx.AsyncClient(timeout=5.0)
    return http_client

# -----------------------------------
# Helpers
# -----------------------------------

def safe_uuid(val: str) -> uuid.UUID:
    try:
        return uuid.UUID(val)
    except ValueError:
        raise HTTPException(status_code=401, detail="invalid token format")

def create_token(payload: dict, expires_in: int) -> str:
    data = payload.copy()
    data["exp"] = int(time.time()) + expires_in
    return jwt.encode(data, JWT_SECRET, algorithm=ALGORITHM)

def generate_verify_token():
    raw = secrets.token_urlsafe(32)
    hashed = hashlib.sha256(raw.encode()).hexdigest()
    return raw, hashed

def validate_slug(slug: str):
    if not re.match(r'^[a-z0-9\-]{3,30}$', slug):
        raise HTTPException(
            status_code=400,
            detail="slug must be 3-30 chars, lowercase letters, numbers, hyphens only"
        )

def validate_password(password: str):
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="password must be at least 8 characters")

def verify_token_payload(token_string: str, expected_type: str = None):
    try:
        payload = jwt.decode(token_string, JWT_SECRET, algorithms=[ALGORITHM])
        if expected_type and payload.get("type") != expected_type:
            raise HTTPException(status_code=401, detail="invalid token type")
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="invalid token")

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    return verify_token_payload(credentials.credentials, "access")

def get_client_ip(request: Request) -> str:
    vercel_ip = request.headers.get("x-vercel-forwarded-for")
    if vercel_ip: return vercel_ip.split(",")[-1].strip()
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded: return forwarded.split(",")[-1].strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip: return real_ip.strip()
    return request.client.host if request.client else "127.0.0.1"

# -----------------------------------
# Rate Limiter & Plans
# -----------------------------------

async def rate_limit(key: str, limit: int, window: int):
    if not UPSTASH_URL or not UPSTASH_TOKEN: return
    redis_key = f"rl:{key}"
    headers = {"Authorization": f"Bearer {UPSTASH_TOKEN}"}
    try:
        client = get_http_client()
        r = await client.post(f"{UPSTASH_URL}/incr/{redis_key}", headers=headers)
        try: count = r.json().get("result", 1)
        except ValueError: count = 1
        if count == 1:
            await client.post(f"{UPSTASH_URL}/expire/{redis_key}/{window}", headers=headers)
        if count > limit:
            raise HTTPException(status_code=429, detail="Too many requests. Try again later.")
    except HTTPException: raise
    except Exception: pass

async def enforce_plan_limit(conn, dev_id):
    dev = await conn.fetchrow("SELECT plan, api_calls_count, api_calls_reset_at FROM developers WHERE id = $1", dev_id)
    plan  = dev["plan"] or "starter"
    limit = PLAN_LIMITS.get(plan, 1000)
    now   = datetime.datetime.now(datetime.timezone.utc)
    reset_at = dev["api_calls_reset_at"]

    if reset_at is None or now >= reset_at + datetime.timedelta(days=30):
        await conn.execute("UPDATE developers SET api_calls_count = 1, api_calls_reset_at = $1 WHERE id = $2", now, dev_id)
        return

    new_count = (dev["api_calls_count"] or 0) + 1
    await conn.execute("UPDATE developers SET api_calls_count = $1 WHERE id = $2", new_count, dev_id)
    if new_count > limit:
        msg = UPGRADE_MESSAGES.get(plan, "API limit reached.")
        raise HTTPException(status_code=429, detail=msg)

# -----------------------------------
# Email
# -----------------------------------

async def send_verification_email(email: str, token: str):
    link = f"{APP_URL}/verify-email?token={token}"
    client = get_http_client()
    try:
        await client.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {RESEND_API_KEY}"},
            json={
                "from": "Ageinx <no-reply@ageinx.com>",
                "to": email,
                "subject": "Verify your email",
                "html": f"""
                <h2>Welcome to Ageinx 🚀</h2>
                <p>Click the link below to verify your email address:</p>
                <a href="{link}">Verify Email</a>
                <p>This link expires in 1 hour.</p>
                """
            }
        )
    except Exception as e:
        # Don't break the signup flow if email fails, but log it
        print(f"Resend Error: {e}")

# -----------------------------------
# Middleware
# -----------------------------------

@app.middleware("http")
async def limit_body_size(request: Request, call_next):
    if request.method in ("POST", "PUT", "PATCH"):
        content_length = request.headers.get("content-length")
        if content_length is None:
            return JSONResponse(status_code=411, content={"detail": "Content-Length required"})
        if not content_length.isdigit() or int(content_length) > 10000:
            return JSONResponse(status_code=413, content={"detail": "Payload too large"})
    return await call_next(request)

# -----------------------------------
# Models
# -----------------------------------

class DevSignup(BaseModel): email: EmailStr; password: str; slug: str; callback_url: str
class DevLogin(BaseModel): email: EmailStr; password: str
class ChangePassword(BaseModel): current_password: str; new_password: str
class ContactForm(BaseModel): name: str; email: EmailStr; plan: str = ""; message: str
class UserSignup(BaseModel): email: EmailStr; password: str
class UserLogin(BaseModel): email: EmailStr; password: str

# -----------------------------------
# OAuth Engine (Core)
# -----------------------------------

@app.get("/api/oauth/{provider}")
async def oauth_login(provider: str, type: str, slug: str = ""):
    state_data = json.dumps({"type": type, "slug": slug})
    state_b64 = base64.urlsafe_b64encode(state_data.encode()).decode()
    
    if provider == "google":
        url = f"https://accounts.google.com/o/oauth2/v2/auth?client_id={GOOGLE_CLIENT_ID}&response_type=code&redirect_uri={APP_URL}/api/oauth/callback/google&scope=email profile&state={state_b64}"
        return RedirectResponse(url=url)
    elif provider == "github":
        url = f"https://github.com/login/oauth/authorize?client_id={GITHUB_CLIENT_ID}&redirect_uri={APP_URL}/api/oauth/callback/github&scope=user:email&state={state_b64}"
        return RedirectResponse(url=url)
    
    raise HTTPException(status_code=400, detail="Provider not supported")

@app.get("/api/oauth/callback/{provider}")
async def oauth_callback(provider: str, code: str, state: str):
    try:
        state_data = json.loads(base64.urlsafe_b64decode(state.encode()).decode())
        login_type = state_data.get("type")
        slug = state_data.get("slug")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid state parameter")
        
    client = get_http_client()
    email = None
    
    if provider == "google":
        token_res = await client.post("https://oauth2.googleapis.com/token", data={
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": f"{APP_URL}/api/oauth/callback/google"
        })
        access_token = token_res.json().get("access_token")
        if not access_token: raise HTTPException(status_code=400, detail="Google auth failed")
        
        user_res = await client.get("https://www.googleapis.com/oauth2/v2/userinfo", headers={"Authorization": f"Bearer {access_token}"})
        email = user_res.json().get("email")

    elif provider == "github":
        token_res = await client.post("https://github.com/login/oauth/access_token", data={
            "client_id": GITHUB_CLIENT_ID,
            "client_secret": GITHUB_CLIENT_SECRET,
            "code": code,
            "redirect_uri": f"{APP_URL}/api/oauth/callback/github"
        }, headers={"Accept": "application/json"})
        access_token = token_res.json().get("access_token")
        if not access_token: raise HTTPException(status_code=400, detail="GitHub auth failed")
        
        user_res = await client.get("https://api.github.com/user/emails", headers={"Authorization": f"Bearer {access_token}"})
        emails = user_res.json()
        email = next((e["email"] for e in emails if e.get("primary") and e.get("verified")), None)
        if not email and emails: email = emails[0]["email"]

    if not email:
        raise HTTPException(status_code=400, detail="Failed to retrieve email from provider")

    db_pool = await get_pool()
    async with db_pool.acquire() as conn:
        dummy_hash = await run_in_threadpool(pwd_context.hash, secrets.token_hex(16))
        
        if login_type == "dev":
            dev = await conn.fetchrow("SELECT id FROM developers WHERE email = $1", email)
            if not dev:
                api_key = f"ax_live_{secrets.token_urlsafe(24)}"
                random_slug = f"app-{secrets.token_hex(4)}"
                dev_id = await conn.fetchval(
                    "INSERT INTO developers (email, password_hash, api_key, slug, callback_url, is_active) VALUES ($1, $2, $3, $4, $5, true) RETURNING id",
                    email, dummy_hash, api_key, random_slug, f"{APP_URL}/dashboard"
                )
            else:
                dev_id = dev["id"]
                
            access_token = create_token({"sub": str(dev_id), "type": "access"}, ACCESS_TOKEN_EXPIRE)
            refresh_token = create_token({"sub": str(dev_id), "type": "refresh"}, REFRESH_TOKEN_EXPIRE)
            
            await conn.execute("INSERT INTO dev_sessions (developer_id, refresh_token, expires_at) VALUES ($1, $2, to_timestamp($3))",
                dev_id, refresh_token, int(time.time()) + REFRESH_TOKEN_EXPIRE)
            
            return RedirectResponse(url=f"{APP_URL}/#token={access_token}")
            
        elif login_type == "user":
            dev = await conn.fetchrow("SELECT id, callback_url FROM developers WHERE slug = $1 AND is_active = true", slug)
            if not dev: raise HTTPException(status_code=404, detail="App not found")
                
            user = await conn.fetchrow("SELECT id FROM users WHERE developer_id = $1 AND email = $2", dev["id"], email)
            if not user:
                # OAuth providers verify emails, so we default to email_verified=TRUE
                user_id = await conn.fetchval(
                    "INSERT INTO users (developer_id, email, password_hash, email_verified) VALUES ($1, $2, $3, TRUE) RETURNING id",
                    dev["id"], email, dummy_hash
                )
            else:
                user_id = user["id"]
                
            await enforce_plan_limit(conn, dev["id"])
            
            token = create_token(
                {"sub": str(user_id), "dev": str(dev["id"]), "email": email, "type": "user_access"},
                USER_ACCESS_EXPIRE
            )
            return RedirectResponse(url=f"{dev['callback_url']}#token={token}")

# -----------------------------------
# General Routes
# -----------------------------------

@app.get("/health")
async def health_check():
    return {"status": "ok"}

@app.post("/refresh")
async def refresh_token(refresh_token: str):
    try:
        payload = verify_token_payload(refresh_token, expected_type="refresh")
        new_token = create_token({"sub": payload.get("sub"), "type": "access"}, ACCESS_TOKEN_EXPIRE) 
        return {"access_token": new_token, "token_type": "bearer", "expires_in": ACCESS_TOKEN_EXPIRE}
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

@app.get("/verify")
async def verify(token: str):
    try:
        payload = verify_token_payload(token)
        return {"status": "active", "user": payload.get("sub")}
    except Exception:
        raise HTTPException(status_code=401, detail="Expired or invalid")

# -----------------------------------
# Developer Platform Routes
# -----------------------------------

@app.post("/platform/dev/signup")
async def dev_signup(request: Request, data: DevSignup):
    ip = get_client_ip(request)
    await rate_limit(f"signup:{ip}", limit=5, window=3600)
    validate_slug(data.slug)
    validate_password(data.password)

    password_hash = await run_in_threadpool(pwd_context.hash, data.password)
    api_key = f"ax_live_{secrets.token_urlsafe(24)}"

    db_pool = await get_pool()
    async with db_pool.acquire() as conn:
        try:
            await conn.execute(
                "INSERT INTO developers (email, password_hash, api_key, slug, callback_url, is_active) VALUES ($1, $2, $3, $4, $5, true)",
                data.email, password_hash, api_key, data.slug, data.callback_url
            )
        except asyncpg.exceptions.UniqueViolationError as e:
            if "email" in str(e): raise HTTPException(status_code=400, detail="email already registered")
            raise HTTPException(status_code=400, detail="slug already taken")

    return {"message": "account created", "api_key": api_key, "auth_url": f"https://ageinx.vercel.app/auth/{data.slug}", "active": True}

@app.post("/platform/dev/login")
async def dev_login(request: Request, data: DevLogin):
    ip = get_client_ip(request)
    await rate_limit(f"login:{ip}", limit=10, window=900)

    db_pool = await get_pool()
    async with db_pool.acquire() as conn:
        dev = await conn.fetchrow("SELECT id, email, password_hash, is_active FROM developers WHERE email = $1", data.email)

    if not dev or not await run_in_threadpool(pwd_context.verify, data.password, dev["password_hash"]):
        raise HTTPException(status_code=401, detail="invalid credentials")
    if not dev["is_active"]:
        raise HTTPException(status_code=403, detail="account not yet activated")

    access_token  = create_token({"sub": str(dev["id"]), "type": "access"},  ACCESS_TOKEN_EXPIRE)
    refresh_token = create_token({"sub": str(dev["id"]), "type": "refresh"}, REFRESH_TOKEN_EXPIRE)

    db_pool = await get_pool()
    async with db_pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO dev_sessions (developer_id, refresh_token, expires_at) VALUES ($1, $2, to_timestamp($3))",
            dev["id"], refresh_token, int(time.time()) + REFRESH_TOKEN_EXPIRE
        )

    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer", "expires_in": ACCESS_TOKEN_EXPIRE}

@app.get("/platform/dev/me")
async def dev_me(token: dict = Depends(verify_token)):
    dev_id = str(token["sub"])
    db_pool = await get_pool()
    async with db_pool.acquire() as conn:
        dev = await conn.fetchrow("SELECT email, api_key, slug, callback_url, plan, is_active, created_at, api_calls_count FROM developers WHERE id = $1", safe_uuid(dev_id))
        if not dev: raise HTTPException(status_code=404, detail="developer not found")
        user_count = await conn.fetchval("SELECT COUNT(*) FROM users WHERE developer_id = $1", safe_uuid(dev_id))
        sessions_this_month = await conn.fetchval("SELECT COUNT(*) FROM dev_sessions WHERE developer_id = $1 AND created_at >= date_trunc('month', now())", safe_uuid(dev_id))

    plan = dev["plan"] or "starter"
    return {
        "email": dev["email"], "api_key": dev["api_key"], "slug": dev["slug"], "callback_url": dev["callback_url"],
        "plan": plan, "is_active": dev["is_active"], "created_at": str(dev["created_at"]),
        "usage": { "users_registered": user_count or 0, "sessions_this_month": sessions_this_month or 0, "api_calls_count": dev["api_calls_count"] or 0, "api_calls_limit": PLAN_LIMITS.get(plan, 1000) }
    }

@app.post("/platform/dev/logout")
async def logout(token: dict = Depends(verify_token)):
    dev_id = str(token["sub"])
    db_pool = await get_pool()
    async with db_pool.acquire() as conn:
        await conn.execute("DELETE FROM dev_sessions WHERE developer_id = $1", safe_uuid(dev_id))
    return {"message": "logged out successfully"}

# -----------------------------------
# End-User Hosted Auth
# -----------------------------------

@app.get("/auth/userinfo")
async def auth_userinfo(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    payload = verify_token_payload(credentials.credentials, expected_type="user_access")
    return {"user_id": payload["sub"], "email": payload.get("email"), "developer_id": payload.get("dev"), "token_type": "user_access"}

@app.get("/auth/{slug}")
async def auth_page(slug: str):
    db_pool = await get_pool()
    async with db_pool.acquire() as conn:
        dev = await conn.fetchrow("SELECT slug FROM developers WHERE slug = $1 AND is_active = true", slug)
    if not dev: raise HTTPException(status_code=404, detail="app not found")

    # Replaced script tag below to handle the new "requires_verification" response
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
.tabs{{display:flex;gap:2px;background:#f3f3f1;border-radius:8px;padding:3px;margin-bottom:20px}}
.tab{{flex:1;padding:7px;border:none;background:none;font-family:'Geist',sans-serif;font-size:0.875rem;font-weight:500;color:#9a9895;border-radius:6px;cursor:pointer;transition:all 0.15s}}
.tab.active{{background:#fff;color:#18170f;box-shadow:0 1px 4px rgba(0,0,0,0.08)}}
.oauth-btn {{ display:flex; align-items:center; justify-content:center; gap:8px; width:100%; background:#fff; border:1px solid #c6c5c1; color:#18170f; padding:9px; border-radius:6px; font-family:'Geist',sans-serif; font-size:0.875rem; font-weight:500; cursor:pointer; transition:all 0.15s; margin-bottom:10px; }}
.oauth-btn:hover {{ background:#f8f7f5; border-color:#18170f; }}
.fg{{margin-bottom:14px}}
.fg label{{display:block;font-size:0.73rem;font-weight:600;color:#2b2a27;margin-bottom:5px}}
.fg input{{width:100%;background:#fff;border:1px solid #c6c5c1;color:#18170f;padding:9px 12px;border-radius:6px;font-family:'Geist',sans-serif;font-size:0.875rem;outline:none;transition:border-color 0.15s,box-shadow 0.15s}}
.fg input:focus{{border-color:#1b6ef2;box-shadow:0 0 0 3px rgba(27,110,242,0.1)}}
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
  
  <div style="display:flex; gap:10px; margin-bottom: 20px;">
    <button class="oauth-btn" style="flex:1" onclick="window.location.href='/api/oauth/google?type=user&slug={slug}'">
      <svg width="16" height="16" viewBox="0 0 24 24"><path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/><path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/><path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l3.66-2.84z" fill="#FBBC05"/><path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/></svg>
      Google
    </button>
    <button class="oauth-btn" style="flex:1" onclick="window.location.href='/api/oauth/github?type=user&slug={slug}'">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
      GitHub
    </button>
  </div>
  <div style="text-align:center;color:#9a9895;font-size:0.75rem;margin-bottom:20px;">— OR EMAIL —</div>

  <div id="form-login">
    <div class="fg"><label>Email</label><input type="email" id="li-email" placeholder="you@example.com"/></div>
    <div class="fg"><label>Password</label><input type="password" id="li-password" placeholder="Your password"/></div>
    <button class="btn" id="li-btn" onclick="handleLogin()">Sign in</button>
    <button class="btn" id="li-resend-btn" style="display:none; background:#f3f3f1; color:#18170f; margin-top:8px;" onclick="handleResend()">Resend Verification Email</button>
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
const API  = window.location.origin;
function switchTab(tab) {{
  document.getElementById('tab-login').classList.toggle('active', tab==='login');
  document.getElementById('tab-signup').classList.toggle('active', tab==='signup');
  document.getElementById('form-login').style.display  = tab==='login'  ? 'block' : 'none';
  document.getElementById('form-signup').style.display = tab==='signup' ? 'block' : 'none';
  document.getElementById('li-resend-btn').style.display = 'none'; // reset resend button
}}
function showMsg(id, html, type) {{
  const el = document.getElementById(id);
  el.innerHTML = html; el.style.display = 'block';
  el.className = 'msg msg-' + type;
}}
async function handleLogin() {{
  const btn = document.getElementById('li-btn');
  const resendBtn = document.getElementById('li-resend-btn');
  const email    = document.getElementById('li-email').value.trim();
  const password = document.getElementById('li-password').value;
  if (!email || !password) {{ showMsg('li-msg','All fields required.','error'); return; }}
  
  btn.disabled = true; btn.textContent = 'Signing in\u2026';
  resendBtn.style.display = 'none';
  
  try {{
    const res  = await fetch(`${{API}}/auth/${{SLUG}}/login`, {{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{email,password}})}});
    const data = await res.json();
    if (!res.ok) {{ 
      showMsg('li-msg', data.detail || 'Login failed.', 'error'); 
      if (data.detail && data.detail.includes("verify your email")) {{
         resendBtn.style.display = 'block'; // Show resend button if unverified
      }}
      return; 
    }}
    showMsg('li-msg', '\u2705 Signed in! Redirecting\u2026', 'success');
    setTimeout(() => {{ window.location.href = data.redirect_url; }}, 800);
  }} catch(e) {{ showMsg('li-msg', 'Network error. Try again.', 'error'); }}
  finally {{ btn.disabled = false; btn.textContent = 'Sign in'; }}
}}

async function handleSignup() {{
  const btn = document.getElementById('su-btn');
  const email    = document.getElementById('su-email').value.trim();
  const password = document.getElementById('su-password').value;
  if (!email || !password) {{ showMsg('su-msg','All fields required.','error'); return; }}
  btn.disabled = true; btn.textContent = 'Creating account\u2026';
  try {{
    const res  = await fetch(`${{API}}/auth/${{SLUG}}/signup`, {{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{email,password}})}});
    const data = await res.json();
    if (!res.ok) {{ showMsg('su-msg', data.detail || 'Signup failed.', 'error'); return; }}
    
    if (data.requires_verification) {{
      showMsg('su-msg', '\u2709\ufe0f Check your email for a verification link.', 'success');
      document.getElementById('su-email').value = '';
      document.getElementById('su-password').value = '';
    }} else {{
      showMsg('su-msg', '\u2705 Account created! Redirecting\u2026', 'success');
      setTimeout(() => {{ window.location.href = data.redirect_url; }}, 800);
    }}
  }} catch(e) {{ showMsg('su-msg', 'Network error. Try again.', 'error'); }}
  finally {{ btn.disabled = false; btn.textContent = 'Create account'; }}
}}

async function handleResend() {{
  const email = document.getElementById('li-email').value.trim();
  const resendBtn = document.getElementById('li-resend-btn');
  if (!email) return;
  
  resendBtn.disabled = true;
  resendBtn.textContent = 'Sending...';
  
  try {{
    const res = await fetch(`${{API}}/auth/resend-verification?email=${{encodeURIComponent(email)}}`, {{method: 'POST'}});
    if (res.ok) {{
      showMsg('li-msg', '\u2709\ufe0f Verification email resent.', 'success');
    }} else {{
      const data = await res.json();
      showMsg('li-msg', data.detail || 'Failed to resend.', 'error');
    }}
  }} catch(e) {{
    showMsg('li-msg', 'Network error. Try again.', 'error');
  }} finally {{
    resendBtn.disabled = false;
    resendBtn.textContent = 'Resend Verification Email';
  }}
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
        dev = await conn.fetchrow("SELECT id, callback_url FROM developers WHERE slug = $1 AND is_active = true", slug)
        if not dev: raise HTTPException(status_code=404, detail="app not found")

        password_hash = await run_in_threadpool(pwd_context.hash, data.password)
        raw_token, hashed_token = generate_verify_token()

        try:
            user_id = await conn.fetchval(
                """
                INSERT INTO users (developer_id, email, password_hash, email_verified, verify_token_hash, verify_expires) 
                VALUES ($1, $2, $3, FALSE, $4, NOW() + interval '1 hour') RETURNING id
                """,
                dev["id"], data.email, password_hash, hashed_token
            )
        except asyncpg.exceptions.UniqueViolationError:
            raise HTTPException(status_code=400, detail="email already registered")

        await enforce_plan_limit(conn, dev["id"])

    # Fire and forget email
    asyncio.create_task(send_verification_email(data.email, raw_token))

    return {"message": "Account created. Please verify your email.", "requires_verification": True}


@app.post("/auth/{slug}/login")
async def auth_user_login(slug: str, request: Request, data: UserLogin):
    ip = get_client_ip(request)
    await rate_limit(f"auth_login:{ip}", limit=10, window=900)

    db_pool = await get_pool()
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT d.id AS dev_id, d.callback_url, d.plan, d.api_calls_count, d.api_calls_reset_at,
                   u.id AS user_id, u.email, u.password_hash, u.email_verified
            FROM developers d
            LEFT JOIN users u ON u.developer_id = d.id AND u.email = $2
            WHERE d.slug = $1 AND d.is_active = true
            """,
            slug, data.email
        )
        if not row: raise HTTPException(status_code=404, detail="app not found")

        if not row["user_id"] or not await run_in_threadpool(pwd_context.verify, data.password, row["password_hash"]):
            raise HTTPException(status_code=401, detail="invalid credentials")

        if not row["email_verified"]:
            raise HTTPException(status_code=403, detail="Please verify your email to log in.")

        await enforce_plan_limit(conn, row["dev_id"])

    token = create_token(
        {"sub": str(row["user_id"]), "dev": str(row["dev_id"]), "email": row["email"], "type": "user_access"},
        USER_ACCESS_EXPIRE
    )
    return {"message": "login successful", "redirect_url": f"{row['callback_url']}#token={token}", "token": token}

# -----------------------------------
# Email Verification Endpoints
# -----------------------------------

@app.get("/verify-email")
async def verify_email_link(token: str):
    hashed = hashlib.sha256(token.encode()).hexdigest()

    db = await get_pool()
    async with db.acquire() as conn:
        user = await conn.fetchrow("""
            SELECT id FROM users
            WHERE verify_token_hash=$1 AND verify_expires>NOW()
        """, hashed)

        if not user:
            return HTMLResponse("""
                <div style="font-family:sans-serif; text-align:center; padding: 50px;">
                    <h2 style="color: #be123c;">Invalid or Expired Link ❌</h2>
                    <p>Please request a new verification email from the login page.</p>
                </div>
            """)

        await conn.execute("""
            UPDATE users
            SET email_verified=TRUE,
                verify_token_hash=NULL,
                verify_expires=NULL
            WHERE id=$1
        """, user["id"])

    return HTMLResponse("""
        <div style="font-family:sans-serif; text-align:center; padding: 50px;">
            <h2 style="color: #15803d;">Email Verified ✅</h2>
            <p>You can now safely close this tab and log in.</p>
        </div>
    """)

@app.post("/auth/resend-verification")
async def resend_verification(request: Request, email: EmailStr):
    # Fixed Vulnerability: Add Rate Limiting here!
    ip = get_client_ip(request)
    await rate_limit(f"resend_email:{ip}", limit=3, window=3600)

    db = await get_pool()
    raw_token, hashed_token = generate_verify_token()

    async with db.acquire() as conn:
        user = await conn.fetchrow("SELECT id, email_verified FROM users WHERE email=$1", email)
        if not user:
            raise HTTPException(status_code=404, detail="user not found")
        
        if user["email_verified"]:
            raise HTTPException(status_code=400, detail="Email is already verified")

        await conn.execute("""
            UPDATE users
            SET verify_token_hash=$1,
                verify_expires=NOW()+interval '1 hour'
            WHERE id=$2
        """, hashed_token, user["id"])

    asyncio.create_task(send_verification_email(email, raw_token))

    return {"message": "Verification email resent"}

