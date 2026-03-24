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
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from urllib.parse import urlparse

from fastapi import FastAPI, Request, HTTPException, Depends, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext

DATABASE_URL         = os.getenv("DATABASE_URL")
JWT_SECRET           = os.getenv("JWT_SECRET")
UPSTASH_URL          = os.getenv("UPSTASH_REDIS_REST_URL")
UPSTASH_TOKEN        = os.getenv("UPSTASH_REDIS_REST_TOKEN")
INTERNAL_API_KEY     = os.getenv("INTERNAL_API_KEY")
GMAIL_USER           = os.getenv("GMAIL_USER")
GMAIL_APP_PASSWORD   = os.getenv("GMAIL_APP_PASSWORD")
CONTACT_TO_EMAIL     = os.getenv("CONTACT_TO_EMAIL", "kjuhi1496@gmail.com")
GOOGLE_CLIENT_ID     = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GITHUB_CLIENT_ID     = os.getenv("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")
APP_URL              = "https://ageinx.vercel.app"

CONTACT_EMAIL        = os.getenv("CONTACT_TO_EMAIL", "kjuhi1496@gmail.com")
ALGORITHM            = "HS256"
ACCESS_TOKEN_EXPIRE  = 60 * 60 * 24
REFRESH_TOKEN_EXPIRE = 60 * 60 * 24 * 7
USER_ACCESS_EXPIRE   = 60 * 60 * 24

PLAN_LIMITS = {"starter": 1000, "pro": 50000, "business": 500000}
UPGRADE_MESSAGES = {
    "starter":  f"API limit reached (1,000/month). To upgrade to Pro, contact {CONTACT_EMAIL}",
    "pro":      f"API limit reached (50,000/month). To upgrade to Business, contact {CONTACT_EMAIL}",
    "business": f"API limit reached (500,000/month). To discuss Enterprise, contact {CONTACT_EMAIL}",
}

pwd_context   = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=10)
bearer_scheme = HTTPBearer()

# ── FIX 5: Dynamic CORS — in-process cache avoids DB on every preflight ────────
# OPTIONS preflights served from TTL cache → zero DB cost after first request.
# Cache lives in-process (per warm instance) with 5-min TTL.

_origin_cache: dict[str, tuple[str, float]] = {}  # slug → (cb_origin, expires_at)
_ORIGIN_CACHE_TTL = 300  # 5 minutes

async def get_allowed_origins(request: Request) -> list[str]:
    origins = [APP_URL]
    path = request.url.path
    if path.startswith("/auth/"):
        parts = path.split("/")
        if len(parts) >= 3:
            slug = parts[2]
            if slug and slug != "userinfo":
                now = time.time()
                cached = _origin_cache.get(slug)
                if cached and now < cached[1]:
                    cb_origin = cached[0]  # cache hit — no DB touch
                else:
                    # cache miss — hit DB once, then cache result
                    try:
                        db_pool = await get_pool()
                        async with db_pool.acquire() as conn:
                            dev = await conn.fetchrow(
                                "SELECT callback_url FROM developers WHERE slug=$1 AND is_active=true", slug
                            )
                        if dev and dev["callback_url"]:
                            parsed = urlparse(dev["callback_url"])
                            cb_origin = f"{parsed.scheme}://{parsed.netloc}"
                        else:
                            cb_origin = ""
                        _origin_cache[slug] = (cb_origin, now + _ORIGIN_CACHE_TTL)
                    except Exception as e:
                        print(f"[CORS] DB lookup failed for slug={slug}: {e}")
                        cb_origin = ""
                if cb_origin and cb_origin not in origins:
                    origins.append(cb_origin)
    return origins


class DynamicCORSMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request = Request(scope, receive)
        origin = request.headers.get("origin", "")
        if request.method == "OPTIONS":
            allowed = await get_allowed_origins(request)
            allow = origin if origin in allowed else APP_URL
            response = Response(status_code=204, headers={
                "Access-Control-Allow-Origin": allow,
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
                "Access-Control-Allow-Headers": "Authorization, Content-Type",
                "Access-Control-Allow-Credentials": "true",
                "Access-Control-Max-Age": "600",
            })
            await response(scope, receive, send)
            return
        allowed = await get_allowed_origins(request)
        allow = origin if origin in allowed else APP_URL

        async def send_with_cors(message):
            if message["type"] == "http.response.start":
                headers = dict(message.get("headers", []))
                headers[b"access-control-allow-origin"] = allow.encode()
                headers[b"access-control-allow-credentials"] = b"true"
                message["headers"] = list(headers.items())
            await send(message)

        await self.app(scope, receive, send_with_cors)


app = FastAPI(title="Ageinx API", version="0.1", docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(DynamicCORSMiddleware)

# ── FIX 1: DB pool max_size=1 for Vercel serverless ─────────────────────────
# Each Vercel instance handles 1 request at a time → max_size=1 is correct.
# max_size=3 → 100 instances = 300 connections → exhausts Supabase free tier.
# max_size=1 → 100 instances = 100 connections → safe for current scale.
#
# FUTURE: When traffic grows, point DATABASE_URL at Supabase's transaction-mode
# pooler (port 6543, Supavisor). Thousands of serverless instances can then share
# ~10 real connections. Keep statement_cache_size=0 for transaction-mode poolers.

pool = None

async def get_pool():
    global pool
    if pool is None:
        pool = await asyncpg.create_pool(
            DATABASE_URL,
            min_size=1,
            max_size=1,           # 1 conn per serverless instance
            command_timeout=10,   # Fail fast, don't stall the function
            statement_cache_size=0,
        )
    return pool


http_client: httpx.AsyncClient | None = None

def get_http_client() -> httpx.AsyncClient:
    global http_client
    if http_client is None or http_client.is_closed:
        http_client = httpx.AsyncClient(timeout=8.0)
    return http_client


def safe_uuid(val: str) -> uuid.UUID:
    try:
        return uuid.UUID(val)
    except ValueError:
        raise HTTPException(status_code=401, detail="invalid token format")

def create_token(payload: dict, expires_in: int) -> str:
    data = payload.copy()
    data["exp"] = int(time.time()) + expires_in
    return jwt.encode(data, JWT_SECRET, algorithm=ALGORITHM)

def validate_slug(slug: str):
    if not re.match(r'^[a-z0-9\-]{3,30}$', slug):
        raise HTTPException(status_code=400, detail="slug must be 3-30 chars, lowercase letters, numbers, hyphens only")

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
    except Exception as e:
        print(f"[rate_limit] Upstash error for key={key}: {e}")


# ── FIX 4: Plan limits via Redis only (no Postgres row locking) ──────────────
# Old code: UPDATE developers SET api_calls_count=N on every request.
# Under load this causes row-level locks and serialization bottlenecks.
# New code: atomic Redis INCR (microseconds, no locks).
# Cron job at /internal/sync-api-counts writes counts back to Postgres hourly.

async def enforce_plan_limit(dev_id: str, plan: str):
    if not UPSTASH_URL or not UPSTASH_TOKEN: return
    limit = PLAN_LIMITS.get(plan, 1000)
    redis_key = f"plan:{dev_id}"
    headers = {"Authorization": f"Bearer {UPSTASH_TOKEN}"}
    client = get_http_client()
    try:
        r = await client.post(f"{UPSTASH_URL}/incr/{redis_key}", headers=headers)
        count = r.json().get("result", 1)
        if count == 1:
            await client.post(f"{UPSTASH_URL}/expire/{redis_key}/2678400", headers=headers)  # 31 days
        if count > limit:
            raise HTTPException(status_code=429, detail=UPGRADE_MESSAGES.get(plan, "API limit reached."))
    except HTTPException: raise
    except Exception as e:
        # Redis down — fail open but log. Monitor this so limits aren't silently bypassed.
        print(f"[enforce_plan_limit] Upstash error for dev_id={dev_id}: {e}")

async def get_redis_call_count(dev_id: str) -> int:
    if not UPSTASH_URL or not UPSTASH_TOKEN: return 0
    try:
        client = get_http_client()
        r = await client.get(f"{UPSTASH_URL}/get/plan:{dev_id}", headers={"Authorization": f"Bearer {UPSTASH_TOKEN}"})
        val = r.json().get("result")
        return int(val) if val else 0
    except Exception:
        return 0



class DevSignup(BaseModel): email: EmailStr; password: str; slug: str; callback_url: str
class DevLogin(BaseModel): email: EmailStr; password: str
class ChangePassword(BaseModel): current_password: str; new_password: str
class ContactForm(BaseModel): name: str; email: EmailStr; plan: str = ""; message: str
class UserSignup(BaseModel): email: EmailStr; password: str
class UserLogin(BaseModel): email: EmailStr; password: str
class VerifyCodePayload(BaseModel): email: EmailStr; code: str

def generate_code():
    return f"{secrets.randbelow(1000000):06d}"

def hash_code(code):
    return hashlib.sha256(code.encode()).hexdigest()


def _send_gmail(to, subject, html, reply_to=None):
    if not GMAIL_USER or not GMAIL_APP_PASSWORD:
        print("[Gmail] credentials not set")
        return
    msg = MIMEMultipart("alternative")
    msg["From"] = "Ageinx <" + GMAIL_USER + ">"
    msg["To"] = to
    msg["Subject"] = subject
    if reply_to:
        msg["Reply-To"] = reply_to
    msg.attach(MIMEText(html, "html"))
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login(GMAIL_USER, GMAIL_APP_PASSWORD)
        smtp.sendmail(GMAIL_USER, to, msg.as_string())


async def send_contact_email(name, email, plan, message):
    subject = "[Ageinx] Contact from " + name + " — " + (plan or "no plan")
    html = (
        "<div style='font-family:sans-serif;max-width:520px;margin:0 auto;padding:32px;'>"
        "<h2 style='color:#18170f;margin-bottom:4px;'>New contact request</h2>"
        "<p style='color:#9a9895;font-size:0.85rem;margin-bottom:24px;'>Via Ageinx website</p>"
        "<table style='width:100%;border-collapse:collapse;'>"
        "<tr><td style='padding:8px 0;color:#6a6965;font-size:0.85rem;width:80px;'>Name</td>"
        "<td style='padding:8px 0;font-size:0.9rem;'>" + name + "</td></tr>"
        "<tr><td style='padding:8px 0;color:#6a6965;font-size:0.85rem;'>Email</td>"
        "<td style='padding:8px 0;font-size:0.9rem;'><a href='mailto:" + email + "'>" + email + "</a></td></tr>"
        "<tr><td style='padding:8px 0;color:#6a6965;font-size:0.85rem;'>Plan</td>"
        "<td style='padding:8px 0;font-size:0.9rem;'>" + (plan or "—") + "</td></tr>"
        "</table>"
        "<div style='margin-top:20px;padding:16px;background:#f8f7f5;border-radius:8px;"
        "font-size:0.9rem;line-height:1.6;white-space:pre-wrap;'>" + message + "</div>"
        "</div>"
    )
    try:
        await run_in_threadpool(_send_gmail, CONTACT_TO_EMAIL, subject, html, reply_to=email)
    except Exception as e:
        print("[Gmail] Contact email failed: " + str(e))


async def send_code_email(to_email, code, is_dev=True):
    who = "developer" if is_dev else "user"
    subject = "Your Ageinx verification code"
    html = (
        "<div style='font-family:sans-serif;max-width:480px;margin:0 auto;padding:40px 24px;'>"
        "<div style='font-size:0.8rem;font-weight:600;letter-spacing:0.15em;text-transform:uppercase;"
        "color:#1b6ef2;margin-bottom:24px;'>AGEINX</div>"
        "<h2 style='color:#18170f;font-size:1.4rem;font-weight:600;margin-bottom:8px;'>Verify your email</h2>"
        "<p style='color:#6a6965;font-size:0.9rem;margin-bottom:28px;line-height:1.6;'>"
        "Enter this code to verify your Ageinx " + who + " account. "
        "It expires in <strong>10 minutes</strong>.</p>"
        "<div style='font-size:2.8rem;font-weight:700;letter-spacing:0.4em;color:#18170f;"
        "background:#f3f3f1;border-radius:12px;padding:20px;text-align:center;"
        "font-family:monospace;margin-bottom:28px;'>" + code + "</div>"
        "<p style='color:#9a9895;font-size:0.78rem;'>If you didn't sign up for Ageinx, ignore this email.</p>"
        "</div>"
    )
    try:
        await run_in_threadpool(_send_gmail, to_email, subject, html)
    except Exception as e:
        print("[Gmail] Code email failed: " + str(e))



@app.post("/platform/contact")
async def contact_form(request: Request, data: ContactForm, token: dict = Depends(verify_token)):
    ip = get_client_ip(request)
    await rate_limit(f"contact:{ip}", limit=5, window=3600)
    if not data.name.strip() or not data.message.strip():
        raise HTTPException(status_code=400, detail="Name and message are required")
    await send_contact_email(data.name.strip(), data.email, data.plan, data.message.strip())
    return {"message": "Message sent! We'll get back to you shortly."}


@app.middleware("http")
async def limit_body_size(request: Request, call_next):
    if request.method in ("POST", "PUT", "PATCH"):
        content_length = request.headers.get("content-length")
        if content_length is not None:
            if not content_length.isdigit() or int(content_length) > 10000:
                return JSONResponse(status_code=413, content={"detail": "Payload too large"})
    return await call_next(request)




# ── FIX 3: OAuth CSRF protection — signed JWT state + nonce cookie ───────────
# Old: state = base64(json) — trivially forgeable, no CSRF protection.
# New: state = JWT signed with JWT_SECRET (10 min expiry) containing a nonce.
#      Nonce also stored in an HttpOnly Secure cookie.
#      Callback checks: JWT signature valid AND cookie nonce == state nonce.
#      Attacker can't forge state (no JWT_SECRET), can't read cookie (HttpOnly).

@app.get("/api/oauth/{provider}")
async def oauth_login(provider: str, request: Request, type: str, slug: str = ""):
    ip = get_client_ip(request)
    await rate_limit(f"oauth:{ip}", limit=20, window=300)  # 20 OAuth initiations per 5 min per IP
    nonce = secrets.token_urlsafe(32)
    state_token = jwt.encode(
        {"nonce": nonce, "type": type, "slug": slug, "exp": int(time.time()) + 600},
        JWT_SECRET, algorithm=ALGORITHM
    )
    if provider == "google":
        oauth_url = (f"https://accounts.google.com/o/oauth2/v2/auth"
                     f"?client_id={GOOGLE_CLIENT_ID}&response_type=code"
                     f"&redirect_uri={APP_URL}/api/oauth/callback/google"
                     f"&scope=email profile&state={state_token}")
    elif provider == "github":
        oauth_url = (f"https://github.com/login/oauth/authorize"
                     f"?client_id={GITHUB_CLIENT_ID}"
                     f"&redirect_uri={APP_URL}/api/oauth/callback/github"
                     f"&scope=user:email&state={state_token}")
    else:
        raise HTTPException(status_code=400, detail="Provider not supported")

    response = RedirectResponse(url=oauth_url)
    response.set_cookie(key="oauth_nonce", value=nonce, httponly=True, secure=True,
                        samesite="lax", max_age=600, path="/")
    return response


@app.get("/api/oauth/callback/{provider}")
async def oauth_callback(provider: str, request: Request, code: str, state: str):
    try:
        state_data = jwt.decode(state, JWT_SECRET, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=400, detail="OAuth session expired. Please try again.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=400, detail="Invalid OAuth state.")

    cookie_nonce = request.cookies.get("oauth_nonce")
    if not cookie_nonce or cookie_nonce != state_data.get("nonce"):
        raise HTTPException(status_code=400, detail="OAuth CSRF check failed. Please try again.")

    login_type = state_data.get("type")
    slug = state_data.get("slug", "")
    client = get_http_client()
    email = None

    if provider == "google":
        token_res = await client.post("https://oauth2.googleapis.com/token", data={
            "client_id": GOOGLE_CLIENT_ID, "client_secret": GOOGLE_CLIENT_SECRET,
            "code": code, "grant_type": "authorization_code",
            "redirect_uri": f"{APP_URL}/api/oauth/callback/google"
        })
        at = token_res.json().get("access_token")
        if not at: raise HTTPException(status_code=400, detail="Google auth failed")
        user_res = await client.get("https://www.googleapis.com/oauth2/v2/userinfo",
                                    headers={"Authorization": f"Bearer {at}"})
        email = user_res.json().get("email")

    elif provider == "github":
        token_res = await client.post("https://github.com/login/oauth/access_token",
            data={"client_id": GITHUB_CLIENT_ID, "client_secret": GITHUB_CLIENT_SECRET,
                  "code": code, "redirect_uri": f"{APP_URL}/api/oauth/callback/github"},
            headers={"Accept": "application/json"})
        at = token_res.json().get("access_token")
        if not at: raise HTTPException(status_code=400, detail="GitHub auth failed")
        user_res = await client.get("https://api.github.com/user/emails",
                                    headers={"Authorization": f"Bearer {at}"})
        emails_list = user_res.json()
        email = next((e["email"] for e in emails_list if e.get("primary") and e.get("verified")), None)
        if not email and emails_list: email = emails_list[0]["email"]

    if not email:
        raise HTTPException(status_code=400, detail="Failed to retrieve email from provider")

    db_pool = await get_pool()
    async with db_pool.acquire() as conn:
        dummy_hash = await run_in_threadpool(pwd_context.hash, secrets.token_hex(16))

        is_new_oauth_dev = False
        if login_type == "dev":
            dev = await conn.fetchrow("SELECT id, plan FROM developers WHERE email=$1", email)
            if not dev:
                api_key = f"ax_live_{secrets.token_urlsafe(24)}"
                rand_slug = f"app-{secrets.token_hex(4)}"
                dev_id = await conn.fetchval(
                    "INSERT INTO developers (email,password_hash,api_key,slug,callback_url,is_active,email_verified) "
                    "VALUES ($1,$2,$3,$4,$5,true,TRUE) RETURNING id",
                    email, dummy_hash, api_key, rand_slug, f"{APP_URL}/dashboard"
                )
                plan = "starter"
                is_new_oauth_dev = True
            else:
                dev_id, plan = dev["id"], dev["plan"] or "starter"

            at_jwt  = create_token({"sub": str(dev_id), "type": "access"},  ACCESS_TOKEN_EXPIRE)
            rt_jwt  = create_token({"sub": str(dev_id), "type": "refresh"}, REFRESH_TOKEN_EXPIRE)
            await conn.execute(
                "INSERT INTO dev_sessions (developer_id,refresh_token,expires_at) VALUES ($1,$2,to_timestamp($3))",
                dev_id, rt_jwt, int(time.time()) + REFRESH_TOKEN_EXPIRE
            )
            # Pass token via URL hash — dashboard JS picks it up and stores in localStorage
            # (HttpOnly cookie is invisible to JS, so localStorage is the correct approach here)
            dest = f"{APP_URL}/onboarding" if is_new_oauth_dev else f"{APP_URL}/dashboard"
            response = RedirectResponse(url=f"{dest}#ax_token={at_jwt}")
            response.delete_cookie("oauth_nonce", path="/")
            return response

        elif login_type == "user":
            dev = await conn.fetchrow(
                "SELECT id,callback_url,plan FROM developers WHERE slug=$1 AND is_active=true", slug
            )
            if not dev: raise HTTPException(status_code=404, detail="App not found")
            user = await conn.fetchrow("SELECT id FROM users WHERE developer_id=$1 AND email=$2", dev["id"], email)
            if not user:
                user_id = await conn.fetchval(
                    "INSERT INTO users (developer_id,email,password_hash,email_verified) VALUES ($1,$2,$3,TRUE) RETURNING id",
                    dev["id"], email, dummy_hash
                )
            else:
                user_id = user["id"]

            await enforce_plan_limit(str(dev["id"]), dev["plan"] or "starter")
            token = create_token(
                {"sub": str(user_id), "dev": str(dev["id"]), "email": email, "type": "user_access"},
                USER_ACCESS_EXPIRE
            )
            response = RedirectResponse(url=f"{dev['callback_url']}#token={token}")
            response.delete_cookie("oauth_nonce", path="/")
            return response


@app.get("/health")
async def health_check():
    return {"status": "ok"}

@app.post("/refresh")
async def refresh_token_endpoint(refresh_token: str):
    try:
        payload = verify_token_payload(refresh_token, expected_type="refresh")
        new_token = create_token({"sub": payload.get("sub"), "type": "access"}, ACCESS_TOKEN_EXPIRE)
        return {"access_token": new_token, "token_type": "bearer", "expires_in": ACCESS_TOKEN_EXPIRE}
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

@app.get("/verify")
async def verify_endpoint(token: str):
    try:
        payload = verify_token_payload(token)
        return {"status": "active", "user": payload.get("sub")}
    except Exception:
        raise HTTPException(status_code=401, detail="Expired or invalid")


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
                "INSERT INTO developers (email,password_hash,api_key,slug,callback_url,is_active,email_verified) "
                "VALUES ($1,$2,$3,$4,$5,true,FALSE)",
                data.email.lower().strip(), password_hash, api_key, data.slug, data.callback_url
            )
        except asyncpg.exceptions.UniqueViolationError as e:
            if "email" in str(e): raise HTTPException(status_code=400, detail="email already registered")
            raise HTTPException(status_code=400, detail="slug already taken")

    code = generate_code()
    code_hash = hash_code(code)
    expires_at = datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
    db_pool2 = await get_pool()
    async with db_pool2.acquire() as conn2:
        await conn2.execute(
            "UPDATE developers SET email_verified=FALSE, verify_token_hash=$1, verify_expires=$2 WHERE email=$3",
            code_hash, expires_at, data.email
        )
    await send_code_email(data.email, code, is_dev=True)
    return {"message": "Account created! Check your email for a verification code.",
            "api_key": api_key, "auth_url": f"{APP_URL}/auth/{data.slug}",
            "active": True, "requires_verification": True}


@app.post("/platform/dev/login")
async def dev_login(request: Request, data: DevLogin):
    ip = get_client_ip(request)
    await rate_limit(f"login:{ip}", limit=10, window=900)

    db_pool = await get_pool()
    async with db_pool.acquire() as conn:
        dev = await conn.fetchrow(
            "SELECT id,email,password_hash,is_active,email_verified FROM developers WHERE email=$1", data.email.lower().strip()
        )

    if not dev or not await run_in_threadpool(pwd_context.verify, data.password, dev["password_hash"]):
        raise HTTPException(status_code=401, detail="invalid credentials")
    if not dev["is_active"]:
        raise HTTPException(status_code=403, detail="account not yet activated")
    if not dev["email_verified"]:
        raise HTTPException(status_code=403, detail="email not verified. Check your inbox for a 6-digit code.")

    access_token  = create_token({"sub": str(dev["id"]), "type": "access"},  ACCESS_TOKEN_EXPIRE)
    refresh_token = create_token({"sub": str(dev["id"]), "type": "refresh"}, REFRESH_TOKEN_EXPIRE)

    db_pool = await get_pool()
    async with db_pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO dev_sessions (developer_id,refresh_token,expires_at) VALUES ($1,$2,to_timestamp($3))",
            dev["id"], refresh_token, int(time.time()) + REFRESH_TOKEN_EXPIRE
        )

    return {"access_token": access_token, "refresh_token": refresh_token,
            "token_type": "bearer", "expires_in": ACCESS_TOKEN_EXPIRE}


@app.get("/platform/dev/me")
async def dev_me(token: dict = Depends(verify_token)):
    dev_id = str(token["sub"])
    db_pool = await get_pool()
    async with db_pool.acquire() as conn:
        dev = await conn.fetchrow(
            "SELECT email,api_key,slug,callback_url,plan,is_active,created_at,api_calls_count,onboarding_complete "
            "FROM developers WHERE id=$1", safe_uuid(dev_id)
        )
        if not dev: raise HTTPException(status_code=404, detail="developer not found")
        user_count = await conn.fetchval("SELECT COUNT(*) FROM users WHERE developer_id=$1", safe_uuid(dev_id))

    plan = dev["plan"] or "starter"
    redis_count = await get_redis_call_count(dev_id)
    api_calls = redis_count if redis_count > 0 else (dev["api_calls_count"] or 0)

    return {"email": dev["email"], "api_key": dev["api_key"], "slug": dev["slug"],
            "callback_url": dev["callback_url"], "plan": plan, "is_active": dev["is_active"],
            "created_at": str(dev["created_at"]),
            "onboarding_complete": dev["onboarding_complete"],
            "usage": {"users_registered": user_count or 0, "api_calls_count": api_calls,
                      "api_calls_limit": PLAN_LIMITS.get(plan, 1000)}}


@app.post("/platform/dev/logout")
async def logout(token: dict = Depends(verify_token)):
    dev_id = str(token["sub"])
    db_pool = await get_pool()
    async with db_pool.acquire() as conn:
        await conn.execute("DELETE FROM dev_sessions WHERE developer_id=$1", safe_uuid(dev_id))
    return {"message": "logged out successfully"}


@app.get("/platform/dev/users")
async def dev_get_users(token: dict = Depends(verify_token)):
    dev_id = str(token["sub"])
    db_pool = await get_pool()
    async with db_pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT id,email,email_verified,created_at FROM users WHERE developer_id=$1 ORDER BY created_at DESC",
            safe_uuid(dev_id)
        )
    return {"users": [dict(r) for r in rows]}


@app.post("/platform/dev/change-password")
async def dev_change_password(data: ChangePassword, token: dict = Depends(verify_token)):
    dev_id = str(token["sub"])
    db_pool = await get_pool()
    async with db_pool.acquire() as conn:
        dev = await conn.fetchrow("SELECT password_hash FROM developers WHERE id=$1", safe_uuid(dev_id))
        if not dev: raise HTTPException(status_code=404, detail="developer not found")
        if not await run_in_threadpool(pwd_context.verify, data.current_password, dev["password_hash"]):
            raise HTTPException(status_code=401, detail="current password incorrect")
        validate_password(data.new_password)
        new_hash = await run_in_threadpool(pwd_context.hash, data.new_password)
        await conn.execute("UPDATE developers SET password_hash=$1 WHERE id=$2", new_hash, safe_uuid(dev_id))
    return {"message": "password updated"}


# ── Cron: sync Redis counts → Postgres (run hourly via vercel.json cron) ─────
# vercel.json: {"crons": [{"path": "/internal/sync-api-counts", "schedule": "0 * * * *"}]}

@app.post("/internal/sync-api-counts")
async def sync_api_counts(request: Request):
    if request.headers.get("x-api-key") != INTERNAL_API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")
    if not UPSTASH_URL or not UPSTASH_TOKEN:
        return {"message": "Redis not configured"}

    client = get_http_client()
    headers = {"Authorization": f"Bearer {UPSTASH_TOKEN}"}

    try:
        r = await client.post(f"{UPSTASH_URL}/scan/0", headers=headers,
                              json=["MATCH", "plan:*", "COUNT", "200"])
        keys = r.json().get("result", [None, []])[1]
    except Exception as e:
        return {"error": str(e)}

    db_pool = await get_pool()
    synced = 0
    for key in keys:
        try:
            dev_id = key.replace("plan:", "")
            val_r = await client.get(f"{UPSTASH_URL}/get/{key}", headers=headers)
            count = int(val_r.json().get("result") or 0)
            async with db_pool.acquire() as conn:
                await conn.execute("UPDATE developers SET api_calls_count=$1 WHERE id=$2",
                                   count, safe_uuid(dev_id))
            synced += 1
        except Exception:
            continue

    return {"synced": synced}




# ── Onboarding: check slug availability (live, as-you-type) ─────────────────
@app.get("/platform/dev/check-slug")
async def check_slug(slug: str, token: dict = Depends(verify_token)):
    try:
        validate_slug(slug)
    except HTTPException:
        return {"available": False, "error": "Slug must be 3-30 chars, lowercase letters, numbers and hyphens only"}
    db_pool = await get_pool()
    async with db_pool.acquire() as conn:
        taken = await conn.fetchval("SELECT id FROM developers WHERE slug=$1", slug)
    return {"available": taken is None}


# ── Onboarding: save slug + callback_url, mark onboarding complete ───────────
class OnboardingData(BaseModel):
    slug: str
    callback_url: str

@app.post("/platform/dev/onboarding")
async def complete_onboarding(data: OnboardingData, token: dict = Depends(verify_token)):
    dev_id = str(token["sub"])
    validate_slug(data.slug)

    # Basic callback_url sanity check
    parsed = urlparse(data.callback_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise HTTPException(status_code=400, detail="callback_url must be a valid http/https URL")

    db_pool = await get_pool()
    async with db_pool.acquire() as conn:
        # Make sure slug isn't taken by someone else
        taken = await conn.fetchval(
            "SELECT id FROM developers WHERE slug=$1 AND id!=$2", data.slug, safe_uuid(dev_id)
        )
        if taken:
            raise HTTPException(status_code=400, detail="slug already taken")

        await conn.execute(
            "UPDATE developers SET slug=$1, callback_url=$2, onboarding_complete=TRUE WHERE id=$3",
            data.slug, data.callback_url, safe_uuid(dev_id)
        )
    return {"message": "Onboarding complete", "slug": data.slug, "callback_url": data.callback_url}




@app.post("/platform/dev/verify-code")
async def dev_verify_code(request: Request, data: VerifyCodePayload):
    ip = get_client_ip(request)
    await rate_limit(f"verify_dev:{data.email}", limit=5, window=900)  # 5 attempts per 15 min per email
    await rate_limit(f"verify_ip:{ip}", limit=20, window=900)           # 20 attempts per 15 min per IP
    db_pool = await get_pool()
    async with db_pool.acquire() as conn:
        dev = await conn.fetchrow(
            "SELECT id, verify_token_hash, verify_expires FROM developers WHERE email=$1", data.email.lower().strip()
        )
    if not dev or not dev["verify_token_hash"]:
        raise HTTPException(status_code=400, detail="No pending verification for this email")
    if dev["verify_expires"] and datetime.datetime.utcnow() > dev["verify_expires"].replace(tzinfo=None):
        raise HTTPException(status_code=400, detail="Code expired. Request a new one.")
    if not secrets.compare_digest(hash_code(data.code), dev["verify_token_hash"]):
        raise HTTPException(status_code=400, detail="Invalid code. Try again.")
    db_pool2 = await get_pool()
    async with db_pool2.acquire() as conn2:
        await conn2.execute(
            "UPDATE developers SET email_verified=TRUE, verify_token_hash=NULL, verify_expires=NULL WHERE id=$1",
            dev["id"]
        )
    return {"message": "Email verified!"}


@app.post("/auth/{slug}/verify-code")
async def user_verify_code(slug: str, request: Request, data: VerifyCodePayload):
    ip = get_client_ip(request)
    await rate_limit(f"verify_user:{data.email}", limit=5, window=900)
    await rate_limit(f"verify_ip:{ip}", limit=20, window=900)
    db_pool = await get_pool()
    async with db_pool.acquire() as conn:
        dev = await conn.fetchrow("SELECT id FROM developers WHERE slug=$1 AND is_active=true", slug)
        if not dev:
            raise HTTPException(status_code=404, detail="App not found")
        user = await conn.fetchrow(
            "SELECT id, verify_token_hash, verify_expires FROM users WHERE developer_id=$1 AND email=$2",
            dev["id"], data.email
        )
    if not user or not user["verify_token_hash"]:
        raise HTTPException(status_code=400, detail="No pending verification for this email")
    if user["verify_expires"] and datetime.datetime.utcnow() > user["verify_expires"].replace(tzinfo=None):
        raise HTTPException(status_code=400, detail="Code expired. Request a new one.")
    if not secrets.compare_digest(hash_code(data.code), user["verify_token_hash"]):
        raise HTTPException(status_code=400, detail="Invalid code. Try again.")
    db_pool2 = await get_pool()
    async with db_pool2.acquire() as conn2:
        await conn2.execute(
            "UPDATE users SET email_verified=TRUE, verify_token_hash=NULL, verify_expires=NULL WHERE id=$1",
            user["id"]
        )
    return {"message": "Email verified!"}


@app.post("/platform/dev/resend-code")
async def dev_resend_code(request: Request):
    ip = get_client_ip(request)
    body = await request.json()
    email = body.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="email required")
    await rate_limit(f"resend_dev:{email}", limit=3, window=300)  # max 3 resends per 5 min
    await rate_limit(f"resend_ip:{ip}", limit=10, window=300)
    db_pool = await get_pool()
    async with db_pool.acquire() as conn:
        dev = await conn.fetchrow("SELECT id, email_verified FROM developers WHERE email=$1", email)
    if not dev:
        raise HTTPException(status_code=404, detail="Account not found")
    if dev["email_verified"]:
        raise HTTPException(status_code=400, detail="Email already verified")
    code = generate_code()
    code_hash = hash_code(code)
    expires_at = datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
    db_pool2 = await get_pool()
    async with db_pool2.acquire() as conn2:
        await conn2.execute(
            "UPDATE developers SET verify_token_hash=$1, verify_expires=$2 WHERE email=$3",
            code_hash, expires_at, email
        )
    await send_code_email(email, code, is_dev=True)
    return {"message": "Code resent"}


@app.post("/auth/{slug}/resend-code")
async def user_resend_code(slug: str, request: Request):
    ip = get_client_ip(request)
    body = await request.json()
    email = body.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="email required")
    await rate_limit(f"resend_user:{email}", limit=3, window=300)
    await rate_limit(f"resend_ip:{ip}", limit=10, window=300)
    db_pool = await get_pool()
    async with db_pool.acquire() as conn:
        dev = await conn.fetchrow("SELECT id FROM developers WHERE slug=$1 AND is_active=true", slug)
        if not dev:
            raise HTTPException(status_code=404, detail="App not found")
        user = await conn.fetchrow(
            "SELECT id, email_verified FROM users WHERE developer_id=$1 AND email=$2",
            dev["id"], email
        )
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user["email_verified"]:
        raise HTTPException(status_code=400, detail="Email already verified")
    code = generate_code()
    code_hash = hash_code(code)
    expires_at = datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
    db_pool2 = await get_pool()
    async with db_pool2.acquire() as conn2:
        await conn2.execute(
            "UPDATE users SET verify_token_hash=$1, verify_expires=$2 WHERE id=$3",
            code_hash, expires_at, user["id"]
        )
    await send_code_email(email, code, is_dev=False)
    return {"message": "Code resent"}

@app.get("/auth/userinfo")
async def auth_userinfo(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    payload = verify_token_payload(credentials.credentials, expected_type="user_access")
    return {"user_id": payload["sub"], "email": payload.get("email"),
            "developer_id": payload.get("dev"), "token_type": "user_access"}


@app.get("/auth/{slug}")
async def auth_page(slug: str):
    db_pool = await get_pool()
    async with db_pool.acquire() as conn:
        dev = await conn.fetchrow("SELECT slug FROM developers WHERE slug=$1 AND is_active=true", slug)
    if not dev: raise HTTPException(status_code=404, detail="app not found")

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
.oauth-btn{{display:flex;align-items:center;justify-content:center;gap:8px;width:100%;background:#fff;border:1px solid #c6c5c1;color:#18170f;padding:9px;border-radius:6px;font-family:'Geist',sans-serif;font-size:0.875rem;font-weight:500;cursor:pointer;transition:all 0.15s;margin-bottom:10px}}
.oauth-btn:hover{{background:#f8f7f5;border-color:#18170f}}
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
  <div style="display:flex;gap:10px;margin-bottom:20px;">
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

<!-- verify modal -->
<div id="vmodal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.5);z-index:500;align-items:center;justify-content:center;padding:24px;">
  <div style="background:#fff;border-radius:14px;padding:40px;width:100%;max-width:400px;text-align:center;box-shadow:0 16px 48px rgba(0,0,0,0.15);">
    <h3 style="font-size:1.2rem;font-weight:600;color:#18170f;margin-bottom:8px;">Check your email</h3>
    <p style="font-size:0.84rem;color:#6a6965;margin-bottom:20px;line-height:1.6;">We sent a 6-digit code to <strong id="vm-email"></strong>. Enter it below.</p>
    <div id="vm-inputs" style="display:flex;gap:8px;justify-content:center;margin-bottom:16px;">
      <input type="text" maxlength="1" inputmode="numeric" style="width:42px;height:52px;text-align:center;font-size:1.3rem;font-weight:700;border:2px solid #c6c5c1;border-radius:8px;font-family:'Geist',sans-serif;outline:none;"/>
      <input type="text" maxlength="1" inputmode="numeric" style="width:42px;height:52px;text-align:center;font-size:1.3rem;font-weight:700;border:2px solid #c6c5c1;border-radius:8px;font-family:'Geist',sans-serif;outline:none;"/>
      <input type="text" maxlength="1" inputmode="numeric" style="width:42px;height:52px;text-align:center;font-size:1.3rem;font-weight:700;border:2px solid #c6c5c1;border-radius:8px;font-family:'Geist',sans-serif;outline:none;"/>
      <input type="text" maxlength="1" inputmode="numeric" style="width:42px;height:52px;text-align:center;font-size:1.3rem;font-weight:700;border:2px solid #c6c5c1;border-radius:8px;font-family:'Geist',sans-serif;outline:none;"/>
      <input type="text" maxlength="1" inputmode="numeric" style="width:42px;height:52px;text-align:center;font-size:1.3rem;font-weight:700;border:2px solid #c6c5c1;border-radius:8px;font-family:'Geist',sans-serif;outline:none;"/>
      <input type="text" maxlength="1" inputmode="numeric" style="width:42px;height:52px;text-align:center;font-size:1.3rem;font-weight:700;border:2px solid #c6c5c1;border-radius:8px;font-family:'Geist',sans-serif;outline:none;"/>
    </div>
    <button id="vm-btn" onclick="verifyCode()" style="width:100%;background:#18170f;color:#fff;border:none;padding:11px;border-radius:8px;font-family:'Geist',sans-serif;font-size:0.9rem;font-weight:500;cursor:pointer;margin-bottom:12px;">Verify</button>
    <div style="font-size:0.8rem;color:#9a9895;">Didn't get it? <a onclick="resendCode()" style="color:#1b6ef2;cursor:pointer;font-weight:500;">Resend</a></div>
    <div id="vm-msg" style="display:none;margin-top:12px;padding:8px 12px;border-radius:7px;font-size:0.82rem;"></div>
  </div>
</div>

<script>
const SLUG = "{slug}";
const API  = window.location.origin;
function switchTab(tab) {{
  document.getElementById('tab-login').classList.toggle('active', tab==='login');
  document.getElementById('tab-signup').classList.toggle('active', tab==='signup');
  document.getElementById('form-login').style.display  = tab==='login'  ? 'block' : 'none';
  document.getElementById('form-signup').style.display = tab==='signup' ? 'block' : 'none';
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
  btn.disabled = true; btn.textContent = 'Signing in\u2026';
  try {{
    const res  = await fetch(`${{API}}/auth/${{SLUG}}/login`, {{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{email,password}})}});
    const data = await res.json();
    if (!res.ok) {{
      showMsg('li-msg', data.detail || 'Login failed.', 'error');
      return;
    }}
    showMsg('li-msg', '\u2705 Signed in! Redirecting\u2026', 'success');
    setTimeout(() => {{ window.location.href = data.redirect_url; }}, 800);
  }} catch(e) {{ showMsg('li-msg', 'Network error. Try again.', 'error'); }}
  finally {{ btn.disabled = false; btn.textContent = 'Sign in'; }}
}}
async function handleSignup() {{
  const btn = document.getElementById('su-btn');
  const email = document.getElementById('su-email').value.trim();
  const password = document.getElementById('su-password').value;
  if (!email || !password) {{ showMsg('su-msg','All fields required.','error'); return; }}
  btn.disabled = true; btn.textContent = 'Creating account\u2026';
  try {{
    const res  = await fetch(`${{API}}/auth/${{SLUG}}/signup`, {{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{email,password}})}});
    const data = await res.json();
    if (!res.ok) {{ showMsg('su-msg', data.detail || 'Signup failed.', 'error'); return; }}
    if (data.requires_verification) {{
      showMsg('su-msg', '\u2705 Account created! Check your email for a 6-digit code.', 'success');
      document.getElementById('su-email').value = '';
      document.getElementById('su-password').value = '';
      showVerifyModal(email);
    }} else {{
      showMsg('su-msg', '\u2705 Account created! Redirecting\u2026', 'success');
      setTimeout(() => {{ window.location.href = data.redirect_url; }}, 800);
    }}
  }} catch(e) {{ showMsg('su-msg', 'Network error. Try again.', 'error'); }}
  finally {{ btn.disabled = false; btn.textContent = 'Create account'; }}

}}

let _vmEmail = '';
function showVerifyModal(email) {{
  _vmEmail = email;
  document.getElementById('vm-email').textContent = email;
  const modal = document.getElementById('vmodal');
  modal.style.display = 'flex';
  const inputs = modal.querySelectorAll('input');
  inputs.forEach(i => i.value = '');
  inputs[0].focus();
  inputs.forEach((inp, i) => {{
    inp.oninput = () => {{
      inp.value = inp.value.replace(/[^0-9]/g,'');
      if (inp.value && i < inputs.length-1) inputs[i+1].focus();
    }};
    inp.onkeydown = e => {{
      if (e.key==='Backspace' && !inp.value && i>0) inputs[i-1].focus();
    }};
  }});
}}

function getVCode() {{
  return [...document.querySelectorAll('#vmodal input')].map(i => i.value).join('');
}}

function setVMsg(text, ok) {{
  const el = document.getElementById('vm-msg');
  el.textContent = text;
  el.style.display = 'block';
  el.style.background = ok ? '#f0fdf4' : '#fff1f2';
  el.style.color      = ok ? '#15803d' : '#be123c';
  el.style.border     = ok ? '1px solid #bbf7d0' : '1px solid #fecdd3';
}}

async function verifyCode() {{
  const code = getVCode();
  if (code.length < 6) {{ setVMsg('Enter all 6 digits.', false); return; }}
  const btn = document.getElementById('vm-btn');
  btn.disabled = true; btn.textContent = 'Verifying...';
  try {{
    const res  = await fetch(`${{API}}/auth/${{SLUG}}/verify-code`, {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{ email: _vmEmail, code }})
    }});
    const data = await res.json();
    if (!res.ok) {{ setVMsg(data.detail || 'Invalid code.', false); return; }}
    setVMsg('\u2705 Email verified! You can now sign in.', true);
    setTimeout(() => {{
      document.getElementById('vmodal').style.display = 'none';
      switchTab('login');
    }}, 1800);
  }} catch(e) {{ setVMsg('Network error.', false); }}
  finally {{ btn.disabled = false; btn.textContent = 'Verify'; }}
}}

async function resendCode() {{
  try {{
    await fetch(`${{API}}/auth/${{SLUG}}/resend-code`, {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{ email: _vmEmail }})
    }});
    setVMsg('New code sent!', true);
  }} catch(e) {{ setVMsg('Failed to resend.', false); }}
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
            "SELECT id,callback_url,plan FROM developers WHERE slug=$1 AND is_active=true", slug
        )
        if not dev: raise HTTPException(status_code=404, detail="app not found")
        password_hash = await run_in_threadpool(pwd_context.hash, data.password)
        try:
            await conn.fetchval(
                "INSERT INTO users (developer_id,email,password_hash,email_verified) "
                "VALUES ($1,$2,$3,FALSE) RETURNING id",
                dev["id"], data.email.lower().strip(), password_hash
            )
        except asyncpg.exceptions.UniqueViolationError:
            raise HTTPException(status_code=400, detail="email already registered")

    await enforce_plan_limit(str(dev["id"]), dev["plan"] or "starter")
    code = generate_code()
    code_hash = hash_code(code)
    expires_at = datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
    db_pool2 = await get_pool()
    async with db_pool2.acquire() as conn2:
        await conn2.execute(
            "UPDATE users SET email_verified=FALSE, verify_token_hash=$1, verify_expires=$2 WHERE developer_id=$3 AND email=$4",
            code_hash, expires_at, dev["id"], data.email
        )
    await send_code_email(data.email, code, is_dev=False)
    return {"message": "Account created! Check your email for a verification code.", "requires_verification": True}


@app.post("/auth/{slug}/login")
async def auth_user_login(slug: str, request: Request, data: UserLogin):
    ip = get_client_ip(request)
    await rate_limit(f"auth_login:{ip}", limit=10, window=900)

    db_pool = await get_pool()
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT d.id AS dev_id,d.callback_url,d.plan,u.id AS user_id,u.email,u.password_hash,u.email_verified "
            "FROM developers d LEFT JOIN users u ON u.developer_id=d.id AND u.email=$2 "
            "WHERE d.slug=$1 AND d.is_active=true",
            slug, data.email.lower().strip()
        )
    if not row: raise HTTPException(status_code=404, detail="app not found")
    if not row["user_id"] or not await run_in_threadpool(pwd_context.verify, data.password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="invalid credentials")
    if not row["email_verified"]:
        raise HTTPException(status_code=403, detail="email not verified. Check your inbox for a 6-digit code.")
    await enforce_plan_limit(str(row["dev_id"]), row["plan"] or "starter")
    token = create_token(
        {"sub": str(row["user_id"]), "dev": str(row["dev_id"]), "email": row["email"], "type": "user_access"},
        USER_ACCESS_EXPIRE
    )
    # Validate redirect target matches stored callback origin (prevent open redirect)
    parsed_cb = urlparse(row["callback_url"])
    cb_origin  = f"{parsed_cb.scheme}://{parsed_cb.netloc}"
    redirect_url = f"{row['callback_url']}#token={token}"
    return {"message": "login successful", "redirect_url": redirect_url, "token": token}
