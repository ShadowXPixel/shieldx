import asyncpg
import os
import jwt
import time
import uuid
import re
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
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE = 60 * 15            # 15 minutes
REFRESH_TOKEN_EXPIRE = 60 * 60 * 24 * 7  # 7 days

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer_scheme = HTTPBearer()

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
    allow_origins=["https://ageinx.vercel.app"],
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
            max_size=1,
            statement_cache_size=0  # required for pgBouncer / Supabase transaction mode
        )
    return pool

# -----------------------------------
# Middleware
# -----------------------------------

@app.middleware("http")
async def limit_body_size(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length and content_length.isdigit() and int(content_length) > 10000:
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
async def dev_signup(data: DevSignup):
    validate_slug(data.slug)
    validate_password(data.password)

    db_pool = await get_pool()
    async with db_pool.acquire() as conn:
        existing_email = await conn.fetchrow(
            "SELECT id FROM developers WHERE email = $1", data.email
        )
        if existing_email:
            raise HTTPException(status_code=400, detail="email already registered")

        existing_slug = await conn.fetchrow(
            "SELECT id FROM developers WHERE slug = $1", data.slug
        )
        if existing_slug:
            raise HTTPException(status_code=400, detail="slug already taken")

        password_hash = pwd_context.hash(data.password)
        api_key = f"ax_live_{uuid.uuid4().hex}"

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

    return {
        "message": "account created. save your api key — it won't be shown again.",
        "api_key": api_key,
        "login_url": f"https://ageinx.vercel.app/auth/{data.slug}",
        "active": True
    }


@app.post("/platform/dev/login")
async def dev_login(data: DevLogin):
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
    dev_id = token["sub"]

    db_pool = await get_pool()
    async with db_pool.acquire() as conn:
        dev = await conn.fetchrow(
            """
            SELECT email, api_key, slug, callback_url, plan, is_active, created_at
            FROM developers WHERE id = $1
            """,
            uuid.UUID(dev_id)
        )

        if not dev:
            raise HTTPException(status_code=404, detail="developer not found")

        user_count = await conn.fetchval(
            "SELECT COUNT(*) FROM users WHERE developer_id = $1",
            uuid.UUID(dev_id)
        )

        sessions_this_month = await conn.fetchval(
            """
            SELECT COUNT(*) FROM dev_sessions
            WHERE developer_id = $1
            AND created_at >= date_trunc('month', now())
            """,
            uuid.UUID(dev_id)
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
    dev_id = token["sub"]

    db_pool = await get_pool()
    async with db_pool.acquire() as conn:
        dev = await conn.fetchrow(
            "SELECT password_hash FROM developers WHERE id = $1",
            uuid.UUID(dev_id)
        )

        if not dev or not pwd_context.verify(data.current_password, dev["password_hash"]):
            raise HTTPException(status_code=401, detail="current password is incorrect")

        validate_password(data.new_password)
        new_hash = pwd_context.hash(data.new_password)

        await conn.execute(
            "UPDATE developers SET password_hash = $1 WHERE id = $2",
            new_hash, uuid.UUID(dev_id)
        )

    return {"message": "password updated successfully"}

@app.post("/platform/dev/logout")
async def logout(token: dict = Depends(verify_token)):
    dev_id = token["sub"]

    db_pool = await get_pool()
    async with db_pool.acquire() as conn:
        await conn.execute(
            "DELETE FROM dev_sessions WHERE developer_id = $1",
            uuid.UUID(dev_id)
        )

    return {"message": "logged out successfully"}

# -----------------------------------
# /internal — Fraud Filter
# -----------------------------------

@app.post("/internal/check", include_in_schema=False)
async def internal_check(request: Request):
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
# /auth — AuthaaS (coming soon)
# -----------------------------------

# @app.get("/auth/{slug}")
# @app.post("/auth/{slug}/signup")
# @app.post("/auth/{slug}/login")
# @app.get("/auth/userinfo")

