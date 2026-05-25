# Ageinx

Modern authentication infrastructure for developers.

Ageinx is a lightweight authentication platform built with FastAPI, designed to provide secure user authentication, OAuth login, email verification, API usage tracking, and developer onboarding workflows.

Built as an experimental full-stack auth system focused on:
- security
- scalability
- developer experience
- serverless deployment

---

## Features

### Authentication
- Email/password authentication
- JWT access + refresh tokens
- Token rotation
- Secure password hashing with bcrypt
- User session management

### OAuth Providers
- Google OAuth
- GitHub OAuth
- PKCE + CSRF protection

### Security
- Rate limiting
- Verification code hashing
- Secure cookies
- Timing-safe authentication checks
- Dynamic CORS validation
- Payload size protection

### Developer Platform
- Developer onboarding system
- API key generation
- Usage tracking
- Plan limits
- Callback URL management

### Infrastructure
- FastAPI backend
- Async PostgreSQL with asyncpg
- Redis-based rate limiting
- Optimized for Vercel serverless deployment

---

## Tech Stack

### Backend
- FastAPI
- PostgreSQL
- asyncpg
- Redis (Upstash)
- JWT
- Passlib

### Frontend
- HTML
- CSS
- Vanilla JavaScript

### Deployment
- Vercel
- Supabase
- Upstash Redis

---

## Architecture

```text
Client
   ↓
FastAPI API
   ↓
Authentication Layer
   ↓
PostgreSQL + Redis
```

---

## Core Features

### OAuth Flow
Ageinx supports secure OAuth authentication using:
- signed JWT state tokens
- nonce validation
- PKCE code challenge verification

### Rate Limiting
Redis-based request limiting protects:
- login routes
- signup endpoints
- verification systems
- OAuth flows

### Serverless Optimization
The backend is optimized for serverless environments:
- lightweight DB connection pooling
- async request handling
- Redis-based counters
- minimized database locking

---

## API Overview

### Developer Routes
```http
POST /platform/dev/signup
POST /platform/dev/login
GET  /platform/dev/me
POST /platform/dev/logout
```

### User Authentication
```http
POST /auth/{slug}/signup
POST /auth/{slug}/login
GET  /auth/userinfo
```

### OAuth
```http
GET /api/oauth/google
GET /api/oauth/github
```

---

## Environment Variables

```env
DATABASE_URL=
JWT_SECRET=

UPSTASH_REDIS_REST_URL=
UPSTASH_REDIS_REST_TOKEN=

GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=

GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=

GMAIL_USER=
GMAIL_APP_PASSWORD=
```

---

## Running Locally

```bash
git clone https://github.com/yourusername/ageinx.git

cd ageinx

pip install -r requirements.txt

uvicorn main:app --reload
```

---

## Status

This project started as an experimental authentication platform and evolved into a full-stack infrastructure learning project.

Some areas are still being refactored and improved.

---

## Future Improvements

- Modular codebase structure
- Better dashboard UI
- SDK support
- Multi-factor authentication
- Better analytics
- Admin dashboard
- Docker support

---

## License

MIT License

---

## Author

Built by Ankur Bhardwaj.

"just another builder."
