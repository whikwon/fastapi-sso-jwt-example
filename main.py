import os
from datetime import datetime, timezone
from typing import Optional

import jwt
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, Response, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi_jwt import JwtAccessCookie, JwtAuthorizationCredentials, JwtRefreshCookie
from fastapi_sso.sso.google import GoogleSSO
from motor.motor_asyncio import AsyncIOMotorClient
from odmantic import AIOEngine, Field, Model, ObjectId

# ─── Load env vars ───────────────────────────────────────────────────────────
load_dotenv(".env")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:9999")
MONGO_URL = os.getenv("MONGO_URL", "mongodb://localhost:27017")
DB_NAME = os.getenv("DB_NAME", "fastapi_sso_demo")
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "super-secret-key")

# ─── FastAPI + CORS ──────────────────────────────────────────────────────────
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_URL],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# ─── JWT setup ────────────────────────────────────────────────────────────────
access_security = JwtAccessCookie(secret_key=SECRET_KEY, auto_error=True)
refresh_security = JwtRefreshCookie(secret_key=SECRET_KEY, auto_error=True)

# ─── MongoDB (ODMantic) ───────────────────────────────────────────────────────
engine = AIOEngine(client=AsyncIOMotorClient(MONGO_URL), database=DB_NAME)


class User(Model):
    google_id: str = Field(index=True, unique=True)
    email: str = Field(index=True)
    name: Optional[str] = None
    avatar_url: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_login: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    model_config = {"collection": "users"}


# ─── Google SSO setup ────────────────────────────────────────────────────────
BACKEND_CALLBACK_URL = "http://localhost:8000/auth/google/callback"
google_sso = GoogleSSO(
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    redirect_uri=BACKEND_CALLBACK_URL,
    allow_insecure_http=True,
)


# ─── Routes ──────────────────────────────────────────────────────────────────
@app.get("/auth/google/login")
async def login():
    async with google_sso:
        return await google_sso.get_login_redirect(
            params={"prompt": "consent", "access_type": "offline"}
        )


@app.get("/auth/google/callback")
async def auth_callback(request: Request):
    async with google_sso:
        sso_user = await google_sso.verify_and_process(request)

    now = datetime.now(timezone.utc)
    user = await engine.find_one(User, User.google_id == sso_user.id)

    if user:
        user.email = sso_user.email
        user.name = sso_user.display_name
        user.avatar_url = sso_user.picture
        user.last_login = now
        await engine.save(user)
    else:
        user = User(
            google_id=sso_user.id,
            email=sso_user.email,
            name=sso_user.display_name,
            avatar_url=sso_user.picture,
            last_login=now,
        )
        await engine.save(user)

    subject_data = {"id": str(user.id)}
    access_token = access_security.create_access_token(subject=subject_data)
    refresh_token = refresh_security.create_refresh_token(subject=subject_data)

    response = RedirectResponse(FRONTEND_URL)
    # ← Here's the crucial addition: path="/"
    response.set_cookie(
        "access_token_cookie",
        access_token,
        httponly=True,
        secure=False,  # set to True in production
        samesite="strict",
        path="/",
    )
    response.set_cookie(
        "refresh_token_cookie",
        refresh_token,
        httponly=True,
        secure=False,  # set to True in production
        samesite="strict",
        path="/",
    )
    return response


@app.post("/auth/refresh")
def refresh(
    response: Response,
    creds: JwtAuthorizationCredentials = Security(refresh_security),
):
    if not creds or not isinstance(creds.subject, dict):
        raise HTTPException(401, "Invalid refresh token")

    new_access = access_security.create_access_token(subject=creds.subject)
    json_resp = JSONResponse({"msg": "Access token refreshed"})
    json_resp.set_cookie(
        "access_token_cookie",
        new_access,
        httponly=True,
        secure=False,  # set to True in production
        samesite="strict",
        path="/",
    )
    return json_resp


@app.post("/auth/logout")
def logout():
    resp = JSONResponse({"msg": "Logged out"})
    # Also clear on the root path
    resp.delete_cookie("access_token_cookie", path="/")
    resp.delete_cookie("refresh_token_cookie", path="/")
    return resp


@app.get("/api/user", response_model=Optional[User])
async def get_current_user(
    creds: JwtAuthorizationCredentials = Security(access_security),
):
    if not creds or not isinstance(creds.subject, dict) or "id" not in creds.subject:
        return None
    try:
        user_id = ObjectId(creds.subject["id"])
    except:
        return None
    return await engine.find_one(User, User.id == user_id)


@app.get("/api/protected")
async def protected(
    creds: JwtAuthorizationCredentials = Security(access_security),
):
    if not creds or not creds.subject:
        raise HTTPException(401, "Not authenticated")
    return {"msg": "🎉 You're authenticated!"}


@app.get("/auth/token-info")
async def token_info(
    request: Request,
    creds: JwtAuthorizationCredentials = Security(access_security),
):
    """
    Returns the raw access_token cookie and its decoded payload.
    """
    # 1. Read the raw token from the cookie name we set earlier:
    raw_token = request.cookies.get("access_token_cookie")
    if not raw_token:
        raise HTTPException(401, "No access_token cookie found")

    # 2. Decode & verify (will raise if signature/expiry invalid)
    try:
        decoded = jwt.decode(
            raw_token, SECRET_KEY, algorithms=["HS256"], options={"require_exp": True}
        )
    except jwt.PyJWTError as e:
        raise HTTPException(401, f"Invalid token: {e}")

    # 3. Return for your front-end debug panel
    return {
        "raw_token": raw_token,
        "decoded_payload": decoded,
    }
