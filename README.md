# FastAPI Google SSO with JWT Cookies Example

This project demonstrates how to implement Google Sign-Sign-On (SSO) with FastAPI, using `fastapi-sso` and `fastapi-jwt` for handling authentication and JWT tokens stored in HttpOnly cookies.

## Setup

### 0. Prerequisites

- Python 3.10+
- MongoDB installed and running.

### 1. Google Cloud Console Configuration

1.  Navigate to the [Google Cloud Console](https://console.cloud.google.com/).
2.  Go to **APIs & Services** > **Credentials**.
3.  Click **Create Credentials** > **OAuth 2.0 Client ID**.
4.  Select **Web application** as the application type.
5.  Under **Authorized redirect URIs**, add `http://localhost:8000/auth/google/callback`.
6.  Click **Create**.
7.  Copy the **Client ID** and **Client Secret**.

### 2. Environment Variables

Create a `.env` file in the project root and add the following variables, replacing the placeholders with your actual credentials:

```env
GOOGLE_CLIENT_ID=YOUR_GOOGLE_CLIENT_ID
GOOGLE_CLIENT_SECRET=YOUR_GOOGLE_CLIENT_SECRET
FRONTEND_URL=http://localhost:9999 # Or your frontend's URL
MONGO_URL=mongodb://localhost:27017 # Or your MongoDB connection string
DB_NAME=fastapi_sso_demo
JWT_SECRET_KEY=a_very_secret_key # Change this to a strong, random secret
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the Application

#### Backend

```bash
uvicorn main:app --reload --port 8000
```

The backend server will be running at `http://localhost:8000`.

#### Frontend (Simple Test Server)

If you don't have a separate frontend setup, you can serve a simple `index.html` (or similar) using Python's built-in server from the directory containing your frontend files:

```bash
# Navigate to your frontend directory first if needed
python -m http.server 9999
```

The frontend will be accessible at `http://localhost:9999` (matching the default `FRONTEND_URL` in `.env`).

## How it Works

1.  User clicks the login button on the frontend (e.g., at `FRONTEND_URL`).
2.  Frontend redirects the user to `/auth/google/login` on the backend.
3.  Backend redirects the user to Google's OAuth consent screen.
4.  User logs in and grants permission.
5.  Google redirects the user back to `/auth/google/callback` on the backend with an authorization code.
6.  Backend exchanges the code for Google access/refresh tokens and fetches user profile information (`fastapi-sso`).
7.  Backend finds or creates a user in the MongoDB database.
8.  Backend generates its own JWT access and refresh tokens (`fastapi-jwt`).
9.  Backend sets the JWT tokens as HttpOnly cookies (`access_token_cookie`, `refresh_token_cookie`) with `path=/` and redirects the user back to the `FRONTEND_URL`.
10. Frontend can now make authenticated requests to backend API endpoints (e.g., `/api/user`, `/api/protected`). The browser automatically includes the cookies.
11. Backend verifies the `access_token_cookie` on protected routes.
12. If the access token expires, the frontend can request a new one using the `refresh_token_cookie` via the `/auth/refresh` endpoint.
13. Logout (`/auth/logout`) clears the cookies.

## References

- [FastAPI Security - OAuth2 with JWT](https://fastapi.tiangolo.com/tutorial/security/oauth2-jwt/)
- [k4black/fastapi-jwt](https://github.com/k4black/fastapi-jwt) (Note: `fastapi-jwt-auth` is unmaintained and might cause conflicts with `fastapi-sso`)
