# StudyAI — Local Auth Backend

Real login/signup that actually works. No frameworks, no npm install, no external services.

---

## File structure

```
studyai/
├── server.js          ← Node backend (auth routes + static server)
├── package.json
├── README.md
├── data/
│   └── users.json     ← Created automatically on first signup
└── public/
    └── index.html     ← Your site, wired to the auth API
```

---

## Requirements

- **Node.js 18+** (uses `crypto.randomUUID`, `crypto.scryptSync`, native `fetch` in tests)
- No npm install needed — only Node built-ins are used

---

## How to run

```bash
# From the studyai/ directory:
node server.js

# Or with auto-restart on file changes (Node 18+):
node --watch server.js
```

Open **http://localhost:3000** in your browser.

---

## Auth API

| Method | Path                 | Body / notes                              |
|--------|----------------------|-------------------------------------------|
| POST   | `/api/auth/signup`   | `{ name, email, password }` → sets cookie |
| POST   | `/api/auth/login`    | `{ email, password }` → sets cookie       |
| POST   | `/api/auth/logout`   | Clears cookie, destroys session           |
| GET    | `/api/auth/me`       | Returns `{ user }` or 401                 |

---

## What's real

- **Passwords** — hashed with `scrypt` + random salt. Never stored in plain text.
- **Sessions** — 64-byte random token stored in an `HttpOnly` cookie. Sessions live 7 days.
- **User DB** — `data/users.json` created at runtime; survives server restarts.
- **Auth guard** — Clicking any dashboard button while logged out redirects to the auth page.
- **Session persistence** — A page refresh hits `/api/auth/me`; if the cookie is valid you skip the login screen entirely.
- **Sidebar logout** — Real `POST /api/auth/logout` call that clears the cookie and resets the UI.
- **User data in UI** — After login, your real name and email appear in the sidebar, the greeting, and the settings panel.

---

## What's intentionally left out (and how to add it)

| Feature | How to add |
|---|---|
| HTTPS | Put Caddy or nginx in front and proxy to port 3000 |
| Email verification | Add a `verified` field to the user; send a token via Nodemailer |
| Password reset | Store a time-limited reset token; email a link |
| Rate limiting | Track attempt counts per IP in a Map; reset hourly |
| Real database | Replace `loadJSON / saveJSON` with `pg` (Postgres) or Supabase client calls |
| OAuth (Google) | Add a `/api/auth/google` route using `passport-google-oauth20` |

---

## Ports & env

`PORT` defaults to `3000`. Override with `PORT=4000 node server.js`.

---

## Resetting all users

```bash
rm data/users.json
```

Sessions are in-memory and clear automatically on server restart.
