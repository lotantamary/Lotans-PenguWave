# PenguWave: Security Operations Portal

A security operations portal for triaging security events. This repo implements **Track A (Backend)**: a real, secure backend for PenguWave, with the existing React frontend wired to it end-to-end — and every security flaw planted in the starter found and fixed.

## What I built

- A **Node + TypeScript + Express** backend implementing the API in [`docs/api_contract.md`](./docs/api_contract.md): authentication, events, and admin-only user management.
- **Session auth via an httpOnly cookie** (not a token in `localStorage`), **server-side role enforcement** (admin / analyst / viewer), input validation, consistent JSON errors, and **SQLite persistence** that survives restarts.
- The frontend rewired to the real API, with the planted **security flaws fixed** (see findings below).
- **Threat-aware ingestion** (signature feature): on ingest, the backend scans every event for embedded attack payloads (XSS, spreadsheet/formula injection) and flags them, so the UI can warn analysts.
- **43 automated tests** (Vitest + Supertest) covering the security behavior — auth, RBAC, mid-session disable, and threat flags.

## Running it

Two processes (two terminals):

```bash
npm install
npm run server   # backend on http://localhost:3001 (seeds SQLite on first run)
npm run dev      # frontend on http://localhost:5173 (proxies /api to the backend)
```

Open http://localhost:5173 and log in.

### Demo credentials (local only — not secrets)

| Email | Password | Role | Status |
| --- | --- | --- | --- |
| admin@penguwave.io | `admin-demo-pw` | admin | active |
| analyst@penguwave.io | `analyst-demo-pw` | analyst | active |
| viewer@penguwave.io | `viewer-demo-pw` | viewer | disabled |

These are seeded throwaway dev logins (overridable via `SEED_ADMIN_PW` / `SEED_ANALYST_PW` / `SEED_VIEWER_PW`). They are not secrets; no real credentials, keys, or `.env` files are committed.

### Tests

```bash
npm run test:server   # 43 tests: backend (Supertest) + frontend unit tests
```

## Architecture

```
React UI ──httpOnly cookie──▶ Express (Node + TypeScript)  :3001
  (Vite proxies /api)          ├─ auth: bcrypt verify, server-side sessions, httpOnly cookie
                               ├─ RBAC middleware (requireAuth / requireAdmin)
                               ├─ zod validation + central error handler
                               ├─ threat-aware ingestion (scanForThreats)
                               └─ better-sqlite3 ──▶ penguwave.db (survives restart)
                                          ▲ seeded from data/mock_events.json
```

### Project structure

```
server/
  index.ts            bootstrap: open db, seed, listen :3001
  app.ts              buildApp(db): middleware + routers + error handler
  db.ts               SQLite schema (users, events, sessions)
  seed.ts             idempotent seed + threat scan on ingest
  threat.ts           scanForThreats(): XSS / formula-injection detection
  auth.ts             bcrypt verify, sessions, httpOnly cookie, requireAuth/requireAdmin
  validation.ts       zod schemas
  errors.ts           ApiError + central error handler
  routes/             auth.routes.ts, events.routes.ts, users.routes.ts
  __tests__/          Supertest integration suites
src/
  api.ts              cookie-based API client (no token, no secret)
  auth/AuthContext.tsx  auth state from /api/auth/me
  utils.ts            real sanitizeHtml (DOMPurify) + injection-safe toCsv
  pages/, components/   Events + Users pages, login, navbar (wired to the API)
```

## Security findings in the starter — and how I fixed them

The starter shipped with several planted vulnerabilities. I found and fixed all of them:

| # | Vulnerability (in the starter) | Fix |
| --- | --- | --- |
| 1 | `sanitizeHtml()` was a no-op (`return input`) and event descriptions were rendered with `dangerouslySetInnerHTML` → **stored XSS** (e.g. `evt-052`). The search box also rendered input as raw HTML → **reflected XSS**. | Real **DOMPurify** sanitization on the description; the search term now renders as plain text. |
| 2 | The auth **token was stored in `localStorage`**, readable by any script — so the XSS above could steal it and impersonate a user. | Session lives in an **httpOnly, SameSite cookie**; JavaScript (and any XSS) cannot read it. |
| 3 | Authorization was **client-side only** (`isAdmin()` trusted an editable `localStorage` value; the Users page had no guard). | **Server-side** `requireAuth` / `requireAdmin` on every protected route; non-admins get `403`. The UI guard is convenience only. |
| 4 | **CSV/formula injection**: exported cells starting with `= + - @` would execute in Excel/Sheets. | `toCsv` prefixes such cells with `'` and quotes values containing commas/quotes/newlines. |
| 5 | A **hardcoded secret** (`pw_live_sk_...`) was committed in `src/api.ts`. | Removed entirely; no secrets in the repo; `.gitignore` covers `.env` and the DB. |
| 6 | **Plaintext passwords** were stored, shown in the Users table, and `console.log`-ged. | Passwords are **bcrypt-hashed**, never returned by the API, never logged; the Users table has no password column. |
| 7 | Login **"succeeded" even on failure** (errors were swallowed and the modal closed). | Real credential check; failures show an inline error; disabled accounts cannot log in. |

## Key decisions and tradeoffs

- **httpOnly cookie instead of a JSON token.** The contract suggested returning a `token`; I deviated (the contract allows it) because a `localStorage` token is XSS-stealable. This is the single fix that breaks the XSS→token-theft chain.
- **Enumeration-safe login.** Bad credentials and disabled accounts both return the same generic `401`, so login never reveals which emails exist or whether a password was correct. Account-status is also enforced at the session layer, so **disabling a user invalidates their existing sessions immediately**.
- **Sessions expire after 8 hours** and are stored server-side (revocable), not as self-contained tokens.
- **Threat-aware ingestion** turns the planted attack data into a feature: the system that stores security events also recognizes attacks hidden inside them.
- **SQLite** for zero-config persistence that survives restarts and is easy to reason about.

## Demo (5-minute presentation)

A before/after that shows the security thinking, not just features:

1. **The wall of findings** — the 7 vulnerabilities table above: proof I reviewed the starter, not just built on top of it.
2. **Live exploit (original starter):** open `evt-052` (or type `<img src=x onerror=alert(1)>` into search) → a JavaScript `alert` fires. The no-op sanitizer + `dangerouslySetInnerHTML` made the app execute attacker data.
3. **The chain:** that token sat in `localStorage`, so the XSS could steal it and impersonate a user — a frontend bug defeating authentication.
4. **The fix (this repo):** the same `evt-052` now renders inert (`<img src="x">`, no `onerror`), the session is an httpOnly cookie the script can't read, and the event is auto-flagged ⚠ by threat-aware ingestion. A `viewer`/`analyst` hitting `/api/users` gets a server-side `403`.

## With more time

- CSRF tokens (defense-in-depth alongside SameSite), and login rate limiting / lockout.
- Session refresh/rotation and a server-side session revocation UI.
- Pagination and indexing on `/api/events` for large datasets.
- An audit log of auth events and authorization denials.
- Broader automated coverage (single-event endpoint, formula-injection flag, TTL expiry) and a browser E2E test.
- The optional repo-scanner extension sketched in `docs/superpowers/plans/` — generalize the threat scanner to audit any repo/codebase.
