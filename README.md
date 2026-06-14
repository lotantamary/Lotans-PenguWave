# PenguWave: Security Operations Portal

**Track A (Backend).** A real, secure backend for PenguWave, with the existing React frontend wired to it end-to-end — built around one realization the starter was designed to test.

---

## The realization: the starter was an attack tool, not just an unfinished app

PenguWave looked like a half-built security dashboard. It wasn't just unfinished — it was **dangerous**.

The starter would take attacker-controlled data from the very events an analyst is meant to triage and **execute it**:

- A malicious event description (e.g. `evt-052`: `<img src=x onerror=alert(document.cookie)>`) ran as **live JavaScript in the analyst's browser** — because `sanitizeHtml()` was a fake (`return input`) feeding `dangerouslySetInnerHTML`.
- The session token sat in `localStorage`, where that injected script could **steal it and impersonate the analyst**.
- The CSV export path left **spreadsheet-formula payloads** (`=HYPERLINK(...)`, `+cmd|...`) intact, so opening an exported report could run commands in Excel.

In other words, **the tool built to investigate attacks was itself a delivery mechanism for them** — open the wrong event and the SOC analyst becomes the victim.

So the real task was not "add a backend." It was to **recognize that the given product was effectively weaponized, prove it, and make it safe.** This repo does that: it hardens every one of those holes and goes a step further — the backend now *detects* the attacks hidden in its own data ([threat-aware ingestion](#signature-feature-threat-aware-ingestion)).

---

## Quickstart

```bash
npm install
npm run server   # backend on http://localhost:3001 (seeds SQLite on first run)
npm run dev      # frontend on http://localhost:5173 (proxies /api to the backend)
```

Open http://localhost:5173 and log in.

| Email | Password | Role | Status |
| --- | --- | --- | --- |
| admin@penguwave.io | `admin-demo-pw` | admin | active |
| analyst@penguwave.io | `analyst-demo-pw` | analyst | active |
| viewer@penguwave.io | `viewer-demo-pw` | viewer | disabled |

Local throwaway logins only (overridable via `SEED_*_PW` env vars) — **not secrets**. No real credentials, keys, or `.env` files are committed.

---

## The vulnerabilities I found — and how I fixed them

| # | Vulnerability in the starter | Why it's dangerous | Fix |
| --- | --- | --- | --- |
| 1 | Fake `sanitizeHtml()` + `dangerouslySetInnerHTML` (+ a reflected-XSS search box) | Stored & reflected **XSS**: attacker data runs in the analyst's browser | Real **DOMPurify** sanitization; search term renders as plain text |
| 2 | Auth token in `localStorage` | The XSS above can **steal the session** and impersonate the analyst | **httpOnly + SameSite cookie** — JavaScript cannot read it |
| 3 | Client-side `isAdmin()`, no route guard | Anyone can edit a localStorage value and become "admin" | **Server-side** `requireAuth` / `requireAdmin`; non-admins get `403` |
| 4 | CSV export with no escaping | **Formula injection** runs commands when opened in Excel/Sheets | Escape leading `= + - @`, quote special chars |
| 5 | Hardcoded `pw_live_sk_...` secret in source | A committed secret is a real incident | Removed; `.gitignore` covers `.env` / `*.db` |
| 6 | Plaintext passwords stored, shown, and logged | Credential exposure | **bcrypt**-hashed, never returned by the API, never logged |
| 7 | Login "succeeded" even on failure | No real authentication boundary | Real credential check; disabled accounts blocked |

## Security decisions and tradeoffs

- **httpOnly cookie instead of a JSON token** (a documented deviation the contract allows). This is the single change that breaks the **XSS → token-theft chain**.
- **Enumeration-safe login:** bad credentials and disabled accounts return the same generic `401`, so login never reveals which emails exist or whether a password was right. Account status is re-checked on every request, so **disabling a user kills their existing sessions immediately**.
- **Sessions expire after 8 hours** and are stored server-side (revocable), not self-contained tokens.
- **SQLite** for zero-config persistence that survives restarts and is easy to reason about.

### Signature feature: threat-aware ingestion

The backend turns the planted attack data into a capability: on ingest it scans every event for embedded payloads (XSS, spreadsheet-formula) and stores `threatFlags`, so the UI badges hostile events ⚠. The system that stores security events now **recognizes the attacks hidden inside them** — exactly what a security product should do with untrusted input.

## Demo (5-minute presentation)

1. **The wall of findings** — the table above: proof I reviewed the starter, not just built on top of it.
2. **Live exploit (original starter):** open `evt-052` (or type `<img src=x onerror=alert(1)>` into search) → a JavaScript `alert` fires. The tool executes attacker data.
3. **The chain:** that token lived in `localStorage`, so the XSS could steal it and impersonate a user — a frontend bug defeating authentication.
4. **The fix (this repo):** the same `evt-052` renders inert (`<img src="x">`), the session is an httpOnly cookie the script can't read, the event is auto-flagged ⚠, and a `viewer`/`analyst` hitting `/api/users` gets a server-side `403`.

---

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

```
server/
  index.ts          bootstrap (open db, seed, listen :3001)
  app.ts            buildApp(db): middleware + routers + error handler
  db.ts             SQLite schema (users, events, sessions)
  seed.ts           idempotent seed + threat scan on ingest
  threat.ts         scanForThreats(): XSS / formula-injection detection
  auth.ts           bcrypt verify, sessions, httpOnly cookie, RBAC middleware
  validation.ts     zod schemas      errors.ts  ApiError + central handler
  routes/           auth.routes.ts, events.routes.ts, users.routes.ts
  __tests__/        Supertest integration suites
src/
  api.ts            cookie-based API client (no token, no secret)
  auth/AuthContext.tsx   auth state from /api/auth/me
  utils.ts          real sanitizeHtml (DOMPurify) + injection-safe toCsv
  pages/, components/    Events + Users pages, login, navbar (wired to the API)
```

## Tests

```bash
npm run test:server   # 43 tests (Vitest + Supertest)
```

Covers login & enumeration-safety, server-side RBAC (`403` for non-admins), passwords never returned, **mid-session disable**, and threat-flag detection.

## How this was delivered

Work was done on a branch (`feat/secure-backend`), in small, clearly-described commits, opened as a Pull Request and merged into `main` — so `main` holds the finished, reviewed work. No secrets are committed.

## With more time

- CSRF tokens (defense-in-depth alongside SameSite) and login rate limiting / lockout.
- Session refresh/rotation and a server-side revocation UI.
- Pagination and indexing on `/api/events`; an audit log of auth and authorization-denial events.
- Broader test coverage (single-event endpoint, formula-injection flag, TTL expiry) and a browser E2E test.
- A **repo-scanner** extension — generalize the threat scanner to audit any codebase for these same classes of flaw.
