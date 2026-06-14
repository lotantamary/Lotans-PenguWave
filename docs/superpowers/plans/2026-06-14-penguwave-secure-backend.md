# PenguWave Secure Backend — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task (one fresh subagent per task, review between tasks). Steps use checkbox (`- [ ]`) syntax for tracking. Each task is TDD: write a failing test, implement, pass, commit.

**Goal:** Build a real, secure Express + TypeScript backend for PenguWave, wire the existing React UI to it, and neutralize the 7 planted security traps — anchored by two wow moments (XSS→token-theft defeated by httpOnly cookies; server-side RBAC) plus a "threat-aware ingestion" signature feature.

**Architecture:** Node + TypeScript Express server persisting to SQLite (`better-sqlite3`), seeded from `data/mock_events.json`. Sessions are opaque server-side tokens carried in an **httpOnly, SameSite cookie**. Every protected route checks auth + role server-side. Frontend talks to `/api` via a Vite dev proxy (same-origin cookies). Pure helpers (`sanitizeHtml`, `toCsv`) fixed with TDD.

**Tech Stack:** Express, better-sqlite3, bcryptjs, zod, cookie-parser, crypto · Vitest + Supertest · DOMPurify (frontend) · Vite proxy.

**Documented deviations from the contract** (contract says shapes are suggestions): httpOnly cookie instead of a JSON `token` (kills token theft); severity widened to include `CRITICAL`; `sourceIp`/`userId` nullable; `threatFlags: string[]` added to events.

**Reference:** Full design rationale in `docs/superpowers/specs/2026-06-14-penguwave-secure-backend-design.md` (esp. §6 trap→fix table, §7 RBAC matrix).

**Commit identity:** commit as Lotan Tamary with no Claude co-author trailer.

---

## File map (created/modified)

**Backend (new, `server/`):** `index.ts` (bootstrap), `app.ts` (`buildApp(db)`), `db.ts` (schema), `seed.ts` (idempotent seed + threat scan), `threat.ts` (scanner), `auth.ts` (hash/verify, sessions, cookie, `requireAuth`/`requireAdmin`), `validation.ts` (zod), `errors.ts` (ApiError + handler), `routes/{auth,events,users}.routes.ts`, `__tests__/*`.

**Frontend (modify):** `api.ts` (cookie client, no secret/token), `auth/AuthContext.tsx` (new), `App.tsx` + `main.tsx` (provider + guards), `components/{LoginModal,Navbar}.tsx`, `pages/{EventsPage,UsersPage}.tsx`, `utils.ts` (real sanitize + safe CSV), `types.ts`.

**Config:** `vite.config.ts` (proxy), `tsconfig.server.json`, `vitest.config.ts`, `.gitignore`, `package.json` (deps + scripts).

---

## Phase 0 — Setup

- [ ] **Task 0.1 — Dependencies & scripts.** Install runtime (`express`, `better-sqlite3`, `bcryptjs`, `zod`, `cookie-parser`, `dompurify`) and dev (`tsx`, `vitest`, `supertest`, types). Add scripts: `server`, `server:start`, `test:server`, `test:watch`. Commit.
- [ ] **Task 0.2 — Config files.** `tsconfig.server.json` (Node/ESNext, esModuleInterop, resolveJsonModule), `vitest.config.ts` (include `server/**/*.test.ts`, node env), Vite `/api`→`localhost:3001` proxy, `.gitignore` (`node_modules`, `dist`, `*.db`, `.env`). Commit.

## Phase 1 — Data layer & signature feature

- [ ] **Task 1.1 — Threat scanner (TDD).** `server/threat.ts`: `scanForThreats(event)` → `string[]`. Flags `xss` (script/`on*=`/`javascript:`/`<img onerror`) and `formula-injection` (cell starts with `= + - @`). **Tests:** flags `evt-052` payload as xss, `=HYPERLINK` and `+cmd|` as formula-injection, clean data → `[]`, null fields don't throw. Commit.
- [ ] **Task 1.2 — DB schema.** `server/db.ts`: `openDb(path)` + `initSchema` for `users` (id, email unique, role, status, password_hash), `events` (all fields + nullable sourceIp/userId + `threatFlags`), `sessions` (token, user_id FK, created_at). Commit.
- [ ] **Task 1.3 — Seed (idempotent).** `server/seed.ts`: seed 3 users (admin/active, analyst/active, viewer/**disabled**) with bcrypt-hashed demo passwords (overridable via env); seed events from `data/mock_events.json`, computing `threatFlags` per event and tolerating messy records (CRITICAL, nulls, 2099 ts, duplicate, missing id). `INSERT OR IGNORE` for idempotency. Commit.

## Phase 2 — Server core

- [ ] **Task 2.1 — Errors.** `server/errors.ts`: `ApiError(status, message)`, `notFound`, central `errorHandler` → consistent `{ error }` JSON. Commit.
- [ ] **Task 2.2 — Validation.** `server/validation.ts`: zod `loginSchema`, `createUserSchema` (email, password min 8, role enum), `updateUserSchema` (role and/or status). Commit.
- [ ] **Task 2.3 — Auth core.** `server/auth.ts`: bcrypt `verifyPassword`; `createSession`/`destroySession`/`userFromSession` (SQLite); `set/clearSessionCookie` (httpOnly, SameSite=lax); `requireAuth` (401) and `requireAdmin` (403) middleware; Express `req.user`/`req.db` augmentation. Commit.

## Phase 3 — Routes & app assembly

- [ ] **Task 3.1 — Auth routes.** `routes/auth.routes.ts`: `POST /login` (validate → verify → reject disabled with 403 → set cookie → return `{ user }`; same 401 message for bad email or password), `POST /logout` (destroy session + clear cookie), `GET /me` (`requireAuth` → `req.user`). Commit.
- [ ] **Task 3.2 — Events routes.** `routes/events.routes.ts`: `GET /` and `GET /:id` (both `requireAuth`; 404 on missing); parse `tags`/`threatFlags` JSON back to arrays. Commit.
- [ ] **Task 3.3 — Users routes.** `routes/users.routes.ts`: router-level `requireAuth` + `requireAdmin`; `GET /` (never selects password), `POST /` (validate, hash, 201), `PATCH /:id` (role/status, 404), `DELETE /:id` (404 if none). Commit.
- [ ] **Task 3.4 — App assembly.** `server/app.ts`: `buildApp(db)` → express.json, cookie-parser, DB-injection middleware, mount the three routers under `/api/*`, `notFound`, `errorHandler`. Commit.

## Phase 4 — Backend tests & bootstrap

- [ ] **Task 4.1 — Test helper.** `__tests__/helpers.ts`: `openDbInMemory()` → `openDb(':memory:')` + `seed`.
- [ ] **Task 4.2 — Auth + events integration tests (Supertest).** Bad creds→401; disabled viewer→403; active login→200 + `Set-Cookie` is `HttpOnly`; `/me` without session→401, with cookie→correct user; `/events` unauth→401, authed→non-empty array. Commit.
- [ ] **Task 4.3 — RBAC + users tests (the headline).** Unauth `/users`→401; analyst→403; admin→200 and **no `password`/`password_hash` in any row**; admin create→201 (no password back); short password→400; delete missing→404. Run full suite green. Commit.
- [ ] **Task 4.4 — Bootstrap.** `server/index.ts`: open db, seed, `buildApp`, listen on 3001. Verify boot + a `curl` login shows `Set-Cookie ... HttpOnly`. Commit.

## Phase 5 — Frontend wiring & security fixes

- [ ] **Task 5.1 — `utils.ts` (TDD).** Real `sanitizeHtml` via DOMPurify; `toCsv` escapes formula-injection (prefix `'`) and quotes commas/quotes/newlines; remove client `isAdmin`. **Tests:** sanitized output drops `onerror`/`<script`; CSV neutralizes `=`/`+` cells and quotes commas. Commit.
- [ ] **Task 5.2 — `types.ts`.** Widen `Severity` (+CRITICAL), nullable `timestamp`/`assetIp`/`sourceIp`/`userId`, add `threatFlags`, password-less `User`, `CurrentUser`. Commit.
- [ ] **Task 5.3 — `api.ts`.** Rewrite: relative `/api`, `credentials:"include"`, JSON error unwrap; functions for login/logout/me/events/users CRUD. No token, no hardcoded secret. Commit.
- [ ] **Task 5.4 — Auth context.** `auth/AuthContext.tsx`: `AuthProvider` fetches `/me` on mount; exposes `user`, `loading`, `login`, `logout`; `useAuth` hook. Commit.
- [ ] **Task 5.5 — App shell + guards.** `main.tsx` wraps with `AuthProvider`; `App.tsx` shows login when logged out, guards `/users` to admins, removes `DEBUG_BYPASS_AUTH`. Commit.
- [ ] **Task 5.6 — Login modal.** Real `login()`, inline error on failure (no auto-close-as-success), no `console.log`. Commit.
- [ ] **Task 5.7 — Navbar.** Show `email (role)` + real logout; Users link admin-only. Commit.

## Phase 6 — Pages on the real API

- [ ] **Task 6.1 — Events page.** Load via `getEvents`; loading/error/empty states; search renders as **plain text** (kills reflected XSS); detail description rendered through `sanitizeHtml`; CRITICAL severity color; **safe CSV export**; **⚠ threat badges** from `threatFlags`. Commit.
- [ ] **Task 6.2 — Users page.** API-backed list + create + delete; **no password column**; password input `type="password"`; error states. Commit.

## Phase 7 — Verification

- [ ] **Task 7.1 — Automated.** `npm run build` (tsc + vite) clean; `npm run lint` clean; `npm run test:server` all green; `npx vitest run src/utils.test.ts` green.
- [ ] **Task 7.2 — Manual E2E + traps-are-dead.** Login as each role (viewer refused); admin sees Users (no passwords), analyst redirected from `/users`; `evt-052` and search payload render inert (no alert); CSV cells inert in a spreadsheet; no `localStorage` token, `pw_session` cookie is HttpOnly; threat badges show; data survives a backend restart. Commit any fixes.

## Phase 8 — Docs, review, PR

- [ ] **Task 8.1 — README.** What was built, how to run (server + dev), demo credentials, architecture, the 7 findings→fixes table, documented deviations, signature feature, "with more time" (CSRF tokens, rate limiting, session expiry/refresh, pagination, audit log). Commit.
- [ ] **Task 8.2 — Review.** Run `security-review` / `superpowers:requesting-code-review` over the diff; fix findings; re-run build/lint/tests. Commit.
- [ ] **Task 8.3 — PR.** Via `superpowers:finishing-a-development-branch`: push `feat/secure-backend`, open PR (summary + findings table + decisions), merge to `main`.

---

## Priority if time runs short
Must-ship: Phases 0–4 (graded secure backend) + Phase 5–6 wiring. Next: threat badges (6.1) and review (8.2). Only cuttable piece: surfacing threat flags in the UI — detection itself (1.1) is cheap and stays in the backend.

## Build-order note
`app.ts` (3.4) imports the events/users routers — implement 3.1–3.3 before 3.4 and before the Phase 4 tests.
