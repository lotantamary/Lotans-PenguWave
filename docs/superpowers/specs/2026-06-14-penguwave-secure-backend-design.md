# PenguWave Secure Backend — Design / PRD

- **Author:** Lotan Tamary
- **Date:** 2026-06-14
- **Track:** A (Backend)
- **Time budget:** ~3 hours

---

## 1. Vision

Turn PenguWave from a frontend-only shell into a **real, secure security-operations
portal** with a working backend — and use the vulnerabilities planted in the starter as
the spine of the story: *find them, show how they hurt the client, fix them properly.*

PenguWave is the screen a security analyst uses to triage incoming security events. The
starter ships a polished React UI running on mock data with no backend, an API contract
describing the intended server, and a set of deliberately planted security traps. This
project builds the backend, wires the UI to it end-to-end, and neutralizes the traps.

**Why this stands out (the moat).** The graded Track-A checklist (real auth, sessions,
RBAC, validation, persistence) is what *every* backend submission will do — table stakes.
Our edge is the planted traps that live in the **frontend and the data**, where a
backend-only person never looks: the fake `sanitizeHtml` + the weaponized event payloads,
the `localStorage` token an XSS can steal, the client-side `isAdmin()`. We find them,
exploit them live, and fix them properly — and we turn the *finding* into a built feature
(threat-aware ingestion, §8). That combination — a working secure backend **plus** a live
exploit-and-defeat story in the language a security company speaks — is what makes this
unique rather than one more checklist backend.

## 2. Goals

- A correct, working backend implementing the API contract (`docs/api_contract.md`), with
  the existing UI wired to it end-to-end.
- Security done **right** so the planted attacks are neutralized: XSS, token theft, fake
  authorization, CSV/formula injection, committed secret, plaintext passwords, fake login.
- A presentation built around the trap findings, with 2–3 live deep-dives.

## 3. Non-goals (YAGNI)

- No rewrite of the frontend UI/design (that is Track B). We touch the frontend only to
  (a) connect it to the real backend and (b) fix the security seams (sanitization, cookie
  auth, safe export).
- No generic GitHub-repo vulnerability scanner.
- No multi-tenant support, real email, password reset, or rate-limiting infrastructure.
  These are noted as "with more time" talking points, not built.

## 4. Demo narrative (the product *is* the proof)

1. **Wall of findings** — one slide listing all 7 vulnerabilities found in the starter.
2. **Live shock** — open the *original* repo, "accidentally" hit a trap; a JS `alert`
   fires on screen.
3. **2–3 deep dives** — for each: *attack → client impact → my fix*, shown in the secured
   app:
   - XSS → token theft → httpOnly cookie fix
   - Fake authorization → server-side RBAC (`viewer`/`analyst` get `403`)
   - (optional third) CSV/formula injection, or the committed secret
4. **Close** — the working secured app, plus threat-aware ingestion flagging the attacks
   embedded in the event data.

Guardrails for the live exploit: rehearse the trigger so it fires on cue; keep the
"confused" act to ~20–30 seconds; have a screen-recording/screenshot fallback.

## 5. Functional requirements (from `docs/api_contract.md`)

- `POST /api/auth/login` — authenticate, start a session.
- `POST /api/auth/logout` — end the session.
- `GET /api/auth/me` — return the current user.
- `GET /api/events` — list events (authenticated).
- `GET /api/events/:id` — single event; `404` when missing.
- `GET /api/users` — list users (**admin only**); passwords never included.
- `POST /api/users` — create user (**admin only**).
- `PATCH /api/users/:id` — update role/status (**admin only**).
- `DELETE /api/users/:id` — delete user (**admin only**).
- Consistent JSON errors `{ "error": "..." }`; correct status codes
  (200 / 201 / 400 / 401 / 403 / 404 / 500).

## 6. Security requirements (each maps to a trap we fix)

| # | Trap (location in starter) | Fix |
|---|---|---|
| 1 | Fake `sanitizeHtml` returns input unchanged → XSS (`src/utils.ts:7`, sinks `src/pages/EventsPage.tsx:55,138`); live payload `data/mock_events.json:247` | Real sanitization (DOMPurify) on render; backend never serves executable content |
| 2 | Auth token in `localStorage`, stealable by XSS (`src/api.ts:14`, `src/components/LoginModal.tsx:23`) | Session in an **httpOnly, SameSite** cookie — JS cannot read it |
| 3 | Client-side `isAdmin()` trusts editable `localStorage`; no route guard (`src/utils.ts:25`, `src/pages/UsersPage.tsx:5`) | **Server-side** role checks on every protected route |
| 4 | CSV/formula injection in export — no escaping of leading `= + - @` (`src/utils.ts:15`); payloads `data/mock_events.json:423,645` | Escape dangerous leading characters on export |
| 5 | Hardcoded `pw_live_sk_...` secret in source (`src/api.ts:4`) | Removed; no secrets in repo; `.gitignore` + env |
| 6 | Plaintext passwords stored, displayed, and logged (`src/pages/UsersPage.tsx:9,110,68`; `src/api.ts:7`) | **bcrypt** hashing; never returned by the API; never logged |
| 7 | Login "succeeds" even on failure (`src/components/LoginModal.tsx:25`) | Real credential check; disabled users cannot log in |

## 7. Roles & permissions

| Capability | admin | analyst | viewer |
|---|---|---|---|
| Log in | yes | yes | no (seeded `disabled` → proves disabled-account block) |
| Read events | yes | yes | yes |
| Manage users | yes | no (`403`) | no (`403`) |

## 8. Signature feature — threat-aware ingestion (bonus; build only after core is flawless)

On seeding/ingest, the backend scans each event's text fields for attack signatures
(HTML/JS such as `onerror=`, spreadsheet formulas such as `=HYPERLINK`, command strings
such as `+cmd|`) and stores a `threatFlags` array on the event. The API serves it so the
UI can badge `evt-052 / evt-053 / evt-054` as *"contains embedded attack payload."* This
turns the traps we *found* into a capability we *built*, and is exactly the kind of
detection a security product should perform on untrusted input.

## 9. Architecture & stack

```
React UI ──httpOnly cookie──▶ Express (Node + TypeScript)
                               ├─ auth (bcrypt, cookie session)
                               ├─ RBAC middleware (server-side)
                               ├─ zod validation + central error handler
                               ├─ threat-aware ingestion
                               └─ better-sqlite3 ──▶ penguwave.db (survives restart)
                                          ▲ seeded from data/mock_events.json
```

**Stack:** Node + TypeScript + Express + zod (input validation) + better-sqlite3
(persistence, zero-config) + bcryptjs (password hashing) + httpOnly cookies (sessions).
Vite dev proxy forwards `/api` to the backend so cookies are same-origin.

Rationale: same language as the frontend (less friction, reuse types), and every piece is
simple enough to explain and own line-by-line — which is the assignment's top criterion.

## 10. Data & persistence

SQLite file (`penguwave.db`). Tables:

- `users` — id, email, role, status, **bcrypt password hash**.
- `events` — all contract fields plus `threatFlags`.
- `sessions` (or signed cookie) — session token → user.

Seeded on first run from `data/mock_events.json`; seeding is idempotent. Ingestion handles
the messy records gracefully: `CRITICAL` severity (not in the original type union), `null`
`sourceIp`/`userId`, the `2099` timestamp, empty descriptions, and the duplicate event.

## 11. Deliverables

- Work on a branch (`feat/secure-backend`), not `main`.
- Small, clear commits with descriptive messages.
- A Pull Request opened when done, then merged into `main`.
- A README: how to run, what was built, key decisions, and the 7 findings.
- No secrets committed; `.gitignore` covers `.env`, `*.db`, `node_modules`.

## 12. Success criteria

- The app works end-to-end on the real backend (login → events → users by role).
- All 7 traps verifiably fixed; the two headline exploits (search-box XSS and event-detail
  XSS) no longer reproduce.
- Server-side RBAC enforced: `viewer`/`analyst` receive `403` on user-management routes.
- Data survives a restart.
- Clean git history and a clean PR.

## 13. Risks & mitigations

- **Time overrun** — core (Sections 5–7) is the only must-ship; the signature feature
  (Section 8) is cut first if time is short.
- **Live-demo failure** — rehearse; keep a recording fallback.
- **Frontend/backend cookie issues** — use the Vite dev proxy so requests are same-origin.

## 14. Execution plan (superpower skills)

1. `writing-plans` — turn this PRD into a detailed, phased, testable implementation plan.
2. `using-git-worktrees` — isolated branch `feat/secure-backend` (already created).
3. `test-driven-development` — failing test → pass, for each endpoint and each security
   fix (e.g. "viewer gets 403", "XSS payload neutralized", "disabled user cannot log in").
4. `executing-plans` — work the plan in checkpoints with review.
5. `security-review` + `requesting-code-review` — adversarial pass over the diff.
6. `verification-before-completion` — run everything; confirm exploits no longer fire.
7. `finishing-a-development-branch` — open the PR, merge to `main`.
