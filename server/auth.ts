import crypto from "crypto";
import bcrypt from "bcryptjs";
import type { Request, Response, NextFunction } from "express";
import type { Database } from "./db";
import { ApiError } from "./errors";

// ─── Constants ───────────────────────────────────────────────────────────────

export const SESSION_COOKIE = "pw_session";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface SessionUser {
  id: string;
  email: string;
  role: string;
  status: string;
}

// Augment Express so req.user and req.db are typed throughout the server
declare global {
  namespace Express {
    interface Request {
      user?: SessionUser;
      db: InstanceType<typeof Database>;
    }
  }
}

// ─── Password ─────────────────────────────────────────────────────────────────

export function verifyPassword(plain: string, hash: string): boolean {
  return bcrypt.compareSync(plain, hash);
}

// ─── Session management ──────────────────────────────────────────────────────

export function createSession(
  db: InstanceType<typeof Database>,
  userId: string
): string {
  const token = crypto.randomBytes(32).toString("hex");
  const created_at = new Date().toISOString();
  db.prepare(
    "INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)"
  ).run(token, userId, created_at);
  return token;
}

export function destroySession(
  db: InstanceType<typeof Database>,
  token: string
): void {
  db.prepare("DELETE FROM sessions WHERE token = ?").run(token);
}

export function userFromSession(
  db: InstanceType<typeof Database>,
  token: string | undefined
): SessionUser | null {
  if (!token) return null;

  const row = db
    .prepare<[string], { id: string; email: string; role: string; status: string }>(
      `SELECT u.id, u.email, u.role, u.status
       FROM sessions s
       JOIN users u ON u.id = s.user_id
       WHERE s.token = ?`
    )
    .get(token);

  return row ?? null;
}

// ─── Cookie helpers ───────────────────────────────────────────────────────────

export function setSessionCookie(res: Response, token: string): void {
  res.cookie(SESSION_COOKIE, token, {
    httpOnly: true,
    sameSite: "lax",
    secure: false,
    path: "/",
  });
}

export function clearSessionCookie(res: Response): void {
  res.clearCookie(SESSION_COOKIE, { path: "/" });
}

// ─── Auth middleware ─────────────────────────────────────────────────────────

export function requireAuth(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  const token: string | undefined = req.cookies?.[SESSION_COOKIE];
  const user = userFromSession(req.db, token);
  if (!user) {
    throw new ApiError(401, "Authentication required");
  }
  req.user = user;
  next();
}

export function requireAdmin(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  if (req.user?.role !== "admin") {
    throw new ApiError(403, "Admin role required");
  }
  next();
}
