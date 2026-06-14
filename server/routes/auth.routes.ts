import { Router } from "express";
import { loginSchema } from "../validation";
import {
  SESSION_COOKIE,
  verifyPassword,
  createSession,
  destroySession,
  setSessionCookie,
  clearSessionCookie,
  requireAuth,
} from "../auth";
import { ApiError } from "../errors";

export const authRouter = Router();

// POST /api/auth/login
authRouter.post("/login", (req, res) => {
  const result = loginSchema.safeParse(req.body);
  if (!result.success) {
    throw new ApiError(400, "Invalid request body");
  }

  const { email, password } = result.data;

  const row = req.db
    .prepare<
      [string],
      {
        id: string;
        email: string;
        role: string;
        status: string;
        password_hash: string;
      }
    >(
      "SELECT id, email, role, status, password_hash FROM users WHERE email = ?"
    )
    .get(email);

  // Account-enumeration safe: same message for missing user and wrong password
  if (!row || !verifyPassword(password, row.password_hash)) {
    throw new ApiError(401, "Invalid email or password");
  }

  if (row.status !== "active") {
    throw new ApiError(403, "Account is disabled");
  }

  const token = createSession(req.db, row.id);
  setSessionCookie(res, token);

  res.status(200).json({ user: { id: row.id, email: row.email, role: row.role } });
});

// POST /api/auth/logout
authRouter.post("/logout", (req, res) => {
  const token: string | undefined = req.cookies?.[SESSION_COOKIE];
  if (token) {
    destroySession(req.db, token);
  }
  clearSessionCookie(res);
  res.status(200).json({ message: "Logged out" });
});

// GET /api/auth/me
authRouter.get("/me", requireAuth, (req, res) => {
  res.json(req.user);
});
