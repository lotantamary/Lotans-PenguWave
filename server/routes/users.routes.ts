import crypto from "crypto";
import { Router } from "express";
import bcrypt from "bcryptjs";
import { requireAuth, requireAdmin } from "../auth";
import { createUserSchema, updateUserSchema } from "../validation";
import { ApiError } from "../errors";

export const usersRouter = Router();

// All users routes require auth + admin
usersRouter.use(requireAuth, requireAdmin);

// Column list — never includes password_hash
const USER_COLUMNS = "id, email, role, status";

interface UserRow {
  id: string;
  email: string;
  role: string;
  status: string;
}

// GET /api/users
usersRouter.get("/", (req, res) => {
  const rows = req.db
    .prepare<[], UserRow>(`SELECT ${USER_COLUMNS} FROM users`)
    .all();
  res.status(200).json(rows);
});

// POST /api/users
usersRouter.post("/", (req, res) => {
  const result = createUserSchema.safeParse(req.body);
  if (!result.success) {
    const firstMessage = result.error.issues[0]?.message ?? "Invalid body";
    throw new ApiError(400, firstMessage);
  }

  const { email, password, role } = result.data;

  // Check for duplicate email
  const existing = req.db
    .prepare<[string], { id: string }>("SELECT id FROM users WHERE email = ?")
    .get(email);
  if (existing) {
    throw new ApiError(400, "Email already in use");
  }

  const id = `usr-${crypto.randomBytes(4).toString("hex")}`;
  const password_hash = bcrypt.hashSync(password, 10);

  req.db
    .prepare<{
      id: string;
      email: string;
      role: string;
      status: string;
      password_hash: string;
    }>(
      "INSERT INTO users (id, email, role, status, password_hash) VALUES (@id, @email, @role, @status, @password_hash)"
    )
    .run({ id, email, role, status: "active", password_hash });

  const created = req.db
    .prepare<[string], UserRow>(`SELECT ${USER_COLUMNS} FROM users WHERE id = ?`)
    .get(id) as UserRow;

  res.status(201).json(created);
});

// PATCH /api/users/:id
usersRouter.patch("/:id", (req, res) => {
  const result = updateUserSchema.safeParse(req.body);
  if (!result.success) {
    const firstMessage = result.error.issues[0]?.message ?? "Invalid body";
    throw new ApiError(400, firstMessage);
  }

  const user = req.db
    .prepare<[string], UserRow>(`SELECT ${USER_COLUMNS} FROM users WHERE id = ?`)
    .get(req.params.id);

  if (!user) {
    throw new ApiError(404, "User not found");
  }

  const { role, status } = result.data;

  if (role !== undefined) {
    req.db
      .prepare<[string, string]>("UPDATE users SET role = ? WHERE id = ?")
      .run(role, req.params.id);
  }
  if (status !== undefined) {
    req.db
      .prepare<[string, string]>("UPDATE users SET status = ? WHERE id = ?")
      .run(status, req.params.id);
  }

  const updated = req.db
    .prepare<[string], UserRow>(`SELECT ${USER_COLUMNS} FROM users WHERE id = ?`)
    .get(req.params.id) as UserRow;

  res.status(200).json(updated);
});

// DELETE /api/users/:id
usersRouter.delete("/:id", (req, res) => {
  const result = req.db
    .prepare<[string]>("DELETE FROM users WHERE id = ?")
    .run(req.params.id);

  if (result.changes === 0) {
    throw new ApiError(404, "User not found");
  }

  res.status(200).json({ message: "User deleted" });
});
