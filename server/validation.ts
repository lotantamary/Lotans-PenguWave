import { z } from "zod";

export const loginSchema = z.object({
  email: z.email(),
  password: z.string().min(1),
});

export const ROLES = ["admin", "analyst", "viewer"] as const;
export const STATUSES = ["active", "disabled"] as const;

export const createUserSchema = z.object({
  email: z.email(),
  password: z.string().min(8),
  role: z.enum(ROLES),
});

export const updateUserSchema = z
  .object({
    role: z.enum(ROLES).optional(),
    status: z.enum(STATUSES).optional(),
  })
  .refine((data) => data.role !== undefined || data.status !== undefined, {
    message: "At least one of role or status must be provided",
  });
