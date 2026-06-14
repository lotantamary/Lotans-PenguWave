import { describe, it, expect, beforeEach } from "vitest";
import request from "supertest";
import { buildApp } from "../app";
import { openDbInMemory } from "./helpers";

describe("Auth & Events integration", () => {
  let app: ReturnType<typeof buildApp>;

  beforeEach(() => {
    app = buildApp(openDbInMemory());
  });

  // ── Login failures ──────────────────────────────────────────────────────────

  it("POST /api/auth/login wrong password → 401 with generic error", async () => {
    const res = await request(app)
      .post("/api/auth/login")
      .send({ email: "admin@penguwave.io", password: "wrong-password" });

    expect(res.status).toBe(401);
    expect(res.body.error).toBe("Invalid email or password");
  });

  it("POST /api/auth/login disabled viewer (correct password) → 401 generic (enumeration-safe)", async () => {
    const res = await request(app)
      .post("/api/auth/login")
      .send({ email: "viewer@penguwave.io", password: "viewer-demo-pw" });

    expect(res.status).toBe(401);
    expect(res.body.error).toBe("Invalid email or password");
  });

  // ── Successful login ────────────────────────────────────────────────────────

  it("POST /api/auth/login admin correct → 200, user.email, HttpOnly cookie", async () => {
    const res = await request(app)
      .post("/api/auth/login")
      .send({ email: "admin@penguwave.io", password: "admin-demo-pw" });

    expect(res.status).toBe(200);
    expect(res.body.user.email).toBe("admin@penguwave.io");

    const setCookie: string | string[] | undefined = res.headers["set-cookie"];
    const cookieStr = Array.isArray(setCookie) ? setCookie.join("; ") : setCookie ?? "";
    expect(cookieStr.toLowerCase()).toContain("httponly");
  });

  // ── /me without session ─────────────────────────────────────────────────────

  it("GET /api/auth/me without a session → 401", async () => {
    const res = await request(app).get("/api/auth/me");
    expect(res.status).toBe(401);
  });

  // ── /me after login ─────────────────────────────────────────────────────────

  it("GET /api/auth/me after logging in → 200, correct role", async () => {
    const agent = request.agent(app);

    await agent
      .post("/api/auth/login")
      .send({ email: "analyst@penguwave.io", password: "analyst-demo-pw" });

    const me = await agent.get("/api/auth/me");
    expect(me.status).toBe(200);
    expect(me.body.role).toBe("analyst");
    expect(me.body.email).toBe("analyst@penguwave.io");
  });

  // ── Logout invalidates session ──────────────────────────────────────────────

  it("POST /api/auth/logout then GET /api/auth/me → 401", async () => {
    const agent = request.agent(app);

    await agent
      .post("/api/auth/login")
      .send({ email: "admin@penguwave.io", password: "admin-demo-pw" });

    await agent.post("/api/auth/logout");

    const me = await agent.get("/api/auth/me");
    expect(me.status).toBe(401);
  });

  // ── Events: unauthenticated ─────────────────────────────────────────────────

  it("GET /api/events unauthenticated → 401", async () => {
    const res = await request(app).get("/api/events");
    expect(res.status).toBe(401);
  });

  // ── Events: authenticated ────────────────────────────────────────────────────

  it("GET /api/events authenticated → 200, array, length 59", async () => {
    const agent = request.agent(app);

    await agent
      .post("/api/auth/login")
      .send({ email: "analyst@penguwave.io", password: "analyst-demo-pw" });

    const res = await agent.get("/api/events");
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
    expect(res.body.length).toBe(59);
  });

  it("GET /api/events authenticated → at least one event has threatFlags containing 'xss'", async () => {
    const agent = request.agent(app);

    await agent
      .post("/api/auth/login")
      .send({ email: "analyst@penguwave.io", password: "analyst-demo-pw" });

    const res = await agent.get("/api/events");
    expect(res.status).toBe(200);

    const hasXss = res.body.some(
      (evt: { threatFlags: unknown[] }) =>
        Array.isArray(evt.threatFlags) && evt.threatFlags.includes("xss")
    );
    expect(hasXss).toBe(true);
  });
});
