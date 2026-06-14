import { describe, it, expect, beforeEach } from "vitest";
import request from "supertest";
import { buildApp } from "../app";
import { openDbInMemory } from "./helpers";

describe("Users RBAC & management integration", () => {
  let app: ReturnType<typeof buildApp>;

  beforeEach(() => {
    app = buildApp(openDbInMemory());
  });

  // Helper: return an agent already logged in as the given user
  async function loginAs(
    agent: ReturnType<typeof request.agent>,
    email: string,
    password: string
  ) {
    const res = await agent.post("/api/auth/login").send({ email, password });
    expect(res.status).toBe(200);
    return agent;
  }

  // ── Unauthenticated ─────────────────────────────────────────────────────────

  it("GET /api/users unauthenticated → 401", async () => {
    const res = await request(app).get("/api/users");
    expect(res.status).toBe(401);
  });

  // ── Analyst RBAC ────────────────────────────────────────────────────────────

  it("GET /api/users as analyst → 403", async () => {
    const agent = request.agent(app);
    await loginAs(agent, "analyst@penguwave.io", "analyst-demo-pw");

    const res = await agent.get("/api/users");
    expect(res.status).toBe(403);
  });

  // ── Admin: list users ───────────────────────────────────────────────────────

  it("GET /api/users as admin → 200; length 3; no password fields", async () => {
    const agent = request.agent(app);
    await loginAs(agent, "admin@penguwave.io", "admin-demo-pw");

    const res = await agent.get("/api/users");
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
    expect(res.body.length).toBe(3);

    for (const user of res.body) {
      expect(user).not.toHaveProperty("password");
      expect(user).not.toHaveProperty("password_hash");
    }
  });

  // ── Admin: create user ──────────────────────────────────────────────────────

  it("POST /api/users as admin (valid) → 201; no password field; appears in list", async () => {
    const agent = request.agent(app);
    await loginAs(agent, "admin@penguwave.io", "admin-demo-pw");

    const newUser = {
      email: "newuser@penguwave.io",
      password: "securepassword",
      role: "analyst",
    };

    const createRes = await agent.post("/api/users").send(newUser);
    expect(createRes.status).toBe(201);
    expect(createRes.body).not.toHaveProperty("password");
    expect(createRes.body).not.toHaveProperty("password_hash");
    expect(createRes.body.email).toBe(newUser.email);

    // Should now appear in list
    const listRes = await agent.get("/api/users");
    expect(listRes.status).toBe(200);
    expect(listRes.body.length).toBe(4);
    const found = listRes.body.some(
      (u: { email: string }) => u.email === newUser.email
    );
    expect(found).toBe(true);
  });

  it("POST /api/users with short password → 400", async () => {
    const agent = request.agent(app);
    await loginAs(agent, "admin@penguwave.io", "admin-demo-pw");

    const res = await agent.post("/api/users").send({
      email: "short@penguwave.io",
      password: "abc",
      role: "analyst",
    });

    expect(res.status).toBe(400);
  });

  it("POST /api/users duplicate email → 400", async () => {
    const agent = request.agent(app);
    await loginAs(agent, "admin@penguwave.io", "admin-demo-pw");

    const res = await agent.post("/api/users").send({
      email: "analyst@penguwave.io",
      password: "somevalidpassword",
      role: "analyst",
    });

    expect(res.status).toBe(400);
  });

  // ── PATCH / DELETE non-existent ─────────────────────────────────────────────

  it("PATCH /api/users/:id non-existent → 404", async () => {
    const agent = request.agent(app);
    await loginAs(agent, "admin@penguwave.io", "admin-demo-pw");

    const res = await agent
      .patch("/api/users/usr-does-not-exist")
      .send({ role: "analyst" });

    expect(res.status).toBe(404);
  });

  it("DELETE /api/users/:id non-existent → 404", async () => {
    const agent = request.agent(app);
    await loginAs(agent, "admin@penguwave.io", "admin-demo-pw");

    const res = await agent.delete("/api/users/usr-does-not-exist");
    expect(res.status).toBe(404);
  });

  // ── RBAC depth: mid-session disable ─────────────────────────────────────────

  it("After admin disables an active user, that user's existing session is rejected (mid-session disable)", async () => {
    const adminAgent = request.agent(app);
    await loginAs(adminAgent, "admin@penguwave.io", "admin-demo-pw");

    // Create a fresh user to disable
    const createRes = await adminAgent.post("/api/users").send({
      email: "target@penguwave.io",
      password: "targetpassword",
      role: "analyst",
    });
    expect(createRes.status).toBe(201);
    const targetId: string = createRes.body.id;

    // Log target user in and confirm they can reach /api/events
    const targetAgent = request.agent(app);
    await loginAs(targetAgent, "target@penguwave.io", "targetpassword");

    const eventsRes = await targetAgent.get("/api/events");
    expect(eventsRes.status).toBe(200);

    // Admin disables the target user
    const patchRes = await adminAgent
      .patch(`/api/users/${targetId}`)
      .send({ status: "disabled" });
    expect(patchRes.status).toBe(200);
    expect(patchRes.body.status).toBe("disabled");

    // The same target agent's session should now be rejected
    const eventsAfterDisable = await targetAgent.get("/api/events");
    expect(eventsAfterDisable.status).toBe(401);
  });
});
