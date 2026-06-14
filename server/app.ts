import express from "express";
import cookieParser from "cookie-parser";
import type { Database } from "./db";
import { authRouter } from "./routes/auth.routes";
import { eventsRouter } from "./routes/events.routes";
import { usersRouter } from "./routes/users.routes";
import { notFound, errorHandler } from "./errors";

export function buildApp(db: InstanceType<typeof Database>) {
  const app = express();

  app.use(express.json());
  app.use(cookieParser());

  // Inject DB into every request
  app.use((req, _res, next) => {
    req.db = db;
    next();
  });

  // Mount routers
  app.use("/api/auth", authRouter);
  app.use("/api/events", eventsRouter);
  app.use("/api/users", usersRouter);

  // 404 and error handling must come last
  app.use(notFound);
  app.use(errorHandler);

  return app;
}
