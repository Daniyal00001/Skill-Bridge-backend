/**
 * browse.routes.ts
 * ─────────────────────────────────────────────────────────────────
 * WHY SEPARATE ROUTES FILE: Route registration separate from controller.
 * Makes it easy to add middleware (auth, rate-limit) per-route.
 * In app.ts, just do: app.use("/api/browse", browseRouter)
 * ─────────────────────────────────────────────────────────────────
 */

import { Router } from "express";
import { browseProjects } from "./browse.controller";
import { requireAuth } from "../../middlewares/auth"; // your existing auth middleware
import { requireRole } from "../../middlewares/role"; // your existing role middleware

const browseRouter = Router();

browseRouter.get(
  "/projects",
  requireAuth,
  requireRole("FREELANCER"),
  browseProjects,
);

export default browseRouter;
