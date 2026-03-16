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

/**
 * GET /api/browse/projects
 *
 * Query params:
 *   sort          = best_match | newest | lowest_proposals | highest_budget | deadline_soon
 *   cursor        = project ID for pagination
 *   search        = string
 *   category      = category slug
 *   skills        = comma-separated skill names
 *   budgetMin     = number
 *   budgetMax     = number
 *   experienceLevel = ENTRY | MID | SENIOR | EXPERT
 *   size          = SMALL | MEDIUM | LARGE
 *   clientVerified = true | false
 *   isAiScoped    = true | false
 *   proposalCountMax = number
 *   location      = string
 */
browseRouter.get(
  "/projects",
  requireAuth,
  requireRole("FREELANCER"),
  browseProjects
);

export default browseRouter;