/**
 * tracking.routes.ts
 * location: backend/src/routes/tracking.routes.ts
 * ─────────────────────────────────────────────────────────────────
 * In app.ts: app.use("/api/track", trackingRouter)
 * ─────────────────────────────────────────────────────────────────
 */

import { Router } from "express";
import {
  trackView,
  saveProject,
  unsaveProject,
  trackCategory,
} from "../controllers/tracking.controller";
import { requireAuth } from "../middlewares/auth";
import { requireRole } from "../middlewares/role";

const trackingRouter = Router();

// All tracking routes require freelancer auth
trackingRouter.use(requireAuth, requireRole("FREELANCER"));

/**
 * POST /api/track/view
 * Body: { projectId: string, categorySlug?: string }
 */
trackingRouter.post("/view", trackView);

/**
 * POST /api/track/save
 * Body: { projectId: string, categorySlug?: string }
 * Returns: { saved: boolean, alreadySaved: boolean }
 */
trackingRouter.post("/save", saveProject);

/**
 * DELETE /api/track/save
 * Body: { projectId: string }
 */
trackingRouter.delete("/save", unsaveProject);

/**
 * POST /api/track/category
 * Body: { categorySlug: string }
 */
trackingRouter.post("/category", trackCategory);

export default trackingRouter;