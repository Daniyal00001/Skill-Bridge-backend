/**
 * browse.routes.ts
 * ─────────────────────────────────────────────────────────────────
 * WHY SEPARATE ROUTES FILE: Route registration separate from controller.
 * Makes it easy to add middleware (auth, rate-limit) per-route.
 * In app.ts, just do: app.use("/api/browse", browseRouter)
 * ─────────────────────────────────────────────────────────────────
 */

import { Router } from "express";
import { 
  browseProjects, 
  toggleSaveProject, 
  getSavedProjects, 
  recordProjectView 
} from "./browse.controller";
import { protect, requireRole } from "../../middlewares/auth.middleware"; 

const browseRouter = Router();

// Feed
browseRouter.get(
  "/projects",
  protect,
  requireRole("FREELANCER"),
  browseProjects,
);

// Saved Projects
browseRouter.get(
  "/projects/saved",
  protect,
  requireRole("FREELANCER"),
  getSavedProjects
);

browseRouter.post(
  "/projects/:projectId/save",
  protect,
  requireRole("FREELANCER"),
  toggleSaveProject
);

// View Tracking
browseRouter.post(
  "/projects/:projectId/view",
  protect,
  requireRole("FREELANCER"),
  recordProjectView
);

export default browseRouter;
