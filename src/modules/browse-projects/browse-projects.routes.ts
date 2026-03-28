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
} from "./browse-projects.controller";
import { protect, requireRole } from "../../middlewares/auth.middleware"; 

const browseProjectsRouter = Router();

// Feed
browseProjectsRouter.get(
  "/projects",
  protect,
  requireRole("FREELANCER"),
  browseProjects,
);

// Saved Projects
browseProjectsRouter.get(
  "/projects/saved",
  protect,
  requireRole("FREELANCER"),
  getSavedProjects
);

browseProjectsRouter.post(
  "/projects/:projectId/save",
  protect,
  requireRole("FREELANCER"),
  toggleSaveProject
);

// View Tracking
browseProjectsRouter.post(
  "/projects/:projectId/view",
  protect,
  requireRole("FREELANCER"),
  recordProjectView
);

export default browseProjectsRouter;
