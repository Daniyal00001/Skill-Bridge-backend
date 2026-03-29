/**
 * browseFreelancers.routes.ts
 * location: backend/src/modules/browse-freelancers/browseFreelancers.routes.ts
 *
 * In app.ts: app.use("/api/browse", browseFreelancersRouter)
 *
 * GET /api/browse/freelancers
 * Query params:
 *   sort            = best_match | top_rated | most_experienced | lowest_rate | highest_rate | recently_active
 *   cursor          = freelancer profile ID (pagination)
 *   search          = string (name, tagline, bio)
 *   skills          = comma-separated: "React,Node.js"
 *   experienceLevel = ENTRY | MID | SENIOR | EXPERT
 *   availability    = AVAILABLE | BUSY | UNAVAILABLE
 *   hourlyRateMin   = number
 *   hourlyRateMax   = number
 *   location        = string
 *   region          = string (Asia, Europe, etc.)
 *   minRating       = number (1-5)
 *   hasPortfolio    = true
 *   isVerified      = true
 *   category        = category slug
 */

import { Router } from "express";
import { browseFreelancers } from "./browseFreelancers.controller";
import { requireAuth } from "../../middlewares/auth";
import { requireRole } from "../../middlewares/role";

const browseFreelancersRouter = Router();

browseFreelancersRouter.get(
  "/freelancers",
  requireAuth,
  requireRole("CLIENT"),
  browseFreelancers,
);

export default browseFreelancersRouter;
