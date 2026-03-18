/**
 * tracking.controller.ts
 * location: backend/src/controllers/tracking.controller.ts
 * ─────────────────────────────────────────────────────────────────
 * WHY A DEDICATED CONTROLLER:
 *   Frontend needs endpoints to fire tracking events:
 *   - POST /api/track/view      → jab card click karo
 *   - POST /api/track/save      → jab bookmark karo
 *   - DELETE /api/track/save    → jab unsave karo
 *   - POST /api/track/category  → jab category filter lagao
 *
 *   Apply tracking existing proposal.controller.ts mein hook hoga
 *   (wahan se trackProjectApply call karein after proposal create).
 *
 * ALL RESPONSES: 200 with minimal body.
 *   Frontend fire-and-forget karta hai — 4xx errors ignore karo.
 * ─────────────────────────────────────────────────────────────────
 */

import { Request, Response } from "express";
import { prisma } from "../config/prisma";
import {
  trackProjectView,
  trackProjectSave,
  trackProjectUnsave,
  trackCategoryClick,
} from "../services/tracking.service";

// ── POST /api/track/view ──────────────────────────────────────────
export const trackView = async (
  req: Request,
  res: Response
): Promise<void> => {
  const freelancerProfileId = (req as any).user?.freelancerProfileId;
  const { projectId, categorySlug } = req.body;

  if (!freelancerProfileId || !projectId) {
    res.status(400).json({ message: "Missing params" });
    return;
  }

  // Fire and forget — don't await, respond immediately
  trackProjectView(prisma, freelancerProfileId, projectId, categorySlug);
  res.json({ ok: true });
};

// ── POST /api/track/save ──────────────────────────────────────────
export const saveProject = async (
  req: Request,
  res: Response
): Promise<void> => {
  const freelancerProfileId = (req as any).user?.freelancerProfileId;
  const { projectId, categorySlug } = req.body;

  if (!freelancerProfileId || !projectId) {
    res.status(400).json({ message: "Missing params" });
    return;
  }

  const result = await trackProjectSave(
    prisma,
    freelancerProfileId,
    projectId,
    categorySlug
  );

  res.json(result);
};

// ── DELETE /api/track/save ────────────────────────────────────────
export const unsaveProject = async (
  req: Request,
  res: Response
): Promise<void> => {
  const freelancerProfileId = (req as any).user?.freelancerProfileId;
  const { projectId } = req.body;

  if (!freelancerProfileId || !projectId) {
    res.status(400).json({ message: "Missing params" });
    return;
  }

  await trackProjectUnsave(prisma, freelancerProfileId, projectId);
  res.json({ ok: true });
};

// ── POST /api/track/category ──────────────────────────────────────
export const trackCategory = async (
  req: Request,
  res: Response
): Promise<void> => {
  const freelancerProfileId = (req as any).user?.freelancerProfileId;
  const { categorySlug } = req.body;

  if (!freelancerProfileId || !categorySlug) {
    res.status(400).json({ message: "Missing params" });
    return;
  }

  trackCategoryClick(prisma, freelancerProfileId, categorySlug);
  res.json({ ok: true });
};