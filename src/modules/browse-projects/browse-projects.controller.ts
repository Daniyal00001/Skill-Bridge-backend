/**
 * browse.controller.ts
 * ─────────────────────────────────────────────────────────────────
 * WHY SEPARATE CONTROLLER: Controller = HTTP concerns only.
 * It parses request, validates params, calls service, formats response.
 * Zero business logic here — that's all in browse.service.ts.
 * ─────────────────────────────────────────────────────────────────
 */

import { Request, Response } from "express";
import { prisma } from "../../config/prisma"; // your existing Prisma instance
import { 
  getBrowseFeed, 
  toggleSaveProject as toggleSaveService,
  getSavedProjects as getSavedService,
  recordProjectInteraction
} from "./browse-projects.service";
import { BrowseFilters, SortOption, InteractionType } from "./browse-projects.types";

export const browseProjects = async (
  req: Request,
  res: Response,
): Promise<void> => {
  try {
    // ── Auth: freelancer ID from JWT middleware ─────────────────
    const freelancerId = (req as any).user?.userId;
    if (!freelancerId) {
      res.status(401).json({ message: "Unauthorized" });
      return;
    }

    // ── Parse filters from query string ────────────────────────
    const expLevelArr = ["ENTRY", "MID", "SENIOR", "EXPERT"];
    const sizeArr = ["SMALL", "MEDIUM", "LARGE"];
    const sortArr = [
      "best_match",
      "newest",
      "lowest_proposals",
      "highest_budget",
      "deadline_soon",
    ];

    const experienceLevel = expLevelArr.includes(
      (req.query.experienceLevel as string)?.toUpperCase(),
    )
      ? (req.query.experienceLevel as any).toUpperCase()
      : undefined;

    const size = sizeArr.includes((req.query.size as string)?.toUpperCase())
      ? (req.query.size as any).toUpperCase()
      : undefined;

    const sort = sortArr.includes(req.query.sort as string)
      ? (req.query.sort as SortOption)
      : "best_match";

    const filters: BrowseFilters = {
      search: req.query.search as string | undefined,
      categorySlug: req.query.category as string | undefined,
      skills: req.query.skills
        ? (req.query.skills as string).split(",")
        : undefined,
      budgetMin: req.query.budgetMin ? Number(req.query.budgetMin) : undefined,
      budgetMax: req.query.budgetMax ? Number(req.query.budgetMax) : undefined,
      experienceLevel,
      size,
      clientVerified: req.query.clientVerified === "true" ? true : undefined,
      proposalCountMax: req.query.proposalCountMax
        ? Number(req.query.proposalCountMax)
        : undefined,
      locationPref: req.query.location as string | undefined,
    };

    // Cursor-based pagination
    const cursor = req.query.cursor as string | undefined;

    // ── Call service ────────────────────────────────────────────
    const result = await getBrowseFeed(
      prisma,
      freelancerId,
      filters,
      sort,
      cursor,
    );

    res.json(result);
  } catch (err) {
    console.error("[BrowseController] Error:", err);
    res.status(500).json({ message: "Failed to fetch projects" });
  }
};

// ── Toggle Save Project ──────────────────────────────────────
export const toggleSaveProject = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId;
    const { projectId } = req.params;

    if (!userId) return res.status(401).json({ message: "Unauthorized" });

    const result = await toggleSaveService(prisma, userId, projectId);
    return res.status(200).json(result);
  } catch (error: any) {
    console.error("[BrowseController] ToggleSave Error:", error);
    return res.status(500).json({ message: error.message || "Internal server error" });
  }
};

// ── Get Saved Projects ──────────────────────────────────────
export const getSavedProjects = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId;
    if (!userId) return res.status(401).json({ message: "Unauthorized" });

    const projects = await getSavedService(prisma, userId);
    return res.status(200).json(projects);
  } catch (error: any) {
    console.error("[BrowseController] GetSaved Error:", error);
    return res.status(500).json({ message: error.message || "Internal server error" });
  }
};

// ── Record Project View ─────────────────────────────────────
export const recordProjectView = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId;
    const { projectId } = req.params;

    if (!userId) return res.status(401).json({ message: "Unauthorized" });

    await recordProjectInteraction(prisma, userId, projectId, "VIEW");
    return res.status(200).json({ success: true });
  } catch (error: any) {
    console.error("[BrowseController] RecordView Error:", error);
    return res.status(500).json({ message: error.message || "Internal server error" });
  }
};
