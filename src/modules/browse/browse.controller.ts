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
import { getBrowseFeed } from "./browse.service";
import { BrowseFilters, SortOption } from "./browse.types";

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
