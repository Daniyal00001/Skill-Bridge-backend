/**
 * browseFreelancers.controller.ts
 * location: backend/src/modules/browse-freelancers/browseFreelancers.controller.ts
 *
 * HTTP layer only — parse, validate, call service, return.
 */

import { Request, Response } from "express";
import { prisma } from "../../config/prisma";
import { getBrowseFreelancersFeed } from "./browseFreelancers.service";
import {
  FreelancerBrowseFilters,
  FreelancerSortOption,
  VALID_FREELANCER_SORT_OPTIONS,
} from "./browseFreelancers.types";

const VALID_EXP_LEVELS = ["ENTRY", "MID", "SENIOR", "EXPERT"];
const VALID_AVAILABILITY = ["AVAILABLE", "BUSY", "UNAVAILABLE"];

export const browseFreelancers = async (
  req: Request,
  res: Response,
): Promise<void> => {
  try {
    // ── Auth ──────────────────────────────────────────────────
    const clientId = (req as any).user?.userId;
    if (!clientId) {
      res.status(401).json({ message: "Unauthorized" });
      return;
    }

    // ── Validate enums ────────────────────────────────────────
    const rawExpLevel = (req.query.experienceLevel as string)?.toUpperCase();
    const experienceLevel = VALID_EXP_LEVELS.includes(rawExpLevel)
      ? (rawExpLevel as any)
      : undefined;

    const rawAvailability = (req.query.availability as string)?.toUpperCase();
    const availability = VALID_AVAILABILITY.includes(rawAvailability)
      ? (rawAvailability as any)
      : undefined;

    // ── Validate sort ─────────────────────────────────────────
    const sort: FreelancerSortOption = VALID_FREELANCER_SORT_OPTIONS.includes(
      req.query.sort as FreelancerSortOption,
    )
      ? (req.query.sort as FreelancerSortOption)
      : "best_match";

    // ── Validate numbers ──────────────────────────────────────
    const hourlyRateMin = req.query.hourlyRateMin
      ? Number(req.query.hourlyRateMin)
      : undefined;
    const hourlyRateMax = req.query.hourlyRateMax
      ? Number(req.query.hourlyRateMax)
      : undefined;
    const minRating = req.query.minRating
      ? Math.min(Number(req.query.minRating), 5)
      : undefined;

    if (hourlyRateMin !== undefined && isNaN(hourlyRateMin)) {
      res.status(400).json({ message: "hourlyRateMin must be a number" });
      return;
    }
    if (hourlyRateMax !== undefined && isNaN(hourlyRateMax)) {
      res.status(400).json({ message: "hourlyRateMax must be a number" });
      return;
    }
    if (
      hourlyRateMin !== undefined &&
      hourlyRateMax !== undefined &&
      hourlyRateMin > hourlyRateMax
    ) {
      res
        .status(400)
        .json({ message: "hourlyRateMin cannot exceed hourlyRateMax" });
      return;
    }

    // ── Build filters ─────────────────────────────────────────
    const filters: FreelancerBrowseFilters = {
      search: req.query.search as string | undefined,
      skills: req.query.skills
        ? (req.query.skills as string)
            .split(",")
            .map((s) => s.trim())
            .filter(Boolean)
        : undefined,
      experienceLevel,
      availability,
      hourlyRateMin,
      hourlyRateMax,
      location: req.query.location as string | undefined,
      region: req.query.region as string | undefined,
      minRating,
      hasPortfolio: req.query.hasPortfolio === "true" ? true : undefined,
      isVerified: req.query.isVerified === "true" ? true : undefined,
      categorySlug: req.query.category as string | undefined,
    };

    const cursor = req.query.cursor as string | undefined;

    // ── Call service ──────────────────────────────────────────
    const result = await getBrowseFreelancersFeed(
      prisma,
      clientId,
      filters,
      sort,
      cursor,
    );

    res.json(result);
  } catch (err) {
    console.error("[BrowseFreelancersController] Error:", err);
    res.status(500).json({ message: "Failed to fetch freelancers" });
  }
};
