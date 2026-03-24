import { Request, Response } from "express";
import { prisma } from "../config/prisma";

export const getMetadata = async (req: Request, res: Response) => {
  try {
    const [languages, locations] = await Promise.all([
      prisma.language.findMany({
        orderBy: { name: "asc" },
      }),
      prisma.location.findMany({
        orderBy: { name: "asc" },
      }),
    ]);

    res.status(200).json({
      success: true,
      languages,
      locations,
    });
  } catch (error: any) {
    res.status(500).json({
      success: false,
      message: error.message || "Failed to fetch metadata",
    });
  }
};

export const getSkills = async (req: Request, res: Response) => {
  try {
    const { q } = req.query;
    let whereClause: any = {
      status: 'APPROVED'
    };
    if (q && typeof q === 'string' && q.trim().length > 0) {
      whereClause.name = {
        contains: q.trim(),
        mode: 'insensitive'
      };
    }
    const skills = await prisma.skill.findMany({
      where: whereClause,
      take: 20, // Return max 20 dropdown suggestions
      orderBy: { name: 'asc' }
    });

    res.status(200).json({ success: true, skills });
  } catch (error: any) {
    res.status(500).json({
      success: false,
      message: error.message || "Failed to fetch skills suggestions",
    });
  }
};
