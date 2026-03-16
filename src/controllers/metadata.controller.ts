import { Request, Response } from "express";
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

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
