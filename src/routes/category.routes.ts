// routes/category.routes.ts
import { Router } from "express";
import { prisma } from "../config/prisma";

const router = Router();

// GET /api/categories  →  all categories with their subcategories
router.get("/", async (req, res) => {
  console.log("categories and sub categories fetching route called");
  try {
    const categories = await prisma.category.findMany({
      include: { subCategories: { orderBy: { name: "asc" } } },
      orderBy: { name: "asc" },
    });
    res.json({ categories });
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch categories" });
  }
});

export default router;