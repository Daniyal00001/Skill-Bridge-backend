import { Request, Response } from 'express';
import { prisma } from '../config/prisma';

// ─────────────────────────────────────────────────────────────
// GET ALL CATEGORIES WITH SUBCATEGORIES (Admin)
// GET /api/admin/categories
// ─────────────────────────────────────────────────────────────
export const getAdminCategories = async (req: Request, res: Response) => {
  try {
    if (req.user?.role !== 'ADMIN') {
      return res.status(403).json({ success: false, message: 'Forbidden' });
    }
    const categories = await prisma.category.findMany({
      include: {
        subCategories: { orderBy: { name: 'asc' } },
        _count: { select: { projects: true, subCategories: true } },
      },
      orderBy: { name: 'asc' },
    });
    return res.status(200).json({ success: true, categories });
  } catch (error: any) {
    console.error('Admin Get Categories Error:', error);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
};

// ─────────────────────────────────────────────────────────────
// CREATE CATEGORY
// POST /api/admin/categories
// ─────────────────────────────────────────────────────────────
export const createCategory = async (req: Request, res: Response) => {
  try {
    if (req.user?.role !== 'ADMIN') {
      return res.status(403).json({ success: false, message: 'Forbidden' });
    }
    const { name, slug, icon, subCategoryName, subCategorySlug } = req.body;
    if (!name || !slug) {
      return res.status(400).json({ success: false, message: 'Category Name and slug are required' });
    }
    if (!subCategoryName || !subCategorySlug) {
      return res.status(400).json({ success: false, message: 'At least one sub-category is required' });
    }

    const category = await prisma.category.create({
      data: { 
        name: name.trim(), 
        slug: slug.trim().toLowerCase(), 
        icon,
        subCategories: {
          create: {
            name: subCategoryName.trim(),
            slug: subCategorySlug.trim().toLowerCase()
          }
        }
      },
      include: { subCategories: true, _count: { select: { projects: true, subCategories: true } } },
    });
    return res.status(201).json({ success: true, category });
  } catch (error: any) {
    if (error.code === 'P2002') {
      return res.status(409).json({ success: false, message: 'Category name or slug already exists' });
    }
    console.error('Admin Create Category Error:', error);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
};

// ─────────────────────────────────────────────────────────────
// UPDATE CATEGORY
// PATCH /api/admin/categories/:id
// ─────────────────────────────────────────────────────────────
export const updateCategory = async (req: Request, res: Response) => {
  try {
    if (req.user?.role !== 'ADMIN') {
      return res.status(403).json({ success: false, message: 'Forbidden' });
    }
    const { id } = req.params;
    const { name, slug, icon } = req.body;
    const category = await prisma.category.update({
      where: { id },
      data: {
        ...(name && { name: name.trim() }),
        ...(slug && { slug: slug.trim().toLowerCase() }),
        ...(icon !== undefined && { icon }),
      },
      include: { subCategories: true, _count: { select: { projects: true, subCategories: true } } },
    });
    return res.status(200).json({ success: true, category });
  } catch (error: any) {
    if (error.code === 'P2002') {
      return res.status(409).json({ success: false, message: 'Category name or slug already exists' });
    }
    console.error('Admin Update Category Error:', error);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
};

// ─────────────────────────────────────────────────────────────
// DELETE CATEGORY
// DELETE /api/admin/categories/:id
// ─────────────────────────────────────────────────────────────
export const deleteCategory = async (req: Request, res: Response) => {
  try {
    if (req.user?.role !== 'ADMIN') {
      return res.status(403).json({ success: false, message: 'Forbidden' });
    }
    const { id } = req.params;
    await prisma.category.delete({ where: { id } });
    return res.status(200).json({ success: true, message: 'Category deleted' });
  } catch (error: any) {
    console.error('Admin Delete Category Error:', error);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
};

// ─────────────────────────────────────────────────────────────
// CREATE SUBCATEGORY
// POST /api/admin/categories/:categoryId/subcategories
// ─────────────────────────────────────────────────────────────
export const createSubCategory = async (req: Request, res: Response) => {
  try {
    if (req.user?.role !== 'ADMIN') {
      return res.status(403).json({ success: false, message: 'Forbidden' });
    }
    const { categoryId } = req.params;
    const { name, slug } = req.body;
    if (!name || !slug) {
      return res.status(400).json({ success: false, message: 'Name and slug are required' });
    }
    const subCategory = await prisma.subCategory.create({
      data: {
        name: name.trim(),
        slug: slug.trim().toLowerCase(),
        categoryId,
      },
    });
    return res.status(201).json({ success: true, subCategory });
  } catch (error: any) {
    if (error.code === 'P2002') {
      return res.status(409).json({ success: false, message: 'Subcategory slug already exists in this category' });
    }
    console.error('Admin Create SubCategory Error:', error);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
};

// ─────────────────────────────────────────────────────────────
// UPDATE SUBCATEGORY
// PATCH /api/admin/categories/subcategories/:id
// ─────────────────────────────────────────────────────────────
export const updateSubCategory = async (req: Request, res: Response) => {
  try {
    if (req.user?.role !== 'ADMIN') {
      return res.status(403).json({ success: false, message: 'Forbidden' });
    }
    const { id } = req.params;
    const { name, slug } = req.body;
    const subCategory = await prisma.subCategory.update({
      where: { id },
      data: {
        ...(name && { name: name.trim() }),
        ...(slug && { slug: slug.trim().toLowerCase() }),
      },
    });
    return res.status(200).json({ success: true, subCategory });
  } catch (error: any) {
    console.error('Admin Update SubCategory Error:', error);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
};

// ─────────────────────────────────────────────────────────────
// DELETE SUBCATEGORY
// DELETE /api/admin/categories/subcategories/:id
// ─────────────────────────────────────────────────────────────
export const deleteSubCategory = async (req: Request, res: Response) => {
  try {
    if (req.user?.role !== 'ADMIN') {
      return res.status(403).json({ success: false, message: 'Forbidden' });
    }
    const { id } = req.params;
    await prisma.subCategory.delete({ where: { id } });
    return res.status(200).json({ success: true, message: 'Subcategory deleted' });
  } catch (error: any) {
    console.error('Admin Delete SubCategory Error:', error);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
};
