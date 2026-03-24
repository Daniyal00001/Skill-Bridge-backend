import { Request, Response } from 'express';
import { prisma } from '../config/prisma';

// ─────────────────────────────────────────────────────────────
// GET ALL SKILLS (Admin, filter by status)
// GET /api/admin/skills?status=PENDING
// ─────────────────────────────────────────────────────────────
export const getAdminSkills = async (req: Request, res: Response) => {
  try {
    const { status } = req.query;
    
    // Only allow Admins to access this.
    // Assuming req.user exists and has a role. If not, protect this via middleware.
    if (req.user?.role !== 'ADMIN') {
       return res.status(403).json({ success: false, message: "Forbidden: Admins only" });
    }

    const whereClause: any = {};
    if (status) {
      whereClause.status = status;
    }

    const skills = await prisma.skill.findMany({
      where: whereClause,
      orderBy: { createdAt: 'desc' }
    });

    return res.status(200).json({ success: true, skills });
  } catch (error: any) {
    console.error("Admin Get Skills Error:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
};

// ─────────────────────────────────────────────────────────────
// UPDATE SKILL STATUS
// PATCH /api/admin/skills/:id/status
// ─────────────────────────────────────────────────────────────
export const updateSkillStatus = async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    if (req.user?.role !== 'ADMIN') {
      return res.status(403).json({ success: false, message: "Forbidden: Admins only" });
    }

    if (!['APPROVED', 'REJECTED', 'PENDING'].includes(status)) {
      return res.status(400).json({ success: false, message: "Invalid status value" });
    }

    const skill = await prisma.skill.update({
      where: { id },
      data: { status }
    });

    return res.status(200).json({ success: true, message: `Skill ${status.toLowerCase()} successfully`, skill });
  } catch (error: any) {
    console.error("Admin Update Skill Error:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
};
