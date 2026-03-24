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

    if (status === 'REJECTED') {
      const skillToDelete = await prisma.skill.findUnique({ where: { id } });
      if (!skillToDelete) {
        return res.status(404).json({ success: false, message: "Skill not found" });
      }

      const skill = await prisma.$transaction(async (tx) => {
        // Create in RejectedSkill
        await tx.rejectedSkill.upsert({
          where: { name: skillToDelete.name },
          update: {},
          create: { name: skillToDelete.name }
        });

        // Explicitly delete from join tables (MongoDB workaround for Cascade)
        // Use the ID from the record we just found to ensure consistency
        const fsDeleted = await tx.freelancerSkill.deleteMany({ where: { skillId: skillToDelete.id } });
        const psDeleted = await tx.projectSkill.deleteMany({ where: { skillId: skillToDelete.id } });

        console.log(`[Rejection] Deleted ${fsDeleted.count} freelancer skills and ${psDeleted.count} project skills for ${skillToDelete.name}`);

        // Delete from Skill
        return await tx.skill.delete({ where: { id: skillToDelete.id } });
      });

      return res.status(200).json({ success: true, message: `Skill rejected and moved to blocked list`, skill });
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
