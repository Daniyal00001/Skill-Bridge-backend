import { Request } from "express";
import { prisma } from "../config/prisma";
import { Role } from "@prisma/client";

/**
 * Logs a login event and updates the lastLoginAt field on the corresponding profile.
 * Supports CLIENT, FREELANCER, and ADMIN roles.
 */
export async function trackLogin(userId: string, role: Role, req: Request) {
  try {
    const ipAddress = (req.ip || req.socket.remoteAddress || "unknown").toString();
    const userAgent = req.headers["user-agent"] || "unknown";

    console.log(`[LoginTracker] Attempting to track login for ${userId} (${role})`);

    // 1. Create Login Log entry
    const log = await prisma.loginLog.create({
      data: {
        userId,
        role: role.toUpperCase() as Role,
        ipAddress,
        userAgent,
      },
    });
    console.log(`[LoginTracker] Created log entry: ${log.id}`);

    // 2. Update lastLoginAt on the specific profile
    const now = new Date();
    const roleUpper = role.toUpperCase();

    if (roleUpper === "CLIENT") {
      await prisma.clientProfile.update({
        where: { userId },
        data: { lastLoginAt: now },
      });
    } else if (roleUpper === "FREELANCER") {
      await prisma.freelancerProfile.update({
        where: { userId },
        data: { lastLoginAt: now },
      });
    } else if (roleUpper === "ADMIN") {
      await prisma.adminProfile.update({
        where: { userId },
        data: { lastLoginAt: now },
      });
    }

    // Also update lastActiveAt on the User model
    await prisma.user.update({
      where: { id: userId },
      data: { lastActiveAt: now },
    });

    console.log(`[LoginTracker] Successfully updated profile for ${userId}`);
  } catch (error) {
    console.error("[LoginTracker] ERROR:", error);
  }
}
