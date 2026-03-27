import { Request, Response } from "express";
import { prisma } from "../config/prisma";

export const getMyProfile = async (req: Request, res: Response) => {
  try {
    const userId = req.user?.userId;
    if (!userId) {
      return res.status(401).json({ success: false, message: "Unauthorized" });
    }

    const clientProfile = await prisma.clientProfile.findUnique({
      where: { userId },
      location: true,
      region: true,
      timezone: true,
      hiringPreference: true,
      budgetRange: true,
      preferredExpLevel: true,
      commMethod: true,
      availability: true,
      language: true,
      locationPref: true,
      hiringMethod: true,
      user: {
        select: {
          name: true,
          email: true,
          isEmailVerified: true,
          isPaymentVerified: true,
          isIdVerified: true,
          profileImage: true,
          phoneNumber: true,
          googleId: true,
        },
      },
    });

    if (!clientProfile) {
      return res
        .status(404)
        .json({ success: false, message: "Client profile not found" });
    }

    // Calculate metrics for profile display
    const clientId = clientProfile.id;
    const [totalProjects, hiredProjectsCount, totalSpentRes] =
      await Promise.all([
        prisma.project.count({ where: { clientProfileId: clientId } }),
        prisma.project.count({
          where: { clientProfileId: clientId, contract: { isNot: null } },
        }),
        prisma.payment.aggregate({
          where: {
            contract: { project: { clientProfileId: clientId } },
            status: "RELEASED",
          },
          _sum: { amount: true },
        }),
      ]);

    const totalSpent = totalSpentRes._sum.amount || 0;
    const hireRate =
      totalProjects > 0
        ? Math.round((hiredProjectsCount / totalProjects) * 100)
        : 0;

    return res.status(200).json({
      success: true,
      profile: {
        ...clientProfile,
        metrics: {
          totalProjects,
          hireRate,
          totalSpent,
        },
      },
    });
  } catch (error) {
    console.error("Error fetching client profile:", error);
    return res
      .status(500)
      .json({ success: false, message: "Internal server error" });
  }
};

export const updateMyProfile = async (req: Request, res: Response) => {
  try {
    const userId = req.user?.userId;
    if (!userId) {
      return res.status(401).json({ success: false, message: "Unauthorized" });
    }

    const {
      fullName,
      company,
      companyType,
      industry,
      bio,
      website,
      location,
      timezone,
      hiringPreference,
      budgetRange,
      preferredExpLevel,
      commMethod,
      availability,
      region,
      phoneNumber,
      profileImage, // Optional: update the user's profile image
    } = req.body;

    const updatedProfile = await prisma.clientProfile.update({
      where: { userId },
      data: {
        fullName,
        company,
        companyType,
        industry,
        bio,
        website,
        location,
        timezone,
        hiringPreference,
        budgetRange,
        preferredExpLevel,
        commMethod,
        availability,
        region,
        language,
        locationPref,
        hiringMethod,
      },
      include: {
        user: {
          select: {
            email: true,
            isEmailVerified: true,
            isPaymentVerified: true,
            isIdVerified: true,
            profileImage: true,
            phoneNumber: true,
          },
        },
      },
    });

    if (profileImage !== undefined || phoneNumber !== undefined) {
      await prisma.user.update({
        where: { id: userId },
        data: {
          ...(profileImage !== undefined && { profileImage }),
          ...(phoneNumber !== undefined && { phoneNumber }),
        },
      });
      // Update the response with the new data
      if (profileImage !== undefined)
        updatedProfile.user.profileImage = profileImage;
      if (phoneNumber !== undefined)
        updatedProfile.user.phoneNumber = phoneNumber;
    }

    return res.status(200).json({
      success: true,
      message: "Profile updated successfully",
      data: updatedProfile,
    });
  } catch (error) {
    console.error("Error updating client profile:", error);
    return res
      .status(500)
      .json({ success: false, message: "Internal server error" });
  }
};
